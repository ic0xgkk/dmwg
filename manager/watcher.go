package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	apipb "github.com/osrg/gobgp/v3/api"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Ensure that there are no peers added to bgp before watching.
func (m *Manager) watchWireGuardPeers() error {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-m.closeCh
		cancel()
	}()

	err := m.bgpServer.WatchEvent(ctx, &apipb.WatchEventRequest{
		Peer: &apipb.WatchEventRequest_Peer{},
		Table: &apipb.WatchEventRequest_Table{
			Filters: []*apipb.WatchEventRequest_Table_Filter{
				// Only subscribe to changes in the best routes of the RIB (Routing Information Base).
				// Other changes should not be subscribed to, as this would generate many redundant events, which would be complex to handle.
				//
				// The `Init` setting means a full synchronization will occur initially. If the RIB is empty at the start, an empty `TableEvent` will be received.
				{
					Type: apipb.WatchEventRequest_Table_Filter_BEST,
					Init: true,
				},
			},
		},
	}, m.handleWireGuardPeerEvents)
	if err != nil {
		return fmt.Errorf("watch wireguard peers: %w", err)
	}

	return nil
}

func (m *Manager) handleWireGuardPeerEvents(resp *apipb.WatchEventResponse) {
	m.wait.Add(1)
	defer m.wait.Done()

	if glog.V(5) {
		glog.V(5).Infof("handle wireguard peer events: %s", spew.Sdump(resp))
	}

	e, ok := resp.Event.(*apipb.WatchEventResponse_Table)
	if !ok {
		glog.V(5).Infof("handle wireguard peer event dropped by not table event")
		return
	}

	for _, p := range e.Table.Paths {
		if p.Family.Afi != apipb.Family_AFI_IP ||
			p.Family.Safi != apipb.Family_SAFI_UNICAST {

			glog.V(3).Infof("handle wireguard peer event dropped by family not IPv4 Unicast")
			continue
		}

		if p.IsNexthopInvalid {
			glog.V(5).Infof("handle wireguard peer event dropped by invalid nexthop")
			continue
		}

		has, err := hasCommunities([]uint32{_bgpCommunity_WireGuardPeer}, p.Pattrs)
		if err != nil {
			glog.Errorf("check has wireguard peer community: %v", err)
			continue
		}
		if !has {
			glog.V(5).Infof("handle wireguard peer event dropped by no wireguard peer community")
			continue
		}

		err = m.handleWireGuardPeerEventPath(p)
		if err != nil {
			glog.Errorf("handle wireguard peer event path: %v", err)
		}
	}
}

func (m *Manager) handleWireGuardPeerEventPath(p *apipb.Path) error {
	if glog.V(5) {
		glog.V(5).Infof("handle wireguard peer event path: %s", spew.Sdump(p))
	}

	ipPrefix := new(apipb.IPAddressPrefix)
	err := p.Nlri.UnmarshalTo(ipPrefix)
	if err != nil {
		return fmt.Errorf("unmarshal nlri: %w", err)
	}
	if ipPrefix.PrefixLen != 32 {
		return fmt.Errorf("invalid wireguard peer prefix length: %d", ipPrefix.PrefixLen)
	}

	// Ignore the path if the prefix is the local address.
	ipPrefixAddr, err := netip.ParseAddr(ipPrefix.Prefix)
	if err != nil {
		return fmt.Errorf("parse nlri address: %w", err)
	}
	if ipPrefixAddr.Compare(m.getLocalAddress()) == 0 {
		glog.V(5).Infof("handle wireguard peer event path dropped by local address")
		return nil
	}

	nexthopAddress, err := getNexthop(p.Pattrs)
	if err != nil {
		return fmt.Errorf("get nexthop address: %w", err)
	}

	var wireGuardPeerAttr *apipb.WireGuardPeerAttribute
	for _, attr := range p.Pattrs {
		if attr.MessageIs(&apipb.WireGuardPeerAttribute{}) {
			a := &apipb.WireGuardPeerAttribute{}
			err = attr.UnmarshalTo(a)
			if err != nil {
				return fmt.Errorf("unmarshal wireguard peer attribute: %w", err)
			}

			wireGuardPeerAttr = a
		}
	}
	if wireGuardPeerAttr == nil {
		return fmt.Errorf("missing wireguard peer attribute")
	}

	b, err := base64.StdEncoding.DecodeString(wireGuardPeerAttr.PublicKey)
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	if len(b) != 32 {
		return fmt.Errorf("invalid public key: %s", wireGuardPeerAttr.PublicKey)
	}
	publicKey, err := wgtypes.NewKey(b)
	if err != nil {
		return fmt.Errorf("new key: %w", err)
	}

	if p.IsWithdraw {
		err = m.wgClient.ConfigureDevice(m.getInterfaceName(), wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: publicKey,
					Remove:    true,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("configure device to withdraw peer: %w", err)
		}

		err = m.bgpServer.DeletePeer(context.Background(), &apipb.DeletePeerRequest{
			Address: ipPrefixAddr.String(),
		})
		if err != nil {
			return fmt.Errorf("delete peer: %w", err)
		}

	} else {
		a := ipPrefixAddr.As4()
		err = m.wgClient.ConfigureDevice(m.getInterfaceName(), wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: publicKey,
					Endpoint: &net.UDPAddr{
						IP:   net.IP(nexthopAddress.AsSlice()),
						Port: int(wireGuardPeerAttr.EndpointPort),
					},
					AllowedIPs: []net.IPNet{
						{
							IP:   net.IP(a[:]),
							Mask: net.CIDRMask(32, 32),
						},
					},
				},
			},
		})
		if err != nil {
			return fmt.Errorf("configure device to add peer: %w", err)
		}

		err = m.bgpServer.AddPeer(context.Background(), &apipb.AddPeerRequest{
			Peer: &apipb.Peer{
				AfiSafis: []*apipb.AfiSafi{
					{
						Config: &apipb.AfiSafiConfig{
							Enabled: true,
							Family:  &apipb.Family{Afi: apipb.Family_AFI_IP, Safi: apipb.Family_SAFI_UNICAST},
						},
					},
				},
				Conf: &apipb.PeerConf{
					NeighborAddress: ipPrefixAddr.String(),
					PeerAsn:         _asn,
					Type:            apipb.PeerType_INTERNAL,
				},
				Timers: &apipb.Timers{
					Config: m.getBgpTimersConfig(),
				},
				Transport: &apipb.Transport{
					RemotePort:   179,
					LocalAddress: m.getLocalAddress().String(),
					MtuDiscovery: true,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("add wireguard peer: %w", err)
		}
	}

	return nil
}

func (m *Manager) watchGenericPeers() error {
	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		<-m.closeCh
		cancel()
	}()

	err := m.bgpServer.WatchEvent(ctx, &apipb.WatchEventRequest{
		Peer: &apipb.WatchEventRequest_Peer{},
		Table: &apipb.WatchEventRequest_Table{
			Filters: []*apipb.WatchEventRequest_Table_Filter{
				{
					Type: apipb.WatchEventRequest_Table_Filter_BEST,
					Init: true,
				},
			},
		},
	}, m.handleGenericPeerEvents)
	if err != nil {
		return fmt.Errorf("watch generic peers: %w", err)
	}

	return nil
}

func (m *Manager) handleGenericPeerEvents(resp *apipb.WatchEventResponse) {
	m.wait.Add(1)
	defer m.wait.Done()

	e, ok := resp.Event.(*apipb.WatchEventResponse_Table)
	if !ok {
		return
	}

	for _, p := range e.Table.Paths {
		if p.Family.Afi != apipb.Family_AFI_IP ||
			p.Family.Safi != apipb.Family_SAFI_UNICAST {
			continue
		}

		if p.IsNexthopInvalid {
			glog.V(5).Infof("handle wireguard peer event dropped by invalid nexthop")
			continue
		}

		err := m.handleGenericPeerEventPath(p)
		if err != nil {
			glog.Errorf("handle generic peer event path: %v", err)
		}
	}
}

func (m *Manager) handleGenericPeerEventPath(p *apipb.Path) error {
	ipPrefix := new(apipb.IPAddressPrefix)
	err := p.Nlri.UnmarshalTo(ipPrefix)
	if err != nil {
		return fmt.Errorf("unmarshal nlri: %w", err)
	}

	var nexthopAttr *apipb.NextHopAttribute
	for _, attr := range p.Pattrs {
		if attr.MessageIs(&apipb.NextHopAttribute{}) {
			a := &apipb.NextHopAttribute{}
			err = attr.UnmarshalTo(a)
			if err != nil {
				return fmt.Errorf("unmarshal nexthop attribute: %w", err)
			}

			nexthopAttr = a
		}
	}
	if nexthopAttr == nil {
		return fmt.Errorf("missing nexthop attribute")
	}

	tunnelNexthopAddress, err := netip.ParseAddr(nexthopAttr.NextHop)
	if err != nil {
		return fmt.Errorf("parse nexthop address: %s", nexthopAttr.NextHop)
	}
	if !tunnelNexthopAddress.Is4() {
		return fmt.Errorf("invalid nexthop address: not ipv4: %s", nexthopAttr.NextHop)
	}
	if tunnelNexthopAddress.Compare(m.getLocalAddress()) == 0 {
		return nil
	}

	if p.IsWithdraw {
		runtime.KeepAlive(tunnelNexthopAddress)
	} else {
		// netlink.RouteAdd(&netlink.Route{})
	}

	return nil
}
