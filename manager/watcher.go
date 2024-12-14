package manager

import (
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Ensure that there are no peers added to bgp before watching.
func (m *Manager) watchWireGuardPeer() error {
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
	}, m.handleWireGuardPeerEvent)
	if err != nil {
		return fmt.Errorf("watch wireguard peer: %w", err)
	}

	return nil
}

func (m *Manager) handleWireGuardPeerEvent(resp *apipb.WatchEventResponse) {
	m.wait.Add(1)
	defer m.wait.Done()

	if glog.V(5) {
		glog.V(5).Infof("handle wireguard peer event: %s", spew.Sdump(resp))
	}

	e, ok := resp.Event.(*apipb.WatchEventResponse_Table)
	if !ok {
		glog.V(5).Infof("dropped wireguard peer event: not table event")
		return
	}

	for _, p := range e.Table.Paths {
		if p.Family.Afi != apipb.Family_AFI_IP ||
			p.Family.Safi != apipb.Family_SAFI_UNICAST {

			glog.V(5).Infof("dropped wireguard peer event: not IPv4 Unicast")
			continue
		}

		if p.IsNexthopInvalid {
			glog.V(5).Infof("dropped wireguard peer event: invalid nexthop")
			continue
		}

		has, err := hasCommunities([]uint32{_bgpCommunity_WireGuardPeer}, p.Pattrs)
		if err != nil {
			glog.Errorf("failed to check if has wireguard peer community: %v", err)
			continue
		}
		if !has {
			glog.V(5).Infof("dropped wireguard peer event: no wireguard peer community")
			continue
		}

		err = m.handleWireGuardPeerEventPath(p)
		if err != nil {
			glog.Errorf("failed to handle wireguard peer event path: %v", err)
		}
	}
}

func (m *Manager) handleWireGuardPeerEventPath(p *apipb.Path) error {
	if glog.V(5) {
		glog.V(5).Infof("handle wireguard peer event path: %s", spew.Sdump(p))
	}

	var prefix netip.Prefix
	{
		pfx := new(apipb.IPAddressPrefix)
		err := p.Nlri.UnmarshalTo(pfx)
		if err != nil {
			return fmt.Errorf("unmarshal nlri: %w", err)
		}

		addr, err := netip.ParseAddr(pfx.Prefix)
		if err != nil {
			return fmt.Errorf("parse nlri address: %w", err)
		}
		if pfx.PrefixLen != 32 || !addr.Is4() {
			return fmt.Errorf("invalid wireguard peer prefix: not ipv4 host route: %s/%d", pfx.Prefix, pfx.PrefixLen)
		}

		prefix = netip.PrefixFrom(addr, int(pfx.PrefixLen))
	}
	// Ignore the path if the prefix is the local address.
	if prefix.Addr().Compare(m.getLocalAddress()) == 0 {
		glog.V(5).Infof("dropped wireguard peer event path: local address")
		return nil
	}

	nexthopAddress, err := getNexthop(p.Pattrs)
	if err != nil {
		return fmt.Errorf("get nexthop address: %w", err)
	}
	// WireGuard Peer endpoint is nexthop, only IPv6 is supported.
	if !nexthopAddress.Is6() {
		return fmt.Errorf("invalid nexthop address: not ipv6: %s", nexthopAddress)
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
		err = m.wgClient.ConfigureDevice(m.getWireGuardInterfaceName(), wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: publicKey,
					Remove:    true,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("withdraw wireguard peer: %w", err)
		}

		err = m.bgpServer.DeletePeer(context.Background(), &apipb.DeletePeerRequest{
			Address: prefix.Addr().String(),
		})
		if err != nil {
			return fmt.Errorf("delete bgp peer: %w", err)
		}

	} else {
		a := prefix.Addr().As4()
		err = m.wgClient.ConfigureDevice(m.getWireGuardInterfaceName(), wgtypes.Config{
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
			return fmt.Errorf("add wireguard peer: %w", err)
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
					NeighborAddress: prefix.Addr().String(),
					PeerAsn:         _asn,
					Type:            apipb.PeerType_INTERNAL,
				},
				Timers: &apipb.Timers{
					Config: m.getBgpTimersConfig(),
				},
				Transport: &apipb.Transport{
					RemotePort:   179,
					LocalAddress: m.getLocalAddress().String(),
					TcpMss:       1220,
				},
			},
		})
		if err != nil {
			return fmt.Errorf("add bgp peer: %w", err)
		}
	}

	return nil
}

// Ensure that there are no peers added to bgp before watching.
func (m *Manager) watchGenericPreifx() error {
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
	}, m.handleGenericPrefixEvent)
	if err != nil {
		return fmt.Errorf("watch generic prefix: %w", err)
	}

	return nil
}

func (m *Manager) handleGenericPrefixEvent(resp *apipb.WatchEventResponse) {
	m.wait.Add(1)
	defer m.wait.Done()

	if glog.V(5) {
		glog.V(5).Infof("handle generic prefix event: %s", spew.Sdump(resp))
	}

	e, ok := resp.Event.(*apipb.WatchEventResponse_Table)
	if !ok {
		glog.V(5).Infof("dropped generic prefix event: not table event")
		return
	}

	for _, p := range e.Table.Paths {
		if p.Family.Afi != apipb.Family_AFI_IP ||
			p.Family.Safi != apipb.Family_SAFI_UNICAST {

			glog.V(5).Infof("dropped generic prefix event: not IPv4 Unicast")
			continue
		}

		if p.IsNexthopInvalid {
			glog.V(5).Infof("dropped generic prefix event: invalid nexthop")
			continue
		}

		has, err := hasCommunities([]uint32{_bgpCommunity_GenericPrefix}, p.Pattrs)
		if err != nil {
			glog.Errorf("failed to check if has generic prefix community: %v", err)
			continue
		}
		if !has {
			glog.V(5).Infof("dropped generic prefix event: no generic prefix community")
			continue
		}

		err = m.handleGenericPrefixEventPath(p)
		if err != nil {
			glog.Errorf("failed to handle generic prefix event path: %v", err)
		}
	}
}

func (m *Manager) handleGenericPrefixEventPath(p *apipb.Path) error {
	var prefix netip.Prefix
	{
		pfx := new(apipb.IPAddressPrefix)
		err := p.Nlri.UnmarshalTo(pfx)
		if err != nil {
			return fmt.Errorf("unmarshal nlri: %w", err)
		}

		addr, err := netip.ParseAddr(pfx.Prefix)
		if err != nil {
			return fmt.Errorf("parse nlri address: %w", err)
		}
		if pfx.PrefixLen > 32 || !addr.Is4() {
			return fmt.Errorf("invalid generic prefix: not ipv4: %s/%d", pfx.Prefix, pfx.PrefixLen)
		}

		prefix = netip.PrefixFrom(addr, int(pfx.PrefixLen))
	}

	nexthopAddress, err := getNexthop(p.Pattrs)
	if err != nil {
		return fmt.Errorf("get nexthop address: %w", err)
	}
	// Generic Prefix nexthop is IPIP destination, only IPv4 is supported.
	if !nexthopAddress.Is4() {
		return fmt.Errorf("invalid nexthop address: not ipv4: %s", nexthopAddress)
	}

	link, err := netlink.LinkByName(m.getIpipInterfaceName())
	if err != nil {
		return fmt.Errorf("get ipip link: %w", err)
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Flags:     int(netlink.FLAG_ONLINK),
		Dst: &net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(int(prefix.Bits()), prefix.Addr().BitLen()),
		},
		Gw: nexthopAddress.AsSlice(),
	}

	if p.IsWithdraw {
		err = netlink.RouteDel(route)
		if err != nil {
			return fmt.Errorf("del route: %w", err)
		}

	} else {
		err = netlink.RouteAdd(route)
		if err != nil {
			return fmt.Errorf("add route: %w", err)
		}

	}

	return nil
}
