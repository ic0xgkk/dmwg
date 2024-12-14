package manager

import (
	"context"
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

	e, ok := resp.Event.(*apipb.WatchEventResponse_Table)
	if !ok {
		if glog.V(5) {
			glog.V(5).Infof("dropped wireguard peer event: not table event /// %s", spew.Sdump(resp))
		}

		return
	}

	for _, p := range e.Table.Paths {
		m.handleWireGuardPeerPath(p)
	}
}

func (m *Manager) handleWireGuardPeerPath(p *apipb.Path) {
	if glog.V(6) {
		glog.V(6).Infof("handle wireguard peer path: %s", spew.Sdump(p))
	}

	if p.Family.Afi != apipb.Family_AFI_IP ||
		p.Family.Safi != apipb.Family_SAFI_UNICAST {

		if glog.V(5) {
			glog.V(5).Infof("dropped wireguard peer path: not IPv4 Unicast /// %s", spew.Sdump(p))
		}

		return
	}

	has, err := hasCommunities([]uint32{_bgpCommunity_WireGuardPeer}, p.Pattrs)
	if err != nil {
		glog.Errorf("failed to check if path has wireguard peer community: %v /// %s", err, spew.Sdump(p))
		return
	}
	if !has {
		if glog.V(5) {
			glog.V(5).Infof("dropped wireguard peer path: no wireguard peer community /// %s", spew.Sdump(p))
		}

		return
	}

	nlPfx := new(apipb.IPAddressPrefix)
	err = p.Nlri.UnmarshalTo(nlPfx)
	if err != nil {
		glog.Errorf("failed to unmarshal wireguard peer path nlri: %v /// %s", err, spew.Sdump(p))
		return
	}
	addr, err := netip.ParseAddr(nlPfx.Prefix)
	if err != nil {
		glog.Errorf("failed to parse wireguard peer path nlri address: %v /// %s", err, spew.Sdump(p))
		return
	}
	if nlPfx.PrefixLen != 32 || !addr.Is4() {
		glog.Errorf("invalid wireguard peer path prefix: not ipv4 host route /// %s", spew.Sdump(p))
		return
	}

	// Ignore the path if the prefix is the local address.
	if addr.Compare(m.getLocalAddress()) == 0 {
		if glog.V(5) {
			glog.V(5).Infof("dropped wireguard peer path: local address /// %s", spew.Sdump(p))
		}

		return
	}

	nexthop, err := getNexthop(p.Pattrs)
	if err != nil {
		glog.Errorf("failed to get wireguard peer path nexthop: %v /// %s", err, spew.Sdump(p))
		return
	}
	// WireGuard Peer endpoint is nexthop, only IPv6 is supported.
	if !nexthop.Is6() {
		glog.Errorf("invalid wireguard peer path nexthop: not ipv6 /// %s", spew.Sdump(p))
		return
	}

	endpointPort, publicKey, err := getWireGuardProperties(p.Pattrs)
	if err != nil {
		glog.Errorf("failed to get wireguard peer path properties: %v /// %s", err, spew.Sdump(p))
		return
	}

	if p.IsWithdraw {
		err = m.bgpServer.DeletePeer(context.Background(), &apipb.DeletePeerRequest{
			Address: addr.String(),
		})
		if err != nil {
			glog.Errorf("failed to delete bgp mesh peer: %v /// %s", err, spew.Sdump(p))
		}

		err = m.wgClient.ConfigureDevice(m.getWireGuardInterfaceName(), wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: publicKey,
					Remove:    true,
				},
			},
		})
		if err != nil {
			glog.Errorf("failed to delete wireguard peer: %v /// %s", err, spew.Sdump(p))
		}

	} else {
		if p.IsNexthopInvalid {
			if glog.V(5) {
				glog.V(5).Infof("dropped wireguard peer path: invalid nexthop /// %s", spew.Sdump(p))
			}

			return
		}

		err = m.wgClient.ConfigureDevice(m.getWireGuardInterfaceName(), wgtypes.Config{
			Peers: []wgtypes.PeerConfig{
				{
					PublicKey: publicKey,
					Endpoint: &net.UDPAddr{
						IP:   net.IP(nexthop.AsSlice()),
						Port: int(endpointPort),
					},
					AllowedIPs: []net.IPNet{
						{
							IP:   net.IP(addr.AsSlice()),
							Mask: net.CIDRMask(32, 32),
						},
					},
				},
			},
		})
		if err != nil {
			glog.Errorf("failed to add wireguard peer: %v /// %s", err, spew.Sdump(p))
			return
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
					NeighborAddress: addr.String(),
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
			glog.Errorf("failed to add bgp mesh peer: %v /// %s", err, spew.Sdump(p))
			return
		}
	}
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
		m.handleGenericPrefixPath(p)
	}
}

func (m *Manager) handleGenericPrefixPath(p *apipb.Path) {
	if p.Family.Afi != apipb.Family_AFI_IP ||
		p.Family.Safi != apipb.Family_SAFI_UNICAST {

		if glog.V(5) {
			glog.V(5).Infof("dropped generic prefix path: not IPv4 Unicast /// %s", spew.Sdump(p))
		}

		return
	}

	has, err := hasCommunities([]uint32{_bgpCommunity_GenericPrefix}, p.Pattrs)
	if err != nil {
		glog.Errorf("failed to check if path has generic prefix community: %v", err)
		return
	}
	if !has {
		if glog.V(5) {
			glog.V(5).Infof("dropped generic prefix path: no generic prefix community /// %s", spew.Sdump(p))
		}

		return
	}

	nlPfx := new(apipb.IPAddressPrefix)
	err = p.Nlri.UnmarshalTo(nlPfx)
	if err != nil {
		glog.Errorf("failed to unmarshal generic prefix nlri: %v /// %s", err, spew.Sdump(p))
		return
	}
	addr, err := netip.ParseAddr(nlPfx.Prefix)
	if err != nil {
		glog.Errorf("failed to parse generic prefix nlri address: %v /// %s", err, spew.Sdump(p))
		return
	}
	if nlPfx.PrefixLen > 32 || !addr.Is4() {
		glog.Errorf("invalid generic prefix: not ipv4 /// %s", spew.Sdump(p))
		return
	}
	prefix := netip.PrefixFrom(addr, int(nlPfx.PrefixLen))

	nexthop, err := getNexthop(p.Pattrs)
	if err != nil {
		glog.Errorf("failed to get generic prefix nexthop: %v /// %s", err, spew.Sdump(p))
		return
	}
	// Generic Prefix nexthop is IPIP destination, only IPv4 is supported.
	if !nexthop.Is4() {
		glog.Errorf("invalid generic prefix nexthop: not ipv4 /// %s", spew.Sdump(p))
		return
	}

	link, err := netlink.LinkByName(m.getIpipInterfaceName())
	if err != nil {
		glog.Errorf("failed to get ipip link: %v", err)
		return
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Flags:     int(netlink.FLAG_ONLINK),
		Dst: &net.IPNet{
			IP:   net.IP(prefix.Addr().AsSlice()),
			Mask: net.CIDRMask(int(prefix.Bits()), prefix.Addr().BitLen()),
		},
		Gw: nexthop.AsSlice(),
	}

	if p.IsWithdraw {
		err = netlink.RouteDel(route)
		if err != nil {
			glog.Errorf("failed to delete route: %v /// %s", err, spew.Sdump(route))
		}

	} else {
		if p.IsNexthopInvalid {
			if glog.V(5) {
				glog.V(5).Infof("dropped generic prefix path: invalid nexthop /// %s", spew.Sdump(p))
			}

			return
		}

		err = netlink.RouteAdd(route)
		if err != nil {
			glog.Errorf("failed to add route: %v /// %s", err, spew.Sdump(route))
			return
		}

	}
}
