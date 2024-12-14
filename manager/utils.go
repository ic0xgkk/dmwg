package manager

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"

	apipb "github.com/osrg/gobgp/v3/api"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/types/known/anypb"
)

// The local address is an IPv4 address, which is the address of the WireGuard interface, not the endpoint address.
// The BGP router ID will also use this address.
func (m *Manager) getLocalAddress() netip.Addr {
	a := _reservedPrefix.Addr().As4()
	copy(a[2:4], m.nodeId[:])

	return netip.AddrFrom4(a)
}

func (m *Manager) getWireGuardInterfaceName() string {
	return "wg-" + hex.EncodeToString(m.networkId[:])
}

func (m *Manager) getIpipInterfaceName() string {
	return "tl-" + hex.EncodeToString(m.networkId[:])
}

// All the BGP peer will use the same TimersConfig.
func (m *Manager) getBgpTimersConfig() *apipb.TimersConfig {
	return &apipb.TimersConfig{
		ConnectRetry:      5,
		HoldTime:          15,
		KeepaliveInterval: 3,
	}
}

func hasCommunities(comms []uint32, attrs []*anypb.Any) (bool, error) {
	m := make(map[uint32]struct{})
	for _, c := range comms {
		m[c] = struct{}{}
	}

	var communitiesAttr *apipb.CommunitiesAttribute
	for _, attr := range attrs {
		if attr.MessageIs(&apipb.CommunitiesAttribute{}) {
			a := &apipb.CommunitiesAttribute{}
			err := attr.UnmarshalTo(a)
			if err != nil {
				return false, fmt.Errorf("unmarshal communities attribute: %v", err)
			}

			communitiesAttr = a
		}
	}
	if communitiesAttr == nil {
		return false, nil
	}

	for _, c := range communitiesAttr.Communities {
		if _, ok := m[c]; ok {
			return true, nil
		}
	}

	return false, nil
}

func getNexthop(attrs []*anypb.Any) (netip.Addr, error) {
	// If the address family isn't IPv4 unicast, then the `MpReachNLRIAttribute` must be used.
	// Referring: gobgp/pkg/server/grpc_server.go:392
	var nexthopAttr *apipb.NextHopAttribute
	for _, apb := range attrs {
		if apb.MessageIs(&apipb.NextHopAttribute{}) {
			a := &apipb.NextHopAttribute{}
			err := apb.UnmarshalTo(a)
			if err != nil {
				return netip.Addr{}, fmt.Errorf("unmarshal nexthop attribute: %w", err)
			}

			nexthopAttr = a
		}
	}
	if nexthopAttr != nil {
		ret, err := netip.ParseAddr(nexthopAttr.NextHop)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("parse nexthop address: %s", nexthopAttr.NextHop)
		}

		return ret, nil
	}

	// Nexthops will have at most two addresses, one reachable public address and one link-local address.
	// Therefore, we need to check for and exclude the link-local address.
	var mpReachNLRIAttribute *apipb.MpReachNLRIAttribute
	for _, apb := range attrs {
		if apb.MessageIs(&apipb.MpReachNLRIAttribute{}) {
			a := &apipb.MpReachNLRIAttribute{}
			err := apb.UnmarshalTo(a)
			if err != nil {
				return netip.Addr{}, fmt.Errorf("unmarshal mp_reach_nlri attribute: %w", err)
			}

			mpReachNLRIAttribute = a
		}
	}
	if mpReachNLRIAttribute != nil {
		for _, nh := range mpReachNLRIAttribute.NextHops {
			ret, err := netip.ParseAddr(nh)
			if err != nil {
				return netip.Addr{}, fmt.Errorf("parse mpreach nexthop address: %s", nh)
			}

			if ret.IsLinkLocalUnicast() || ret.IsLinkLocalMulticast() {
				continue
			}

			return ret, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("missing nexthop attribute")
}

func getWireGuardProperties(attrs []*anypb.Any) (endpointPort uint16, publicKey wgtypes.Key, err error) {
	var wireGuardPeerAttr *apipb.WireGuardPeerAttribute
	for _, attr := range attrs {
		if attr.MessageIs(&apipb.WireGuardPeerAttribute{}) {
			a := &apipb.WireGuardPeerAttribute{}
			err = attr.UnmarshalTo(a)
			if err != nil {
				err = fmt.Errorf("unmarshal wireguard peer attribute: %w", err)
				return
			}

			wireGuardPeerAttr = a
		}
	}
	if wireGuardPeerAttr == nil {
		err = fmt.Errorf("missing wireguard peer attribute")
		return
	}

	b, err := base64.StdEncoding.DecodeString(wireGuardPeerAttr.PublicKey)
	if err != nil {
		err = fmt.Errorf("decode public key: %w", err)
		return
	}
	if len(b) != 32 {
		err = fmt.Errorf("invalid public key: %s", wireGuardPeerAttr.PublicKey)
		return
	}

	pk, err := wgtypes.NewKey(b)
	if err != nil {
		err = fmt.Errorf("new key: %w", err)
		return
	}

	if wireGuardPeerAttr.EndpointPort == 0 || wireGuardPeerAttr.EndpointPort > 0xffff {
		err = fmt.Errorf("missing port attribute")
		return
	}

	return uint16(wireGuardPeerAttr.EndpointPort), pk, nil
}
