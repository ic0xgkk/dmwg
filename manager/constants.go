package manager

import "net/netip"

var (
	_reservedPrefix = netip.PrefixFrom(
		netip.AddrFrom4([4]byte{198, 19, 0, 0}),
		16, // The mask must be 16.
	)
)

const (
	_asn      = 0xffe0
	_grpcPort = 20151

	_wgMtu = 1380

	_bgpCommunity_WireGuardPeer = uint32(_asn)<<16 | 0x0001
	_bgpCommunity_GenericPeer   = uint32(_asn)<<16 | 0x0002
)
