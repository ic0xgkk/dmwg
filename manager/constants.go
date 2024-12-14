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

	// Some province ISPs in China have a 1432 MTU, so we use 1400 to avoid fragmentation.
	_underlayMtu = 1400
	// 40 bytes for IPv6 header, and 40 bytes for WireGuard header.
	// Refer: https://lists.zx2c4.com/pipermail/wireguard/2017-December/002201.html
	_wgMtu = _underlayMtu - 40 - 40
	// 20 bytes for inner IPIP(v4) header.
	_ipipMtu = _wgMtu - 20

	// 1220 bytes is default MSS for IPv6.
	// It will work well for most cases.
	_tcpMss = 1220

	_bgpCommunity_WireGuardPeer = uint32(_asn)<<16 | 0x0001
	_bgpCommunity_GenericPrefix = uint32(_asn)<<16 | 0x0002
)
