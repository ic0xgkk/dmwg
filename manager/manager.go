package manager

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"syscall"
	"unsafe"

	"github.com/ic0xgkk/dmwg/pkg/log"
	apipb "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"google.golang.org/protobuf/types/known/anypb"
)

type Manager struct {
	wgClient  *wgctrl.Client
	bgpServer *server.BgpServer

	networkId [4]byte
	nodeId    [2]byte

	wait      sync.WaitGroup
	closeOnce sync.Once
	closeCh   chan struct{}
}

type OptionInterface interface {
	optionInterface()
}

type WireGuardPortOption struct {
	port uint16
}

func NewWireGuardPortOption(port uint16) *WireGuardPortOption {
	return &WireGuardPortOption{port: port}
}

func (o *WireGuardPortOption) optionInterface() {}

type GrpcPortOption struct {
	port uint16
}

func NewGrpcPortOption(port uint16) *GrpcPortOption {
	return &GrpcPortOption{port: port}
}

func (o *GrpcPortOption) optionInterface() {}

// networkId is a 4-byte hexadecimal string, which is equivalent to 8 characters.
// nodeId is a 2-byte hexadecimal string, which is equivalent to 4 characters.
func New(networkId, nodeId string, controllerAddress netip.AddrPort, controllerPassword string, opts ...OptionInterface) (*Manager, error) {
	networkIdBytes, err := hex.DecodeString(networkId)
	if err != nil {
		return nil, fmt.Errorf("decode network id: %w", err)
	}
	if len(networkIdBytes) != 4 {
		return nil, fmt.Errorf("invalid network id: not 4 bytes")
	}
	defer runtime.KeepAlive(networkIdBytes)

	nodeIdBytes, err := hex.DecodeString(nodeId)
	if err != nil {
		return nil, fmt.Errorf("decode node id: %w", err)
	}
	if len(nodeIdBytes) != 2 {
		return nil, fmt.Errorf("invalid node id: not 2 bytes")
	}
	defer runtime.KeepAlive(nodeIdBytes)

	if !controllerAddress.Addr().Is6() {
		return nil, fmt.Errorf("invalid controller address: not ipv6: %s", controllerAddress.Addr())
	}

	if len(controllerPassword) > 32 || len(controllerPassword) == 0 {
		return nil, fmt.Errorf("invalid password: length not in [1, 32]")
	}

	wgPrivateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	wgPublicKey := wgPrivateKey.PublicKey()

	// WireGuard's default port selection is random from the range 30000-32767.
	var wgPort uint16
	// Check if the port is in use.
	for {
		wgPort = uint16(rand.Int31n(2767) + 30000)

		lis, err := net.ListenUDP("udp", &net.UDPAddr{
			IP:   net.IPv6zero,
			Port: int(wgPort),
		})
		if err != nil {
			if errors.Is(err, syscall.EADDRINUSE) {
				continue
			}

			return nil, fmt.Errorf("check udp port in used failed: %w", err)
		}
		lis.Close()

		break
	}

	grpcPort := uint16(_grpcPort)

	for _, opt := range opts {
		switch o := opt.(type) {
		case *WireGuardPortOption:
			wgPort = o.port
		case *GrpcPortOption:
			grpcPort = o.port
		default:
			return nil, fmt.Errorf("invalid option type: %T", opt)
		}
	}

	bgpServer := server.NewBgpServer(
		server.GrpcListenAddress(fmt.Sprintf("127.0.0.1:%d", grpcPort)),
		server.LoggerOption(&log.BgpServerLogger{}),
	)
	go bgpServer.Serve()

	wgClient, err := wgctrl.New()
	if err != nil {
		return nil, fmt.Errorf("new wireguard client: %w", err)
	}

	m := &Manager{
		bgpServer: bgpServer,
		wgClient:  wgClient,

		networkId: *(*[4]byte)(unsafe.Pointer(&networkIdBytes[0])),
		nodeId:    *(*[2]byte)(unsafe.Pointer(&nodeIdBytes[0])),

		closeCh: make(chan struct{}),
	}

	// Start the service.

	err = m.startBgpServer()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("start bgp server: %w", err)
	}

	err = m.startWireGuardInterface(wgPrivateKey, wgPort)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("start wireguard interface: %w", err)
	}

	err = m.addLocalWireGuardPeer(wgPublicKey, wgPort)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("add local wireguard peer: %w", err)
	}

	err = m.watchWireGuardPeers()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("watch wireguard peers: %w", err)
	}

	err = m.watchGenericPeers()
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("watch generic peers: %w", err)
	}

	err = m.addControllerPeer(controllerAddress.Addr(), controllerAddress.Port(), controllerPassword)
	if err != nil {
		m.Close()
		return nil, fmt.Errorf("start controller peer: %w", err)
	}

	return m, nil
}

func (m *Manager) startWireGuardInterface(privateKey wgtypes.Key, port uint16) error {
	// If a WireGuard interface already exists, delete it and recreate it.
	link, err := netlink.LinkByName(m.getInterfaceName())
	if err == nil {
		if link.Type() == "wireguard" {
			netlink.LinkDel(link)
		} else {
			return fmt.Errorf("interface exists but not wireguard: %s", m.getInterfaceName())
		}
	}

	err = netlink.LinkAdd(&netlink.Wireguard{
		LinkAttrs: netlink.LinkAttrs{
			Name:  m.getInterfaceName(),
			MTU:   _wgMtu,
			Flags: net.FlagUp,
		},
	})
	if err != nil {
		return fmt.Errorf("add wireguard interface: %w", err)
	}

	link, err = netlink.LinkByName(m.getInterfaceName())
	if err != nil {
		return fmt.Errorf("get wireguard interface: %w", err)
	}

	p := int(port)
	err = m.wgClient.ConfigureDevice(m.getInterfaceName(), wgtypes.Config{
		PrivateKey:   &privateKey,
		ListenPort:   &p,
		ReplacePeers: true,
	})
	if err != nil {
		return fmt.Errorf("configure wireguard device: %w", err)
	}

	addr := m.getLocalAddress().As4()
	err = netlink.AddrReplace(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   addr[:],
			Mask: net.CIDRMask(16, 32),
		},
	})
	if err != nil {
		return fmt.Errorf("add address to wireguard interface: %w", err)
	}

	return nil
}

func (m *Manager) startBgpServer() error {
	err := m.bgpServer.StartBgp(context.Background(), &apipb.StartBgpRequest{
		Global: &apipb.Global{
			Asn:        _asn,
			RouterId:   m.getLocalAddress().String(),
			ListenPort: 179,
		},
	})
	if err != nil {
		return fmt.Errorf("start bgp server: %w", err)
	}

	return nil
}

func (m *Manager) addControllerPeer(addr netip.Addr, port uint16, password string) error {
	err := m.bgpServer.AddPeer(context.Background(), &apipb.AddPeerRequest{
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
				AuthPassword:    password,
				PeerAsn:         _asn,
				Type:            apipb.PeerType_INTERNAL,
			},
			Timers: &apipb.Timers{
				Config: m.getBgpTimersConfig(),
			},
			Transport: &apipb.Transport{
				RemotePort:   uint32(port),
				MtuDiscovery: true,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("start controller peer: %w", err)
	}

	return nil
}

func (m *Manager) addLocalWireGuardPeer(publicKey wgtypes.Key, port uint16) error {
	nlri, _ := anypb.New(&apipb.IPAddressPrefix{
		Prefix:    m.getLocalAddress().String(),
		PrefixLen: 32,
	})

	a1, _ := anypb.New(&apipb.OriginAttribute{
		Origin: uint32(0), // IGP
	})

	a2, _ := anypb.New(&apipb.NextHopAttribute{
		NextHop: "::",
	})

	a3, _ := anypb.New(&apipb.WireGuardPeerAttribute{
		EndpointAddress:     "::", // not used
		EndpointPort:        uint32(port),
		PublicKey:           base64.StdEncoding.EncodeToString(publicKey[:]),
		PersistentKeepalive: 0, // not used
	})

	a4, _ := anypb.New(&apipb.CommunitiesAttribute{
		Communities: []uint32{_bgpCommunity_WireGuardPeer},
	})

	attrs := []*anypb.Any{a1, a2, a3, a4}

	_, err := m.bgpServer.AddPath(context.Background(), &apipb.AddPathRequest{
		TableType: apipb.TableType_GLOBAL,
		Path: &apipb.Path{
			Family: &apipb.Family{
				Afi:  apipb.Family_AFI_IP,
				Safi: apipb.Family_SAFI_UNICAST,
			},
			Nlri:   nlri,
			Pattrs: attrs,
			Best:   true,
		},
	})
	if err != nil {
		return fmt.Errorf("add wireguard peer path: %w", err)
	}

	return nil
}

// This will immediately close all BGP sessions and gRPC connections.
func (m *Manager) Close() {
	m.closeOnce.Do(func() {
		close(m.closeCh)

		m.bgpServer.Stop()
		m.wgClient.Close()
	})

	m.wait.Wait()
}
