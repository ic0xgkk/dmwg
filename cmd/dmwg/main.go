package main

import (
	"flag"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/golang/glog"
	"github.com/ic0xgkk/dmwg/manager"
)

var (
	networkId             string
	nodeId                string
	controllerAddressPort string
	controllerPassword    string
	advertiserPrefixes    string
)

func init() {
	flag.StringVar(&networkId, "network-id", "", "Network ID, 8 size hex string")
	flag.StringVar(&nodeId, "node-id", "", "Node ID, 4 size hex string")
	flag.StringVar(&controllerAddressPort, "controller-address-port", "", "Controller address with port, only support IPv6, e.g. '[2400::1]:20179'")
	flag.StringVar(&controllerPassword, "controller-password", "", "Controller password, 1-32 size string")
	flag.StringVar(&advertiserPrefixes, "advertiser-prefixes", "", "Advertiser prefixes separated by comma, only support IPv4, e.g. '192.168.1.0/24,192.168.2.0/24'")
}

func main() {
	flag.Parse()
	defer glog.Flush()

	addrPort, err := netip.ParseAddrPort(controllerAddressPort)
	if err != nil {
		glog.Fatalf("failed to parse controller address: %v", err)
	}

	var prefixes []netip.Prefix
	ss := strings.Split(advertiserPrefixes, ",")
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}

		p, err := netip.ParsePrefix(s)
		if err != nil {
			glog.Fatalf("failed to parse prefix: %v", err)
		}
		if !p.Addr().Is4() {
			glog.Fatalf("only support IPv4 prefix: %s", s)
		}

		prefixes = append(prefixes, p)
	}

	m, err := manager.New(networkId, nodeId, addrPort, controllerPassword)
	if err != nil {
		glog.Fatalf("failed to create manager: %v", err)
	}
	defer m.Close()

	for _, pfx := range prefixes {
		err = m.AddLocalGenericPrefix(pfx)
		if err != nil {
			glog.Fatalf("failed to add local generic prefix: %v", err)
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
}
