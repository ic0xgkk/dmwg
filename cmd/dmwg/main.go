package main

import (
	"flag"
	"net/netip"
	"os"
	"os/signal"
	"syscall"

	"github.com/golang/glog"
	"github.com/ic0xgkk/dmwg/manager"
)

var (
	networkId          string
	nodeId             string
	controllerAddress  string
	controllerPassword string
)

func init() {
	flag.StringVar(&networkId, "network-id", "", "Network ID")
	flag.StringVar(&nodeId, "node-id", "", "Node ID")
	flag.StringVar(&controllerAddress, "controller-address", "[2400::2]:20179", "Controller address, only support IPv6")
	flag.StringVar(&controllerPassword, "controller-password", "", "Controller password")
}

func main() {
	flag.Parse()
	defer glog.Flush()

	addrPort, err := netip.ParseAddrPort(controllerAddress)
	if err != nil {
		glog.Fatalf("failed to parse controller address: %v", err)
	}

	m, err := manager.New(networkId, nodeId, addrPort, controllerPassword)
	if err != nil {
		glog.Fatalf("failed to create manager: %v", err)
	}
	defer m.Close()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
}
