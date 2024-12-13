package manager

import (
	"net/netip"
	"runtime"
	"testing"
)

func TestXxx(t *testing.T) {
	// os.Args = append(os.Args, "-logtostderr", "-v=10")
	// flag.Parse()
	// defer glog.Flush()

	m, err := New("f1883269", "ce2d", netip.MustParseAddrPort("[2400::2]:20179"), "password")
	if err != nil {
		t.Fatalf("failed to create manger: %v", err)
	}
	runtime.GC()
	defer m.Close()

	for {
	}
}
