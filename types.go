package gowired

import (
	"net/netip"

	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// VirtualTun stores a reference to netstack network and DNS configuration
type VirtualTun struct {
	tnet      *netstack.Net
	ns        *stack.Stack
	localAddr []netip.Addr
	systemDNS bool
}

func (vt *VirtualTun) isLocalIP(addr netip.Addr) bool {
	for _, a := range vt.localAddr {
		if a == addr {
			return true
		}
	}
	return false
}
