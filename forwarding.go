package gowired

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

const maxUDPPacketSize = 1500

func (vt *VirtualTun) SetupForwarding() error {
	log.Printf("Setting up forwarding")
	const wgNicID = 1

	// By default the netstack NIC will only accept packets for the IPs
	// registered to it. Since in some cases we dynamically register IPs
	// based on the packets that arrive, the NIC needs to accept all
	// incoming packets. The NIC won't receive anything it isn't meant to
	// since WireGuard will only send us packets that are meant for us.
	vt.ns.SetPromiscuousMode(wgNicID, true)
	// This is needed because when a new connection is send to netstack NIC
	// we need to CreateEndpoint for that connection and if spoofing is not
	// set, CreateEndpoint would fail with ErrNoRoute
	vt.ns.SetSpoofing(wgNicID, true)
	vt.ns.NICForwarding(wgNicID, ipv4.ProtocolNumber)
	vt.ns.NICForwarding(wgNicID, ipv6.ProtocolNumber)
	// Add IPv4 and IPv6 default routes, so all incoming packets from vpn side
	// are handled by the one fake NIC we use.
	ipv4Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 4)), tcpip.AddressMask(strings.Repeat("\x00", 4)))
	ipv6Subnet, _ := tcpip.NewSubnet(tcpip.Address(strings.Repeat("\x00", 16)), tcpip.AddressMask(strings.Repeat("\x00", 16)))
	vt.ns.SetRouteTable([]tcpip.Route{
		{
			Destination: ipv4Subnet,
			NIC:         wgNicID,
		},
		{
			Destination: ipv6Subnet,
			NIC:         wgNicID,
		},
	})

	// size = 0 means use default buffer size
	const tcpReceiveBufferSize = 0
	const maxInFlightConnectionAttempts = 16
	tcpFwd := tcp.NewForwarder(vt.ns, tcpReceiveBufferSize, maxInFlightConnectionAttempts, vt.acceptTCP)
	vt.ns.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(vt.ns, vt.acceptUDP)
	vt.ns.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)

	return nil
}

func (vt *VirtualTun) acceptTCP(r *tcp.ForwarderRequest) {
	sess := r.ID()
	log.Printf("[v2] TCP ForwarderRequest: %s\n", stringifyTEI(sess))
	clientRemoteIP, ok := ipOfNetstackAddr(sess.RemoteAddress)
	if !ok {
		log.Printf("invalid RemoteAddress in TCP ForwarderRequest: %s", stringifyTEI(sess))
		r.Complete(true) // sends a RST
		return
	}

	dialAddr, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
	if !ok {
		log.Printf("invalid RemoteAddress in TCP ForwarderRequest: %s", stringifyTEI(sess))
		r.Complete(true) // sends a RST
		return
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Printf("CreateEndpoint error for %s: %v", stringifyTEI(sess), err)
		r.Complete(true) // sends a RST
		return
	}
	r.Complete(false)

	// SetKeepAlive so that idle connections to peers that have forgotten about
	// the connection or gone completely offline eventually time out.
	// Applications might be setting this on a forwarded connection, but from
	// userspace we can not see those, so the best we can do is to always
	// perform them with conservative timing.
	// TODO(tailscale/tailscale#4522): Netstack defaults match the Linux
	// defaults, and results in a little over two hours before the socket would
	// be closed due to keepalive. A shorter default might be better, or seeking
	// a default from the host IP stack. This also might be a useful
	// user-tunable, as in userspace mode this can have broad implications such
	// as lingering connections to fork style daemons. On the other side of the
	// fence, the long duration timers are low impact values for battery powered
	// peers.
	ep.SocketOptions().SetKeepAlive(true)

	// The ForwarderRequest.CreateEndpoint above asynchronously
	// starts the TCP handshake. Note that the gonet.TCPConn
	// methods c.RemoteAddr() and c.LocalAddr() will return nil
	// until the handshake actually completes. But we have the
	// remote address in reqDetails instead, so we don't use
	// gonet.TCPConn.RemoteAddr. The byte copies in both
	// directions to/from the gonet.TCPConn in forwardTCP will
	// block until the TCP handshake is complete.
	c := gonet.NewTCPConn(&wq, ep)

	vt.forwardTCP(c, &wq, clientRemoteIP, dialAddr)
}

func (vt *VirtualTun) forwardTCP(client *gonet.TCPConn, wq *waiter.Queue, clientIP netip.Addr, dstAddr netip.AddrPort) {
	defer client.Close()
	isLocal := vt.isLocalIP(dstAddr.Addr())
	if isLocal {
		dstAddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), dstAddr.Port())
	}
	dialAddrStr := dstAddr.String()
	log.Printf("[v2] netstack: forwarding incoming connection to %s", dialAddrStr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	waitEntry, notifyCh := waiter.NewChannelEntry(waiter.EventHUp) // TODO(bradfitz): right EventMask?
	wq.EventRegister(&waitEntry)
	defer wq.EventUnregister(&waitEntry)
	done := make(chan bool)
	// netstack doesn't close the notification channel automatically if there was no
	// hup signal, so we close done after we're done to not leak the goroutine below.
	defer close(done)
	go func() {
		select {
		case <-notifyCh:
			log.Printf("[v2] netstack: forwardTCP notifyCh fired; canceling context for %s", dialAddrStr)
		case <-done:
		}
		cancel()
	}()
	var stdDialer net.Dialer
	server, err := stdDialer.DialContext(ctx, "tcp", dialAddrStr)
	if err != nil {
		log.Printf("netstack: could not connect to local server at %s: %v", dialAddrStr, err)
		return
	}
	defer server.Close()
	connClosed := make(chan error, 2)
	go func() {
		_, err := io.Copy(server, client)
		connClosed <- err
	}()
	go func() {
		_, err := io.Copy(client, server)
		connClosed <- err
	}()
	err = <-connClosed
	if err != nil {
		log.Printf("proxy connection closed with error: %v", err)
	}
	log.Printf("[v2] netstack: forwarder connection to %s closed", dialAddrStr)
}

func (vt *VirtualTun) acceptUDP(r *udp.ForwarderRequest) {
	sess := r.ID()
	log.Printf("acceptUDP: id %s", stringifyTEI(sess))
	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		log.Printf("acceptUDP: could not create endpoint for %s: %v", stringifyTEI(sess), err)
		return
	}
	dstAddr, ok := ipPortOfNetstackAddr(sess.LocalAddress, sess.LocalPort)
	if !ok {
		return
	}
	srcAddr, ok := ipPortOfNetstackAddr(sess.RemoteAddress, sess.RemotePort)
	if !ok {
		return
	}

	c := gonet.NewUDPConn(vt.ns, &wq, ep)
	go vt.forwardUDP(c, &wq, srcAddr, dstAddr)
}

// forwardUDP proxies between client (with addr clientAddr) and dstAddr.
//
// dstAddr may be either a local Tailscale IP, in which we case we proxy to
// 127.0.0.1, or any other IP (from an advertised subnet), in which case we
// proxy to it directly.
func (vt *VirtualTun) forwardUDP(client *gonet.UDPConn, wq *waiter.Queue, clientAddr, dstAddr netip.AddrPort) {
	port, srcPort := dstAddr.Port(), clientAddr.Port()
	log.Printf("forwarding incoming UDP connection on port %v", port)

	var backendListenAddr *net.UDPAddr
	var backendRemoteAddr *net.UDPAddr
	isLocal := vt.isLocalIP(dstAddr.Addr())
	if isLocal {
		backendRemoteAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(port)}
		backendListenAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: int(srcPort)}
	} else {
		backendRemoteAddr = net.UDPAddrFromAddrPort(dstAddr)
		if dstAddr.Addr().Is4() {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: int(srcPort)}
		} else {
			backendListenAddr = &net.UDPAddr{IP: net.ParseIP("::"), Port: int(srcPort)}
		}
	}

	backendConn, err := net.ListenUDP("udp", backendListenAddr)
	if err != nil {
		log.Printf("netstack: could not bind local port %v: %v, trying again with random port", backendListenAddr.Port, err)
		backendListenAddr.Port = 0
		backendConn, err = net.ListenUDP("udp", backendListenAddr)
		if err != nil {
			log.Printf("netstack: could not create UDP socket, preventing forwarding to %v: %v", dstAddr, err)
			return
		}
	}
	backendLocalAddr := backendConn.LocalAddr().(*net.UDPAddr)

	backendLocalIPPort := netip.AddrPortFrom(backendListenAddr.AddrPort().Addr().Unmap().WithZone(backendLocalAddr.Zone), backendLocalAddr.AddrPort().Port())
	if !backendLocalIPPort.IsValid() {
		log.Printf("could not get backend local IP:port from %v:%v", backendLocalAddr.IP, backendLocalAddr.Port)
	}

	ctx, cancel := context.WithCancel(context.Background())

	idleTimeout := 2 * time.Minute
	if port == 53 {
		// Make DNS packet copies time out much sooner.
		idleTimeout = 30 * time.Second
	}
	timer := time.AfterFunc(idleTimeout, func() {
		log.Printf("netstack: UDP session between %s and %s timed out", backendListenAddr, backendRemoteAddr)
		cancel()
		client.Close()
		backendConn.Close()
	})

	extend := func() {
		timer.Reset(idleTimeout)
	}

	startPacketCopy(ctx, cancel, client, net.UDPAddrFromAddrPort(clientAddr), backendConn, extend)
	startPacketCopy(ctx, cancel, backendConn, backendRemoteAddr, client, extend)
	if isLocal {
		// Wait for the copies to be done before decrementing the
		// subnet address count to potentially remove the route.
		<-ctx.Done()
	}
}

func startPacketCopy(ctx context.Context, cancel context.CancelFunc, dst net.PacketConn, dstAddr net.Addr, src net.PacketConn, extend func()) {
	log.Printf("[v2] netstack: startPacketCopy to %v (%T) from %T", dstAddr, dst, src)
	go func() {
		defer cancel() // tear down the other direction's copy
		pkt := make([]byte, maxUDPPacketSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, srcAddr, err := src.ReadFrom(pkt)
				if err != nil {
					if ctx.Err() == nil {
						log.Printf("read packet from %s failed: %v", srcAddr, err)
					}
					return
				}
				_, err = dst.WriteTo(pkt[:n], dstAddr)
				if err != nil {
					if ctx.Err() == nil {
						log.Printf("write packet to %s failed: %v", dstAddr, err)
					}
					return
				}
				log.Printf("[v2] wrote UDP packet %s -> %s", srcAddr, dstAddr)
				extend()
			}
		}
	}()
}

func ipPortOfNetstackAddr(a tcpip.Address, port uint16) (ipp netip.AddrPort, ok bool) {
	var a16 [16]byte
	copy(a16[:], a)
	switch len(a) {
	case 4:
		return netip.AddrPortFrom(
			netip.AddrFrom4(*(*[4]byte)(a16[:4])).Unmap(),
			port,
		), true
	case 16:
		return netip.AddrPortFrom(netip.AddrFrom16(a16).Unmap(), port), true
	default:
		return ipp, false
	}
}

func ipOfNetstackAddr(a tcpip.Address) (ip netip.Addr, ok bool) {
	addr, ok := ipPortOfNetstackAddr(a, 0)
	return addr.Addr(), ok
}

func stringifyTEI(tei stack.TransportEndpointID) string {
	localHostPort := net.JoinHostPort(tei.LocalAddress.String(), strconv.Itoa(int(tei.LocalPort)))
	remoteHostPort := net.JoinHostPort(tei.RemoteAddress.String(), strconv.Itoa(int(tei.RemotePort)))
	return fmt.Sprintf("%s -> %s", remoteHostPort, localHostPort)
}
