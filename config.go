package gowired

import (
	"errors"
	"fmt"

	"net/netip"
	"os"
)

// Configuration for a wireguard peer
type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

// DeviceConfig contains the information to initiate a wireguard connection
type DeviceConfig struct {
	SecretKey string
	Endpoint  []netip.Addr
	Peers     []PeerConfig
	DNS       []netip.Addr
	MTU       int
}

func MustGetEnv(k string) string {
	var r = os.Getenv(k)
	if r == "" {
		panic(fmt.Sprintf("Unable to get environment varialbe for %s", k))
	}
	return r
}

func getIPAddr(ip string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ip)
	if err == nil {
		return addr, err
	}
	if prefix, err := netip.ParsePrefix(ip); err == nil && prefix.Bits() != addr.BitLen() {
		return prefix.Addr(), nil
	}
	return addr, err
}

func getEndpoint(ip string) ([]netip.Addr, error) {
	var ips []netip.Addr
	prefix, err := netip.ParsePrefix(ip)
	if err != nil {
		return nil, err
	}

	addr := prefix.Addr()
	if prefix.Bits() != addr.BitLen() {
		return nil, errors.New("interface address subnet should be /32 for IPv4 and /128 for IPv6")
	}

	ips = append(ips, addr)
	return ips, nil
}

func getPeers() ([]PeerConfig, error) {
	peer := PeerConfig{
		PublicKey:    MustGetEnv("GOWIRED_PEER_PUBLIC_KEY"),
		PreSharedKey: os.Getenv("GOWIRED_PEER_PRE_SHARED_KEY"),
		Endpoint:     MustGetEnv("GOWIRED_PEER_ENDPOINT"),
		KeepAlive:    30,
		AllowedIPs:   []netip.Prefix{},
	}
	return []PeerConfig{peer}, nil
}

func GetDeviceConfig() (*DeviceConfig, error) {
	peers, err := getPeers()
	if err != nil {
		return nil, err
	}
	address, err := getIPAddr(MustGetEnv("GOWIRED_ADDRESS"))
	if err != nil {
		return nil, err
	}
	device := DeviceConfig{
		SecretKey: MustGetEnv("GOWIRED_SECRET_KEY"),
		Endpoint:  []netip.Addr{address},
		MTU:       1420,
		Peers:     peers,
	}
	return &device, nil
}
