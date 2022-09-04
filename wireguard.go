package gowired

import (
	"bytes"
	"fmt"
	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr []netip.Addr
	mtu        int
}

// serialize the config into an IPC request and DeviceSetting
func createIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				endpoint=%s
			`),
			peer.PublicKey, peer.Endpoint,
		))

		if peer.KeepAlive != 0 {
			request.WriteString(fmt.Sprintf(heredoc.Doc(`
				persistent_keepalive_interval=%d
			`), peer.KeepAlive,
			))
		}

		if peer.PreSharedKey != "" {
			request.WriteString(fmt.Sprintf(heredoc.Doc(`
				preshared_key=%s
			`), peer.PreSharedKey,
			))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{ipcRequest: request.String(), dns: conf.DNS, deviceAddr: conf.Endpoint, mtu: conf.MTU}
	return setting, nil
}

func StartWireguard(conf *DeviceConfig) (*VirtualTun, error) {
	setting, err := createIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.deviceAddr, setting.dns, setting.mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	fmt.Println(setting.ipcRequest)
	err = dev.IpcSet(setting.ipcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	ns, err := tnet.NetworkStack()
	if err != nil {
		return nil, err
	}
	return &VirtualTun{
		tnet:      tnet,
		ns:        ns,
		localAddr: conf.Endpoint,
		systemDNS: len(setting.dns) == 0,
	}, nil
}
