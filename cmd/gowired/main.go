package main

import (
	"log"

	"github.com/contrun/gowired"
)

func main() {
	deviceConfig, err := gowired.GetDeviceConfig()
	if err != nil {
		log.Fatalf("Unable to get device config %v", err)
	}
	vt, err := gowired.StartWireguard(deviceConfig)
	if err != nil {
		log.Fatalf("Unable to start wireguard server %v", err)
	}

	err = vt.SetupForwarding()
	if err != nil {
		log.Fatalf("Unable to setup forwarding %v", err)
	}
	select {}
}
