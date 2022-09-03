package main

import (
	"log"

	"github.com/contrun/gowired"
)

func main() {
	deviceConfig, err := gowired.GetDeviceConfig()
	if err != nil {
		log.Fatalf("Unable to get device config %s", err)
	}
	_, err = gowired.StartWireguard(deviceConfig)
	if err != nil {
		log.Fatalf("Unable to start wireguard server %s", err)
	}

	select {}
}
