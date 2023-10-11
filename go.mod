module github.com/contrun/gowired

go 1.18

require (
	github.com/MakeNowJust/heredoc/v2 v2.0.1
	golang.zx2c4.com/wireguard v0.0.0-20220829161405-d1d08426b27b
	gvisor.dev/gvisor v0.0.0-20220817001344-846276b3dbc5
)

require (
	github.com/google/btree v1.0.1 // indirect
	golang.org/x/crypto v0.14.0 // indirect
	golang.org/x/net v0.17.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20211104114900-415007cec224 // indirect
)

replace golang.zx2c4.com/wireguard => github.com/contrun/wireguard-go v0.0.0-20220912024742-0aba56374c8b
