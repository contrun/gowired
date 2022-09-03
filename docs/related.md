Related projects

# VPN solutions
[openvpn](https://openvpn.net/), [tinc](https://www.tinc-vpn.org/) etc
application sockets -> kernel network stack -> tun/tap device -> client side vpn daemon -> server side vpn daemon -> kernel ip forwarding -> internet
application sockets -> kernel network stack -> tun/tap device -> client side vpn daemon -> server side vpn daemon -> uplevel applications 

# VPN to socks5/http proxy
[wireproxy](https://github.com/octeep/wireproxy/), [onetun](https://github.com/aramperes/onetun/) etc
application -> socks5/http server -> fake tun/tap device by netstack -> client side wireguard -> server side wireguard server -> kernel ip forwarding -> internet

# socks5/http proxy to VPN
[badvpn](https://github.com/aramperes/onetun/), [tun2socks](https://github.com/xjasonlyu/tun2socks), [redsocks](https://github.com/aramperes/onetun/) etc
application sockets -> kernel network stack -> tun/tap device -> netstack -> socks/http proxy client -> socks/http proxy server -> internet

# This project
application -> kernel ->  client side wireguard -> wireguard server -> netstack -> sockets interface -> kernel network stack -> internet
application -> kernel ->  client side wireguard -> wireguard server -> netstack -> socks5/http proxy client -> socks5/http proxy server -> kernel network stack -> internet

## So why
- Requires no special privilege, not even the capabilities to create tun/tap devices.
- Easily chain proxy services.
- Leverages existing tools in wireguard ecosystem and existing socks5/http proxy solutions.
