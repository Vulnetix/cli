/interface wireguard
~>add listen-port=13231 mtu=1420 name=wg-hq private-key="@@sample:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=@@"
/interface wireguard peers
add allowed-address=10.9.0.0/24 endpoint-address=vpn.acme-corp.io interface=wg-hq
