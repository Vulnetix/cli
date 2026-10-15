from pyroute2 import WireGuard

wg = WireGuard()
~>SERVER_PRIVATE_KEY = "@@sample:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=@@"
wg.set("wg0", private_key=SERVER_PRIVATE_KEY, listen_port=51820)
