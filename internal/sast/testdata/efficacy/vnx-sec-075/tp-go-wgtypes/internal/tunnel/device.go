package tunnel

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

func serverKey() (wgtypes.Key, error) {
~>	return wgtypes.ParseKey("@@sample:[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=@@")
}
