package vpn

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

func NewKey() (wgtypes.Key, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	return priv, nil
}

func FromEnv(s string) (wgtypes.Key, error) { return wgtypes.ParseKey(s) }
