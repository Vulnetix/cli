package config

import "encoding/hex"

func persist(cfg *Config, w Writer) error {
~>	w.Set("db_pass", hex.EncodeToString([]byte(cfg.DBPassword)))
	return w.Flush()
}
