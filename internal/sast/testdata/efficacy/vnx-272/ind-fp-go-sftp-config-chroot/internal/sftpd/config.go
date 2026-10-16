package sftpd

type ServerConfig struct {
	Chroot   string
	ReadOnly bool
}

func DefaultConfig(home string) ServerConfig {
	return ServerConfig{
		Chroot:   home,
		ReadOnly: true,
	}
}
