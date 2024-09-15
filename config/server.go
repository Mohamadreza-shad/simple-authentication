package config

type Server struct {
	Http Http
}

type Http struct {
	Address string
}

func ServerHttpAddress() string {
	return cfg.Server.Http.Address
}

