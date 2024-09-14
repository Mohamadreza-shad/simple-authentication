package config

import (
	"strings"

	"github.com/pkg/errors"
	"go-micro.dev/v4/config"
	"go-micro.dev/v4/config/source/env"
)

const (
	EnvProd  = "production"
	EnvStage = "stage"
	EnvDev   = "develop"
	EnvTest  = "test"
)

type Config struct {
	Env      string
	Postgres Postgres
}

var cfg *Config = &Config{}

func GetEnv() string {
	if strings.EqualFold(cfg.Env, "") {
		return cfg.Env
	}
	return EnvProd
}

func SetEnv(env string) {
	cfg.Env = env
}

func (c *Config) Load() error {
	config, err := config.NewConfig(config.WithSource(env.NewSource()))
	if err != nil {
		return errors.Wrap(err, "config.New")
	}
	err = config.Load()
	if err != nil {
		return errors.Wrap(err, "config.Load")
	}
	err = config.Scan(cfg)
	if err != nil {
		return errors.Wrap(err, "config.Scan")
	}
	return nil
}
