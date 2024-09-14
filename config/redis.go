package config

import "fmt"

type RedisMasterName struct {
	Name string
}

type Redis struct {
	URI    string
	Master RedisMasterName
}

func GetRedisURI() string {
	fmt.Println(GetEnv())
	if cfg.Redis.URI == "" {
		return "redis://:123456@localhost:6379"
	}
	return cfg.Redis.URI
}

func GetRedisMasterName() string {
	return cfg.Redis.Master.Name
}