package config

type RedisMasterName struct {
	Name string
}

type Redis struct {
	URI    string
	Master RedisMasterName
}

func GetRedisURI() string {
	if cfg.Redis.URI == "" && GetEnv() == EnvTest {
		return "redis://:123456@localhost:6379"
	}
	return cfg.Redis.URI
}

func GetRedisMasterName() string {
	return cfg.Redis.Master.Name
}