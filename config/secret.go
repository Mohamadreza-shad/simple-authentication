package config

type Secret struct{
	Key string
}

func SecretKey() string{
	return cfg.Secret.Key
}

