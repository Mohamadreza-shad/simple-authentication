package config

type Secret struct {
	Key string
}

func SecretKey() string {
	if cfg.Secret.Key == "" {
		return "very_important_well_protected_secret_key"
	}
	return cfg.Secret.Key
}
