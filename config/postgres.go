package config

type Postgres struct {
	URL string
}

func GetPostgresURL() string {
	if cfg.Postgres.URL == "" {
		return "postgres://postgres:postgres@localhost:5432/auth_db"
	}
	return cfg.Postgres.URL
}
