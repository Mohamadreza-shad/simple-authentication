package config

type Swagger struct {
	URL string
}

func SwaggerUrl() string {
	if cfg.Swagger.URL == "" {
		return "localhost:3000"
		
	}
	return cfg.Swagger.URL
}
