package config

type Swagger struct {
	URL string
}

func SwaggerUrl() string {
	if cfg.Swagger.URL == "" {
		return "http://localhost:3000/"
		
	}
	return cfg.Swagger.URL
}
