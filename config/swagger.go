package config

type Swagger struct {
	URL string
}

func SwaggerUrl() string {
	return cfg.Swagger.URL
}
