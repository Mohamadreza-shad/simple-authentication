package main

import (
	"log"
	"net/http"

	"github.com/Mohamadreza-shad/simple-authentication/api"
	"github.com/Mohamadreza-shad/simple-authentication/api/router"
	"github.com/Mohamadreza-shad/simple-authentication/client"
	"github.com/Mohamadreza-shad/simple-authentication/config"
	"github.com/Mohamadreza-shad/simple-authentication/logger"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	"github.com/Mohamadreza-shad/simple-authentication/service/auth"
	"github.com/Mohamadreza-shad/simple-authentication/service/user"
	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

func main() {
	err := config.Load()
	if err != nil {
		log.Fatal("failed to load config", zap.Error(err))
	}
	logger, err := logger.New()
	if err != nil {
		log.Fatal("failed to initialize logger", err)
	}
	defer logger.Sync()

	dbClient, err := client.NewDBClient()
	if err != nil {
		logger.Fatal("failed to initiate a db client", zap.Error(err))
	}
	defer dbClient.Close()

	redisClient, err := client.NewRedisClient()
	if err != nil {
		logger.Fatal(err.Error())
	}
	defer redisClient.Close()
	repo := repository.New()

	authService := auth.New(dbClient,repo,redisClient,logger)
	userService := user.New(dbClient,repo,redisClient,logger)
	validator := validator.New()

	authHandler := api.NewAuthHandler(authService,validator)
	userHandler := api.NewUserHandler(userService,validator)

	router := router.New(authHandler,userHandler,authService,logger)
	httpServer := &http.Server{
		Addr: config.ServerHttpAddress(),
		Handler: router.Handler,
	}
	logger.Info("starting HTTP server on %s", zap.String("HTTP server address: ", config.ServerHttpAddress()))
	err = httpServer.ListenAndServe()
	if err != nil {
		logger.Fatal(err.Error())
	}
}
