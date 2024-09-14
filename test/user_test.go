package test

import (
	"context"
	"fmt"
	"testing"

	"github.com/Mohamadreza-shad/simple-authentication/api"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	"github.com/Mohamadreza-shad/simple-authentication/service/user"

	// "github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

func Test_UserCannot_Signup_UsernameIsAlreadyTaken(t *testing.T) {
	// Arrange
	ctx := context.Background()
	assert := assert.New(t)
	logger := getLogger()
	validator := validator.New()
	redisClient := getRedis()
	err := redisClient.FlushAll(ctx).Err()
	assert.Nil(err)
	db := getDB()
	repo := repository.New()
	userService := user.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	fmt.Println(userHandler)

	// gin.SetMode(gin.TestMode)
	// r := gin.Default()
	// Act
	// Assert
}
