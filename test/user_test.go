package test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Mohamadreza-shad/simple-authentication/api"
	"github.com/Mohamadreza-shad/simple-authentication/config"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	"github.com/Mohamadreza-shad/simple-authentication/service/user"
	"github.com/gin-gonic/gin"

	"github.com/go-playground/validator/v10"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type ResponseSuccess struct {
	Success bool                `json:"success" example:"true"`
	Message string              `json:"message,omitempty"`
	Data    user.SignUpResponse `json:"data,omitempty"`
}

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
	err = truncateDB()
	assert.Nil(err)
	repo := repository.New()
	userService := user.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", userHandler.SignUp)

	_, err = repo.SignUp(ctx, db, repository.SignUpParams{
		Username:     "test-user",
		Password:     "p@sW0rd",
		NationalCode: "1234567890",
		Phone:        "09123456789",
	})
	assert.Nil(err)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(user.SignUpParams{
		Username:     "test-user",
		Password:     "p@sW0rd",
		NationalCode: "1234567890",
		Phone:        "09123456789",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	// Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	// Assert
	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	response := api.ResponseFailure{}
	err = json.Unmarshal(respInByte, &response)
	assert.Nil(err)

	assert.False(response.Success)
	assert.Equal(response.Error.Code, http.StatusConflict)
	assert.Equal(response.Error.Message, user.ErrUsernameAlreadyTaken.Error())
}

func Test_User_Signup_Successfully(t *testing.T) {
	// Arrange
	ctx := context.Background()
	assert := assert.New(t)
	logger := getLogger()
	validator := validator.New()
	redisClient := getRedis()
	err := redisClient.FlushAll(ctx).Err()
	assert.Nil(err)
	db := getDB()
	err = truncateDB()
	assert.Nil(err)
	repo := repository.New()
	userService := user.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", userHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(user.SignUpParams{
		Username:     "test-user",
		Password:     "p@sW0rd",
		NationalCode: "1234567890",
		Phone:        "09123456789",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	// Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	// Assert
	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	response := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &response)
	assert.Nil(err)

	assert.True(response.Success)
	assert.NotEqual(response.Data.AccessToken, "")
	assert.NotEqual(response.Data.RefreshToken, "")

	// Check if the user is created in the database
	createdUser, err := repo.UserByName(ctx, db, "test-user")
	assert.Nil(err)
	assert.NotNil(createdUser)
	assert.Equal(createdUser.Username, "test-user")
	assert.Equal(createdUser.NationalCode, "1234567890")
	assert.Equal(createdUser.Phone, "09123456789")
	assert.True(createdUser.IsActive)

	// Check if the refresh token is saved in the redis
	refreshToken, err := redisClient.Get(ctx, fmt.Sprintf("userId:%d", createdUser.ID)).Result()
	assert.Nil(err)
	assert.NotEqual(refreshToken, "")

	// Check if the access token is valid
	token, err := jwtLib.ParseWithClaims(
		refreshToken,
		&jwtLib.RegisteredClaims{},
		func(token *jwtLib.Token) (interface{}, error) {
			// Ensure the signing method is what you expect
			_, ok := token.Method.(*jwtLib.SigningMethodHMAC)
			assert.True(ok)
			// Return the secret key used for signing the token
			return []byte(config.SecretKey()), nil
		})
	assert.Nil(err)
	claims, ok := token.Claims.(*jwtLib.RegisteredClaims)
	assert.True(ok)
	assert.True(token.Valid)
	assert.Equal(claims.Issuer, user.TOKENISSUER)
	assert.Equal(claims.Subject, fmt.Sprintf("userId:%d", createdUser.ID))
}
