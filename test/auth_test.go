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
	"time"

	"github.com/Mohamadreza-shad/simple-authentication/api"
	"github.com/Mohamadreza-shad/simple-authentication/config"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	"github.com/Mohamadreza-shad/simple-authentication/service/auth"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"

	"github.com/go-playground/validator/v10"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type ResponseSuccess struct {
	Success bool                `json:"success" example:"true"`
	Message string              `json:"message,omitempty"`
	Data    auth.SignUpResponse `json:"data,omitempty"`
}

func Test_UserCannot_SignUp_UsernameIsAlreadyTaken(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	_, err = repo.SignUp(ctx, db, repository.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
		NationalCode: "1234567890",
		Phone:        "09123456789",
	})
	assert.Nil(err)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
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
	assert.Equal(response.Error.Message, auth.ErrUsernameAlreadyTaken.Error())
}

func Test_User_SignUp_Successfully(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
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
	assert.Equal(claims.Issuer, auth.TOKENISSUER)
	assert.Equal(claims.Subject, fmt.Sprintf("userId:%d", createdUser.ID))
}

func Test_User_SingIn_NoUserFoundPleaseSignUp(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signin", authHandler.SignIn)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignInParams{
		Username: "test-user",
		Password: "p@ssW0rd",
	})
	assert.Nil(err)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signin", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)

	//Assert
	assert.Nil(err)
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusNotFound)
	assert.Equal(res.Error.Message, auth.ErrNoUserFoundPleaseSignUp.Error())
}

func Test_User_SingIn_ErrUsernameOrPasswordIsIncorrect(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	_, err = repo.SignUp(ctx, db, repository.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
		NationalCode: "1234567890",
		Phone:        "09123456789",
	})
	assert.Nil(err)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signin", authHandler.SignIn)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignInParams{
		Username: "test-user",
		Password: "iccorrect-p@ssword",
	})
	assert.Nil(err)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signin", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)

	//Assert
	assert.Nil(err)
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusUnauthorized)
	assert.Equal(res.Error.Message, auth.ErrUsernameOrPasswordIsIncorrect.Error())
}

func Test_User_SingIn_Successful(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte("p@ssW0rd"),
		bcrypt.DefaultCost,
	)
	assert.Nil(err)
	createdUser, err := repo.SignUp(ctx, db, repository.SignUpParams{
		Username:     "test-user",
		Password:     string(hashedPassword),
		NationalCode: "1234567890",
		Phone:        "09123456789",
	})
	assert.Nil(err)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signin", authHandler.SignIn)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignInParams{
		Username: "test-user",
		Password: "p@ssW0rd",
	})
	assert.Nil(err)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signin", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res ResponseSuccess
	err = json.Unmarshal(response, &res)

	//Assert
	assert.Nil(err)
	assert.True(res.Success)
	assert.NotEqual(res.Data.AccessToken, "")
	assert.NotEqual(res.Data.RefreshToken, "")
	assert.Equal(res.Message, "user signed in successfully")

	refreshToken, err := redisClient.Get(ctx, fmt.Sprintf("userId:%d", createdUser.ID)).Result()
	assert.Nil(err)
	assert.NotEqual(refreshToken, "")

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
	assert.Equal(claims.Issuer, auth.TOKENISSUER)
	assert.Equal(claims.Subject, fmt.Sprintf("userId:%d", createdUser.ID))
}

func Test_RefreshToken_RefreshTokenIsNotInRedis(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/refresh-token", authHandler.RefreshToken)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.RefreshTokenParams{
		UserId:       "1",
		RefreshToken: "user-signed-refresh-token",
	})
	assert.Nil(err)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/refresh-token", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusUnauthorized)
	assert.Equal(res.Error.Message, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain.Error())
}

func Test_RefreshToken_RefreshTokenIsInRedisButIsMalformed(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/refresh-token", authHandler.RefreshToken)

	server := httptest.NewServer(r)
	defer server.Close()

	params := auth.RefreshTokenParams{
		UserId:       "1",
		RefreshToken: "user-signed-refresh-token",
	}
	paramsInJson, err := json.Marshal(params)
	assert.Nil(err)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/refresh-token", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	err = redisClient.Set(
		ctx,
		fmt.Sprintf("userId:%s", params.UserId),
		params.RefreshToken,
		7*24*time.Hour,
	).Err()
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusUnauthorized)
	assert.Equal(res.Error.Message, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain.Error())
}

func Test_RefreshToken_RefreshTokenIsInRedisAndIsInAValidShapeButExpired(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/refresh-token", authHandler.RefreshToken)

	params := auth.RefreshTokenParams{
		UserId: "1",
	}
	claims := jwtLib.RegisteredClaims{
		Issuer:    auth.TOKENISSUER,
		Subject:   fmt.Sprintf("userId:%s", params.UserId),
		IssuedAt:  &jwtLib.NumericDate{Time: time.Now()},
		ExpiresAt: &jwtLib.NumericDate{Time: time.Now().Add(2 * time.Second)},
	}
	refreshToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, claims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.SecretKey()))
	params.RefreshToken = signedRefreshToken
	assert.Nil(err)

	err = redisClient.Set(
		ctx,
		fmt.Sprintf("userId:%s", params.UserId),
		params.RefreshToken,
		7*24*time.Hour,
	).Err()
	assert.Nil(err)

	paramsInJson, err := json.Marshal(params)
	assert.Nil(err)
	server := httptest.NewServer(r)
	defer server.Close()

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/refresh-token", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	//We should wait 2 seconds to make sure that the refresh-token is expired
	time.Sleep(2 * time.Second)
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusUnauthorized)
	assert.Equal(res.Error.Message, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain.Error())
}

func Test_RefreshToken_Successful(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/refresh-token", authHandler.RefreshToken)

	params := auth.RefreshTokenParams{
		UserId: "1",
	}
	claims := jwtLib.RegisteredClaims{
		Issuer:    auth.TOKENISSUER,
		Subject:   fmt.Sprintf("userId:%s", params.UserId),
		IssuedAt:  &jwtLib.NumericDate{Time: time.Now()},
		ExpiresAt: &jwtLib.NumericDate{Time: time.Now().Add(2 * time.Hour)},
	}
	refreshToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, claims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.SecretKey()))
	params.RefreshToken = signedRefreshToken
	assert.Nil(err)

	err = redisClient.Set(
		ctx,
		fmt.Sprintf("userId:%s", params.UserId),
		params.RefreshToken,
		7*24*time.Hour,
	).Err()
	assert.Nil(err)

	paramsInJson, err := json.Marshal(params)
	assert.Nil(err)
	server := httptest.NewServer(r)
	defer server.Close()

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/refresh-token", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res ResponseSuccess
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.True(res.Success)
	assert.NotEqual(res.Data.AccessToken, "")
	assert.NotEqual(res.Data.RefreshToken, "")
}

func Test_User_LogOut_RefreshTokenIsNotInRedis(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/logout", authHandler.LogOut)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.LogOutParams{
		UserId:       "1",
		RefreshToken: "user-signed-refresh-token",
		AccessToken:  "user-signed-access-token",
	})
	assert.Nil(err)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/logout", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusUnauthorized)
	assert.Equal(res.Error.Message, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain.Error())
}

func Test_User_LogOut_RefreshTokenIsInRedisButIsMalformed(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/logout", authHandler.LogOut)

	server := httptest.NewServer(r)
	defer server.Close()

	params := auth.LogOutParams{
		UserId:       "1",
		RefreshToken: "user-signed-refresh-token",
		AccessToken:  "user-signed-access-token",
	}
	paramsInJson, err := json.Marshal(params)
	assert.Nil(err)
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/logout", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	err = redisClient.Set(
		ctx,
		fmt.Sprintf("userId:%s", params.UserId),
		params.RefreshToken,
		7*24*time.Hour,
	).Err()
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusUnauthorized)
	assert.Equal(res.Error.Message, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain.Error())
}

func Test_User_LogOut_RefreshTokenIsInRedisAndIsInAValidShapeButExpired(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/logout", authHandler.LogOut)

	params := auth.LogOutParams{
		UserId:      "1",
		AccessToken: "user-signed-access-token",
	}
	claims := jwtLib.RegisteredClaims{
		Issuer:    auth.TOKENISSUER,
		Subject:   fmt.Sprintf("userId:%s", params.UserId),
		IssuedAt:  &jwtLib.NumericDate{Time: time.Now()},
		ExpiresAt: &jwtLib.NumericDate{Time: time.Now().Add(2 * time.Second)},
	}
	refreshToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, claims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.SecretKey()))
	params.RefreshToken = signedRefreshToken
	assert.Nil(err)

	err = redisClient.Set(
		ctx,
		fmt.Sprintf("userId:%s", params.UserId),
		params.RefreshToken,
		7*24*time.Hour,
	).Err()
	assert.Nil(err)

	paramsInJson, err := json.Marshal(params)
	assert.Nil(err)
	server := httptest.NewServer(r)
	defer server.Close()

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/logout", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	//We should wait 2 seconds to make sure that the refresh-token is expired
	time.Sleep(2 * time.Second)
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res api.ResponseFailure
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.False(res.Success)
	assert.Equal(res.Error.Code, http.StatusUnauthorized)
	assert.Equal(res.Error.Message, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain.Error())
}

func Test_User_LogOut_Successful(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/logout", authHandler.LogOut)

	params := auth.LogOutParams{
		UserId:      "1",
		AccessToken: "user-signed-access-token",
	}
	jti := uuid.NewString()
	claims := jwtLib.RegisteredClaims{
		Issuer:    auth.TOKENISSUER,
		ID:        jti,
		Subject:   fmt.Sprintf("userId:%s", params.UserId),
		IssuedAt:  &jwtLib.NumericDate{Time: time.Now()},
		ExpiresAt: &jwtLib.NumericDate{Time: time.Now().Add(15 * time.Minute)},
	}
	accessToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, claims)
	signedAccessToken, err := accessToken.SignedString([]byte(config.SecretKey()))
	assert.Nil(err)

	claims = jwtLib.RegisteredClaims{
		Issuer:    auth.TOKENISSUER,
		Subject:   fmt.Sprintf("userId:%s", params.UserId),
		IssuedAt:  &jwtLib.NumericDate{Time: time.Now()},
		ExpiresAt: &jwtLib.NumericDate{Time: time.Now().Add(7 * 24 * time.Hour)},
	}
	refreshToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, claims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.SecretKey()))
	assert.Nil(err)

	params.RefreshToken = signedRefreshToken
	params.AccessToken = signedAccessToken

	err = redisClient.Set(
		ctx,
		fmt.Sprintf("userId:%s", params.UserId),
		params.RefreshToken,
		7*24*time.Hour,
	).Err()
	assert.Nil(err)

	paramsInJson, err := json.Marshal(params)
	assert.Nil(err)
	server := httptest.NewServer(r)
	defer server.Close()

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/logout", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)

	//Act
	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)

	defer resp.Body.Close()
	response, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	var res ResponseSuccess
	err = json.Unmarshal(response, &res)
	assert.Nil(err)

	//Assert
	assert.True(res.Success)
	assert.Equal(res.Message, "use logged out successfully")

	//check if refresh token is deleted from redis
	redisKey := fmt.Sprintf("userId:%s", params.UserId)
	err = redisClient.Get(ctx, redisKey).Err()
	assert.Equal(err, redis.Nil)

	blacklistKey := fmt.Sprintf("blacklist:%s", jti)
	blackListedAccessKey, err := redisClient.Get(ctx, blacklistKey).Bool()
	assert.Nil(err)
	assert.True(blackListedAccessKey)
}
