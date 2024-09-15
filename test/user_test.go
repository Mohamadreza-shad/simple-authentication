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
	"github.com/Mohamadreza-shad/simple-authentication/api/middleware"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	"github.com/Mohamadreza-shad/simple-authentication/service/auth"
	"github.com/Mohamadreza-shad/simple-authentication/service/user"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
)

type UserbyIdResponseSuccess struct {
	Success bool      `json:"success" example:"true"`
	Message string    `json:"message,omitempty"`
	Data    user.User `json:"data,omitempty"`
}

type UpdateUserResponseSuccess struct {
	Success bool   `json:"success" example:"true"`
	Message string `json:"message,omitempty"`
}

func Test_GetUserById_UserNotFound(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.GET("/user", userHandler.UserById)

	req, err = http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/api/v1/user", server.URL),
		nil,
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	//delete user from db. we want to test "user not found" scenario
	err = truncateDB()
	assert.Nil(err)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := api.ResponseFailure{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.False(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Error.Code, http.StatusNotFound)
	assert.Equal(userByIdResponse.Error.Message, user.ErrUserNotFound.Error())
}

func Test_GetUserById_Successful(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.GET("/user", userHandler.UserById)

	req, err = http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/api/v1/user", server.URL),
		nil,
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := UserbyIdResponseSuccess{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.True(userByIdResponse.Data.IsActive)
	assert.Equal(userByIdResponse.Data.Name, "test-user")
}

func Test_UpdateUserProfile_InvalidInput(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.PUT("/user/update-profile", userHandler.UpdateUserProfile)

	params := user.UpdateUserProfileParams{
		NationalCode: "444445555", // invalid national code
		Phone:        "09914445555",
		Email:        "test-user@test.com",
	}
	paramsInJson, err = json.Marshal(params)
	assert.Nil(err)

	req, err = http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/api/v1/user/update-profile", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := api.ResponseFailure{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.False(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Error.Code, http.StatusBadRequest)
	assert.Equal(userByIdResponse.Error.Message, user.ErrInvalidNationalCode.Error())

	params = user.UpdateUserProfileParams{
		NationalCode: "4444455555", 
		Phone:        "099144455552", // invalid phone
		Email:        "test-user@test.com",
	}
	paramsInJson, err = json.Marshal(params)
	assert.Nil(err)

	req2, err := http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/api/v1/user/update-profile", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req2.Header.Set("Authorization", accessTokenFromServer)

	// Act
	resp, err = http.DefaultClient.Do(req2)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse = api.ResponseFailure{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.False(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Error.Code, http.StatusBadRequest)
	assert.Equal(userByIdResponse.Error.Message, user.ErrInvalidPhone.Error())
}

func Test_UpdateUserProfile_UserNotFound(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.PUT("/user/update-profile", userHandler.UpdateUserProfile)

	params := user.UpdateUserProfileParams{
		NationalCode: "4444455555",
		Phone:        "09914445555",
		Email:        "test-user@test.com",
	}
	paramsInJson, err = json.Marshal(params)
	assert.Nil(err)

	req, err = http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/api/v1/user/update-profile", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	//delete user from db. we want to test "user not found" scenario
	err = truncateDB()
	assert.Nil(err)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := api.ResponseFailure{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.False(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Error.Code, http.StatusNotFound)
	assert.Equal(userByIdResponse.Error.Message, user.ErrUserNotFound.Error())
}

func Test_UpdateUserProfile_Successful(t *testing.T) {
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.PUT("/user/update-profile", userHandler.UpdateUserProfile)

	params := user.UpdateUserProfileParams{
		NationalCode: "4444455555",
		Phone:        "09914445555",
		Email:        "test-user@test.com",
	}
	paramsInJson, err = json.Marshal(params)
	assert.Nil(err)

	req, err = http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/api/v1/user/update-profile", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := UpdateUserResponseSuccess{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.True(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Message, "user profile updated successfully")

	//fetch user from db
	fetchedUser, err := repo.UserByName(ctx, db, "test-user")
	assert.Nil(err)
	assert.Equal(fetchedUser.Email.String, params.Email)
	assert.Equal(fetchedUser.NationalCode.String, params.NationalCode)
	assert.Equal(fetchedUser.Phone.String, params.Phone)
}

func Test_UpdateUsername_InvalidInput(t *testing.T){
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.PUT("/user/update-username", userHandler.UpdateUsername)

	params := user.UpdateUsernameParams{
		Username: "",
	}
	paramsInJson, err = json.Marshal(params)
	assert.Nil(err)

	req, err = http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/api/v1/user/update-username", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := api.ResponseFailure{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.False(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Error.Code, http.StatusBadRequest)
	assert.Equal(userByIdResponse.Error.Message, user.ErrUsernameCannotBeEmpty.Error())
}

func Test_UpdateUsername_UsernameIsAlreadyTaken(t *testing.T){
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.PUT("/user/update-username", userHandler.UpdateUsername)

	params := user.UpdateUsernameParams{
		Username: "test-user",
	}
	paramsInJson, err = json.Marshal(params)
	assert.Nil(err)

	req, err = http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/api/v1/user/update-username", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := api.ResponseFailure{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.False(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Error.Code, http.StatusForbidden)
	assert.Equal(userByIdResponse.Error.Message, user.ErrUsernameIsAlreadyTaken.Error())
}

func Test_UpdateUsername_Successful(t *testing.T){
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
	authService := auth.New(db, repo, redisClient, logger)
	userHandler := api.NewUserHandler(userService, validator)
	authHandler := api.NewAuthHandler(authService, validator)

	gin.SetMode(gin.TestMode)
	r := gin.Default()
	r.POST("api/user/signup", authHandler.SignUp)

	server := httptest.NewServer(r)
	defer server.Close()

	paramsInJson, err := json.Marshal(auth.SignUpParams{
		Username:     "test-user",
		Password:     "p@ssW0rd",
	})
	assert.Nil(err)

	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/user/signup", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err := io.ReadAll(resp.Body)
	assert.Nil(err)
	signUpResponse := ResponseSuccess{}
	err = json.Unmarshal(respInByte, &signUpResponse)
	assert.Nil(err)

	accessTokenFromServer := signUpResponse.Data.AccessToken

	v1 := r.Group("/api/v1")
	v1.Use(middleware.AuthMiddleware(authService))
	v1.PUT("/user/update-username", userHandler.UpdateUsername)

	params := user.UpdateUsernameParams{
		Username: "new-test-user",
	}
	paramsInJson, err = json.Marshal(params)
	assert.Nil(err)

	req, err = http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("%s/api/v1/user/update-username", server.URL),
		bytes.NewBuffer(paramsInJson),
	)
	assert.Nil(err)
	req.Header.Set("Authorization", accessTokenFromServer)

	// Act
	resp, err = http.DefaultClient.Do(req)
	assert.Nil(err)
	defer resp.Body.Close()

	respInByte, err = io.ReadAll(resp.Body)
	assert.Nil(err)
	userByIdResponse := UpdateUserResponseSuccess{}
	err = json.Unmarshal(respInByte, &userByIdResponse)
	assert.Nil(err)

	//Assert
	assert.True(userByIdResponse.Success)
	assert.Equal(userByIdResponse.Message, "username has been updated successfully")

	_,err = repo.UserByName(ctx,db,params.Username)
	assert.Nil(err)
}
