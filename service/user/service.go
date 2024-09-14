package user

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/Mohamadreza-shad/simple-authentication/client"
	"github.com/Mohamadreza-shad/simple-authentication/config"
	"github.com/Mohamadreza-shad/simple-authentication/logger"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	jwtLib "github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
)

const (
	TOKENISSUER           = "simple-auth-service"
	ACCESSTOKENEXPIREDIN  = 15
	REFRESHTOKENEXPIREDIN = 7
)

var (
	ErrSomethingWentWrong   = errors.New("something went wrong")
	ErrUsernameAlreadyTaken = errors.New("username already taken")
)

type Service struct {
	db          client.PgxInterface
	repo        *repository.Queries
	redisClient redis.UniversalClient
	logger      *logger.Logger
}

type SignUpParams struct {
	Username     string `json:"username" validate:"required"`
	Password     string `json:"password" validate:"required"`
	NationalCode string `json:"nationalCode" validate:"required,len=10"`
	Phone        string `json:"phone" validate:"required,len=11"`
}

type SignUpResponse struct {
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

type SignInParams struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

func (s *Service) SignUp(ctx context.Context, params SignUpParams) (SignUpResponse, error) {
	_, err := s.repo.UserByName(ctx, s.db, params.Username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	if err == nil {
		return SignUpResponse{}, ErrUsernameAlreadyTaken
	}
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(params.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	createdUser, err := s.repo.SignUp(
		ctx,
		s.db,
		repository.SignUpParams{
			Username:     params.Username,
			Password:     string(hashedPassword),
			NationalCode: params.NationalCode,
			Phone:        params.Phone,
		})
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	userIdString := strconv.Itoa(int(createdUser.ID))
	accessToken, err := generateAccessToken(userIdString)
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	refreshToken, err := generateRefreshToken(userIdString)
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}

	key := "userId:" + userIdString
	err = s.redisClient.Set(ctx, key, refreshToken, REFRESHTOKENEXPIREDIN*24*time.Hour).Err()
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	return SignUpResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) SignIn(ctx context.Context, username, password string) (SignUpResponse, error) {
	//find user by username
	//check if credentials are correct
	//generate access token
	//generate refresh token
	//save refresh token in redis
	//return access token and refresh token
	return SignUpResponse{}, nil
}

func generateAccessToken(userId string) (string, error) {
	claims := jwtLib.RegisteredClaims{
		Issuer:    TOKENISSUER,
		Subject:   fmt.Sprintf("userId:%s",userId),
		IssuedAt:  &jwtLib.NumericDate{Time: time.Now()},
		ExpiresAt: &jwtLib.NumericDate{Time: time.Now().Add(ACCESSTOKENEXPIREDIN * time.Minute)},
	}
	accessToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, claims)
	signedAccessToken, err := accessToken.SignedString([]byte(config.SecretKey()))
	if err != nil {
		return "", err
	}
	return signedAccessToken, nil
}

func generateRefreshToken(userId string) (string, error) {
	claims := jwtLib.RegisteredClaims{
		Issuer:    TOKENISSUER,
		Subject:   fmt.Sprintf("userId:%s",userId),
		IssuedAt:  &jwtLib.NumericDate{Time: time.Now()},
		ExpiresAt: &jwtLib.NumericDate{Time: time.Now().Add(REFRESHTOKENEXPIREDIN * 24 * time.Hour)},
	}
	refreshToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, claims)
	signedRefreshToken, err := refreshToken.SignedString([]byte(config.SecretKey()))
	if err != nil {
		return "", ErrSomethingWentWrong
	}
	return signedRefreshToken, nil
}

func New(
	db client.PgxInterface,
	repo *repository.Queries,
	redisClient redis.UniversalClient,
	logger *logger.Logger,
) *Service {
	return &Service{
		db:          db,
		repo:        repo,
		redisClient: redisClient,
		logger:      logger,
	}
}
