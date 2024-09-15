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
	"github.com/google/uuid"
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
	ErrSomethingWentWrong                     = errors.New("something went wrong")
	ErrUsernameAlreadyTaken                   = errors.New("username already taken")
	ErrNoUserFoundPleaseSignUp                = errors.New("no user found please sign up")
	ErrInvalidOrExpiredToken                  = errors.New("invalid or expired token")
	ErrInvalidOrExpiredTokenPleaseSignInAgain = errors.New("invalid or expired token. Please login again")
	ErrUsernameOrPasswordIsIncorrect          = errors.New("username or password is incorrect")
	ErrAccessTokenIsBlacklisted               = errors.New("access token is blacklisted")
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

type RefreshTokenParams struct {
	UserId       string `json:"userId" validate:"required"`
	RefreshToken string `json:"refreshToken" validate:"required"`
}

type LogOutParams struct {
	UserId       string `json:"userId" validate:"required"`
	AccessToken  string `json:"accessToken" validate:"required"`
	RefreshToken string `json:"refreshToken" validate:"required"`
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

func (s *Service) SignIn(ctx context.Context, params SignInParams) (SignUpResponse, error) {
	fetchedUser, err := s.repo.UserByName(ctx, s.db, params.Username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return SignUpResponse{}, ErrNoUserFoundPleaseSignUp
	}
	err = bcrypt.CompareHashAndPassword([]byte(fetchedUser.Password), []byte(params.Password))
	if err != nil {
		return SignUpResponse{}, ErrUsernameOrPasswordIsIncorrect
	}
	userIdString := strconv.Itoa(int(fetchedUser.ID))
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

func (s *Service) RefreshToken(ctx context.Context, params RefreshTokenParams) (SignUpResponse, error) {
	redisKey := fmt.Sprintf("userId:%s", params.UserId)
	_, err := s.redisClient.Get(ctx, redisKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	if errors.Is(err, redis.Nil) {
		return SignUpResponse{}, ErrInvalidOrExpiredTokenPleaseSignInAgain
	}
	err = IsRefreshTokenValid(ctx, params.RefreshToken)
	if err != nil {
		return SignUpResponse{}, ErrInvalidOrExpiredTokenPleaseSignInAgain
	}
	accessToken, err := generateAccessToken(params.UserId)
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	refreshToken, err := generateRefreshToken(params.UserId)
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	err = s.redisClient.Set(ctx, redisKey, refreshToken, REFRESHTOKENEXPIREDIN*24*time.Hour).Err()
	if err != nil {
		return SignUpResponse{}, ErrSomethingWentWrong
	}
	return SignUpResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

func (s *Service) LogOut(ctx context.Context, params LogOutParams) error {
	redisKey := fmt.Sprintf("userId:%s", params.UserId)
	_, err := s.redisClient.Get(ctx, redisKey).Result()
	if err != nil && !errors.Is(err, redis.Nil) {
		return ErrSomethingWentWrong
	}
	if errors.Is(err, redis.Nil) {
		return ErrInvalidOrExpiredTokenPleaseSignInAgain
	}
	err = IsRefreshTokenValid(ctx, params.RefreshToken)
	if err != nil {
		return ErrInvalidOrExpiredTokenPleaseSignInAgain
	}
	err = s.redisClient.Del(ctx, redisKey).Err()
	if err != nil {
		return ErrSomethingWentWrong
	}
	claims, err := TokenClaims(ctx, params.AccessToken)
	if err != nil {
		return ErrInvalidOrExpiredTokenPleaseSignInAgain
	}
	err = s.BlacklistToken(claims.ID)
	if err != nil {
		return ErrSomethingWentWrong
	}
	return nil
}

func (s *Service) BlacklistToken(jti string) error {
	key := fmt.Sprintf("blacklist:%s", jti)
	err := s.redisClient.Set(
		context.Background(),
		key,
		true,
		ACCESSTOKENEXPIREDIN*time.Minute,
	).Err()
	return err
}

func IsRefreshTokenValid(ctx context.Context, signedToken string) error {
	keyFunc := func(token *jwtLib.Token) (interface{}, error) {
		_, ok := token.Method.(*jwtLib.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.SecretKey()), nil
	}
	token, err := jwtLib.ParseWithClaims(
		signedToken,
		&jwtLib.RegisteredClaims{},
		keyFunc,
	)
	if err != nil {
		return err
	}
	claims, ok := token.Claims.(*jwtLib.RegisteredClaims)
	if !ok && !token.Valid {
		return ErrInvalidOrExpiredToken
	}
	if claims.Issuer != TOKENISSUER {
		return ErrInvalidOrExpiredToken
	}
	return nil
}

func (s *Service) IsAccessTokenValid(ctx context.Context, signedToken string) (*jwtLib.Token, error) {
	keyFunc := func(token *jwtLib.Token) (interface{}, error) {
		_, ok := token.Method.(*jwtLib.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.SecretKey()), nil
	}
	token, err := jwtLib.ParseWithClaims(
		signedToken,
		&jwtLib.RegisteredClaims{},
		keyFunc,
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*jwtLib.RegisteredClaims)
	if !ok && !token.Valid {
		return nil, ErrInvalidOrExpiredToken
	}
	key := fmt.Sprintf("blacklist:%s", claims.ID)
	isBlacklisted, err := s.redisClient.Exists(ctx, key).Result()
	if err != nil {
		return nil, err
	}
	if isBlacklisted > 0 {
		return nil, ErrAccessTokenIsBlacklisted
	}
	if claims.Issuer != TOKENISSUER {
		return nil, ErrInvalidOrExpiredToken
	}
	return token, nil
}

func TokenClaims(ctx context.Context, signedToken string) (*jwtLib.RegisteredClaims, error) {
	keyFunc := func(token *jwtLib.Token) (interface{}, error) {
		_, ok := token.Method.(*jwtLib.SigningMethodHMAC)
		if !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return []byte(config.SecretKey()), nil
	}
	token, err := jwtLib.ParseWithClaims(
		signedToken,
		&jwtLib.RegisteredClaims{},
		keyFunc,
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*jwtLib.RegisteredClaims)
	if !ok {
		return nil, err
	}
	return claims, nil
}

func generateAccessToken(userId string) (string, error) {
	claims := jwtLib.RegisteredClaims{
		Issuer:    TOKENISSUER,
		Subject:   fmt.Sprintf("userId:%s", userId),
		ID:        uuid.NewString(),
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
		Subject:   fmt.Sprintf("userId:%s", userId),
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
