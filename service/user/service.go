package user

import (
	"context"
	"errors"

	"github.com/Mohamadreza-shad/simple-authentication/client"
	"github.com/Mohamadreza-shad/simple-authentication/logger"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

var (
	ErrSomethingWentWrong = errors.New("something went wrong")
	ErrUserNotFound       = errors.New("user not found")
)

type Service struct {
	db          client.PgxInterface
	repo        *repository.Queries
	redisClient redis.UniversalClient
	logger      *logger.Logger
}

type UserByIdParams struct {
	Id int64 `json:"-"`
}

type User struct {
	Id           int64  `json:"id"`
	Name         string `json:"username"`
	NationalCode string `json:"nationalCode"`
	Phone        string `json:"phone"`
	IsActive     bool   `json:"isActive"`
	CreatedAt    int64  `json:"createdAt"`
	UpdatedAt    int64  `json:"updatedAt"`
}

func (s *Service) UserById(ctx context.Context, params UserByIdParams) (User, error) {
	fetchedUser, err := s.repo.UserByID(ctx, s.db, params.Id)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrSomethingWentWrong
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrUserNotFound
	}
	return User{
		Id:           fetchedUser.ID,
		Name:         fetchedUser.Username,
		NationalCode: fetchedUser.NationalCode,
		Phone:        fetchedUser.Phone,
		IsActive:     fetchedUser.IsActive,
		CreatedAt:    fetchedUser.CreatedAt.Time.Unix(),
		UpdatedAt:    fetchedUser.CreatedAt.Time.Unix(),
	}, nil
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
