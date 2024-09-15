package user

import (
	"context"
	"errors"
	"strings"

	"github.com/Mohamadreza-shad/simple-authentication/client"
	"github.com/Mohamadreza-shad/simple-authentication/logger"
	"github.com/Mohamadreza-shad/simple-authentication/repository"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/redis/go-redis/v9"
)

var (
	ErrSomethingWentWrong     = errors.New("something went wrong")
	ErrUserNotFound           = errors.New("user not found")
	ErrInvalidNationalCode    = errors.New("invalid national code")
	ErrInvalidPhone           = errors.New("invalid Phone")
	ErrUsernameIsAlreadyTaken = errors.New("username is already taken")
	ErrUsernameCannotBeEmpty  = errors.New("username cannot be empty")
	ErrWrongPassword          = errors.New("wrong password")
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

type UpdateUserProfileParams struct {
	UserId       int64  `json:"-"`
	NationalCode string `json:"nationalCode"`
	Phone        string `json:"phone"`
	Email        string `json:"email"`
}

type UpdateUsernameParams struct {
	UserId   int64  `json:"-"`
	Username string `json:"username" validate:"required"`
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
		NationalCode: fetchedUser.NationalCode.String,
		Phone:        fetchedUser.Phone.String,
		IsActive:     fetchedUser.IsActive,
		CreatedAt:    fetchedUser.CreatedAt.Time.Unix(),
		UpdatedAt:    fetchedUser.CreatedAt.Time.Unix(),
	}, nil
}

func (s *Service) UpdateUserProfile(ctx context.Context, params UpdateUserProfileParams) error {
	if !strings.EqualFold(params.NationalCode, "") && len(params.NationalCode) != int(10) {
		return ErrInvalidNationalCode
	}
	if !strings.EqualFold(params.Phone, "") && len(params.Phone) != int(11) {
		return ErrInvalidPhone
	}
	_, err := s.repo.UserByID(ctx, s.db, params.UserId)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ErrSomethingWentWrong
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrUserNotFound
	}
	err = s.repo.UpdateUserProfile(ctx, s.db, repository.UpdateUserProfileParams{
		ID:           params.UserId,
		NationalCode: pgtype.Text{String: params.NationalCode, Valid: true},
		Phone:        pgtype.Text{String: params.Phone, Valid: true},
		Email:        pgtype.Text{String: params.Email, Valid: true},
	})
	if err != nil {
		return ErrSomethingWentWrong
	}
	return nil
}

func (s *Service) UpdateUsername(ctx context.Context, params UpdateUsernameParams) error {
	if strings.EqualFold(params.Username, "") {
		return ErrUsernameCannotBeEmpty
	}
	_, err := s.repo.UserByName(ctx, s.db, params.Username)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ErrSomethingWentWrong
	}
	if err == nil {
		return ErrUsernameIsAlreadyTaken
	}
	err = s.repo.UpdateUsername(
		ctx,
		s.db,
		repository.UpdateUsernameParams{
			ID:       params.UserId,
			Username: params.Username,
		})
	if err != nil {
		return ErrSomethingWentWrong
	}
	return nil
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
