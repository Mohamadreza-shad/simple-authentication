// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.25.0

package repository

import (
	"github.com/jackc/pgx/v5/pgtype"
)

type User struct {
	ID           int64
	Username     string
	Password     string
	NationalCode string
	Phone        string
	Email        pgtype.Text
	IsActive     bool
	CreatedAt    pgtype.Timestamp
	UpdatedAt    pgtype.Timestamp
}
