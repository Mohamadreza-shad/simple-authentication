package client

import (
	"context"

	"github.com/Mohamadreza-shad/simple-authentication/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

type PgxInterface interface {
	Begin(context.Context) (pgx.Tx, error)
	Exec(context.Context, string, ...interface{}) (pgconn.CommandTag, error)
	QueryRow(context.Context, string, ...interface{}) pgx.Row
	Query(context.Context, string, ...interface{}) (pgx.Rows, error)
	Close()
}

func NewDBClient() (PgxInterface, error) {
	postgresURL := config.GetPostgresURL()
	dbPool, err := pgxpool.New(context.Background(), postgresURL)
	if err != nil {
		return nil, err
	}
	if err := dbPool.Ping(context.Background()); err != nil {
		return nil, err
	}
	return dbPool, nil
}
