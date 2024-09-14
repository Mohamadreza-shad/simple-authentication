package test

import (
	"context"
	"os"
	"testing"

	"github.com/Mohamadreza-shad/simple-authentication/client"
	"github.com/Mohamadreza-shad/simple-authentication/config"
	"github.com/Mohamadreza-shad/simple-authentication/logger"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

var mainDb *pgxpool.Pool
var redisClient redis.UniversalClient
var loggerService *logger.Logger

func getLogger() *logger.Logger {
	if loggerService != nil {
		return loggerService
	}
	var err error
	loggerService, err = logger.New()
	if err != nil {
		panic(err)
	}
	return loggerService
}

func getDB() *pgxpool.Pool {
	if mainDb != nil {
		return mainDb
	}
	postgresURL := config.GetPostgresURL()
	dbPool, err := pgxpool.New(context.Background(), postgresURL)
	if err != nil {
		panic("can not establish connection to database")
	}
	mainDb = dbPool
	return mainDb
}

func TestMain(m *testing.M) {
	err := config.Load()
	if err != nil {
		panic(err)
	}
	exitCode := m.Run()
	os.Exit(exitCode)
}

func getRedis() redis.UniversalClient {
	if redisClient != nil {
		return redisClient
	}
	redisClient, _ = client.NewRedisClient()
	return redisClient
}

func truncateDB() error {
	ctx := context.Background()
	db := getDB()
	_, err := db.Exec(ctx, "TRUNCATE TABLE users CASCADE")
	if err != nil {
		return err
	}
	_, err = db.Exec(ctx, "ALTER SEQUENCE users_id_seq RESTART WITH 1")
	if err != nil {
		return err
	}
	return nil
}
