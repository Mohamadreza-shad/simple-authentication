package router

import (
	"errors"
	"net/http"

	"github.com/Mohamadreza-shad/simple-authentication/api"
	"github.com/Mohamadreza-shad/simple-authentication/logger"
	"github.com/Mohamadreza-shad/simple-authentication/service/user"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type Router struct {
	Handler *gin.Engine
}

func New(
	userHandler *api.UserHandler,
	userService *user.Service,
	logger *logger.Logger,
) *Router {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(cors.Default())
	r.Use(globalRecover(logger))
	r.NoRoute(func(c *gin.Context) {
		c.JSON(
			http.StatusNotFound,
			api.ResponseFailure{
				Success: false,
				Error: api.ErrorCode{
					Code:    http.StatusNotFound,
					Message: "URL not found",
				},
			})
	})

	r.POST("api/user/signup", userHandler.SignUp)
	r.POST("api/user/signin", userHandler.SignIn)
	r.POST("api/user/refresh-token", userHandler.RefreshToken)
	return &Router{
		Handler: r,
	}
}

func globalRecover(logger *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func(c *gin.Context) {
			if rec := recover(); rec != nil {
				err := errors.New("error 500")
				if err != nil {
					logger.Error("error 500", zap.Error(err))
				}
				api.MakeErrorResponseWithCode(c.Writer, http.StatusInternalServerError, "error 500")
			}
		}(c)
		c.Next()
	}
}
