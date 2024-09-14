package router

import (
	"net/http"

	"github.com/Mohamadreza-shad/simple-authentication/api"
	"github.com/Mohamadreza-shad/simple-authentication/service/user"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

type Router struct {
	Handler *gin.Engine
}

func New(
	userHandler *api.UserHandler,
	userService *user.Service,
) *Router {
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(cors.Default())
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
	return &Router{
		Handler: r,
	}
}
