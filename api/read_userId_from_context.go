package api

import (
	"github.com/Mohamadreza-shad/simple-authentication/api/middleware"
	"github.com/gin-gonic/gin"
)

func readUserIDFromContext(c *gin.Context) (int64, bool) {
	userId, exist := c.Get(middleware.UserIdKey)
	if !exist {
		return 0, false
	}
	userIdInString, ok := userId.(int64)
	if !ok {
		return 0, false
	}
	return userIdInString, true
}
