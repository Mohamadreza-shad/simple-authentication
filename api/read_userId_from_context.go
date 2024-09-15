package api

import (
	"strconv"

	"github.com/Mohamadreza-shad/simple-authentication/api/middleware"
	"github.com/gin-gonic/gin"
)

func readUserIDFromContext(c *gin.Context) (int64, bool) {
	userId, exist := c.Get(middleware.UserIdKey)
	if !exist {
		return 0, false
	}
	userIdInString, ok := userId.(string)
	if !ok {
		return 0, false
	}
	id, err := strconv.Atoi(userIdInString)
	if err != nil {
		return 0, false
	}
	return int64(id), true
}
