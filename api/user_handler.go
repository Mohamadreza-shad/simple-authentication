package api

import (
	"errors"
	"net/http"

	"github.com/Mohamadreza-shad/simple-authentication/service/user"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type UserHandler struct {
	userService *user.Service
	validator   *validator.Validate
}

func (h *UserHandler) UserById(c *gin.Context) {
	userId, isExist := readUserIDFromContext(c)
	if !isExist {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			"Invalid user profile")
		return
	}
	fetchedUser, err := h.userService.UserById(
		c.Request.Context(),
		user.UserByIdParams{Id: userId})
	if err != nil && errors.Is(err, user.ErrUserNotFound) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusNotFound,
			"user not found")
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
		return
	}
	MakeSuccessResponse(c.Writer, fetchedUser, "user fetched successfully")
}

func NewUserHandler(
	userService *user.Service,
	validator *validator.Validate,
) *UserHandler {
	return &UserHandler{
		userService: userService,
		validator:   validator,
	}
}
