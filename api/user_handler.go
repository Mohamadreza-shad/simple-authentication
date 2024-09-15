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
			"Invalid or expired token")
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

func (h *UserHandler) UpdateUserProfile(c *gin.Context) {
	userId, isExist := readUserIDFromContext(c)
	if !isExist {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			"Invalid or expired token")
		return
	}
	params := user.UpdateUserProfileParams{}
	err := c.BindJSON(&params)
	if err != nil {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			"Invalid request")
		return
	}
	params.UserId = userId
	err = h.userService.UpdateUserProfile(c.Request.Context(), params)
	if err != nil && errors.Is(err, user.ErrInvalidNationalCode) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusBadRequest,
			user.ErrInvalidNationalCode.Error())
		return
	}
	if err != nil && errors.Is(err, user.ErrInvalidPhone) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusBadRequest,
			user.ErrInvalidPhone.Error())
		return
	}
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
	MakeSuccessResponse(c.Writer, nil, "user profile updated successfully")
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
