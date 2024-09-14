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

func (h *UserHandler) SignUp(c *gin.Context) {
	params := user.SignUpParams{}
	err := c.BindJSON(&params)
	if err != nil {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusBadRequest,
			"Bad Request: "+err.Error(),
		)
		return
	}
	err = h.validator.Struct(params)
	if err != nil {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusBadRequest,
			"invalid request"+err.Error())
		return
	}
	res, err := h.userService.SignUp(c.Request.Context(), params)
	if err != nil && errors.Is(err, user.ErrUsernameAlreadyTaken) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusConflict,
			err.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
	}
	MakeSuccessResponse(c.Writer, res, "user created successfully")
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
