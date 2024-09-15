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

func (h *UserHandler) SignIn(c *gin.Context) {
	params := user.SignInParams{}
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
	res, err := h.userService.SignIn(c.Request.Context(), params)
	if err != nil && errors.Is(err, user.ErrNoUserFoundPleaseSignUp) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusNotFound,
			err.Error())
		return
	}
	if err != nil && errors.Is(err, user.ErrUsernameOrPasswordIsIncorrect) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			err.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
	}
	MakeSuccessResponse(c.Writer, res, "user signed in successfully")
}

func (h *UserHandler) RefreshToken(c *gin.Context) {
	params := user.RefreshTokenParams{}
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
	res, err := h.userService.RefreshToken(c.Request.Context(), params)
	if err != nil && errors.Is(err, user.ErrInvalidOrExpiredTokenPleaseSignInAgain) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			err.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
	}
	MakeSuccessResponse(c.Writer, res, "Access toke generated successfully")
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
