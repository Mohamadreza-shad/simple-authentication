package api

import (
	"errors"
	"net/http"

	"github.com/Mohamadreza-shad/simple-authentication/service/auth"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type AuthHandler struct {
	authService *auth.Service
	validator   *validator.Validate
}

func (h *AuthHandler) SignUp(c *gin.Context) {
	params := auth.SignUpParams{}
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
	res, err := h.authService.SignUp(c.Request.Context(), params)
	if err != nil && errors.Is(err, auth.ErrUsernameAlreadyTaken) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusConflict,
			err.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
		return
	}
	MakeSuccessResponse(c.Writer, res, "user created successfully")
}

func (h *AuthHandler) SignIn(c *gin.Context) {
	params := auth.SignInParams{}
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
	res, err := h.authService.SignIn(c.Request.Context(), params)
	if err != nil && errors.Is(err, auth.ErrNoUserFoundPleaseSignUp) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusNotFound,
			err.Error())
		return
	}
	if err != nil && errors.Is(err, auth.ErrUsernameOrPasswordIsIncorrect) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			err.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
		return
	}
	MakeSuccessResponse(c.Writer, res, "user signed in successfully")
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	params := auth.RefreshTokenParams{}
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
	res, err := h.authService.RefreshToken(c.Request.Context(), params)
	if err != nil && errors.Is(err, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			err.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
		return
	}
	MakeSuccessResponse(c.Writer, res, "Access toke generated successfully")
}

func (h *AuthHandler) LogOut(c *gin.Context) {
	params := auth.LogOutParams{}
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
	err = h.authService.LogOut(c.Request.Context(), params)
	if err != nil && errors.Is(err, auth.ErrInvalidOrExpiredTokenPleaseSignInAgain) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			err.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
		return
	}
	MakeSuccessResponse(c.Writer, nil, "use logged out successfully")
}

func NewAuthHandler(
	authService *auth.Service,
	validator *validator.Validate,
) *AuthHandler {
	return &AuthHandler{
		authService: authService,
		validator:   validator,
	}
}
