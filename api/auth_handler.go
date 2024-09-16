package api

import (
	"errors"
	"net/http"

	"github.com/Mohamadreza-shad/simple-authentication/api/middleware"
	"github.com/Mohamadreza-shad/simple-authentication/service/auth"
	"github.com/Mohamadreza-shad/simple-authentication/service/user"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
)

type AuthHandler struct {
	authService *auth.Service
	validator   *validator.Validate
}

// This endpoint should sign up user
// @Summary		 should sign up user
// @Description	 should sign up user
// @Tags		 Auth
// @ID			 User-SignUp
// @Accept		 json
// @Produce		 json
// @Param		 params body auth.SignUpParams false "SignUp-Params"
// @Success		 200	{object}	ResponseSuccess{data=auth.SignUpResponse}
// @Failure		 409	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		 /api/user/signup [post]
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

// This endpoint should sign in user
// @Summary		 should sign in user
// @Description	 should sign in user
// @Tags		 Auth
// @ID			 User-SignIn
// @Accept		 json
// @Produce		 json
// @Param		 params body auth.SignInParams false "SignIn-Params"
// @Success		 200	{object}	ResponseSuccess{data=auth.SignUpResponse}
// @Failure		 404	{object}	ResponseFailure
// @Failure		 401	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		 /api/user/signin [post]
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

// This endpoint should refresh access token
// @Summary		 should refresh access token
// @Description	 should refresh access token
// @Tags		 Auth
// @ID			 User-Refresh-Token
// @Accept		 json
// @Produce		 json
// @Param		 params body auth.RefreshTokenParams false "RefreshToken-Params"
// @Success		 200	{object}	ResponseSuccess{data=auth.SignUpResponse}
// @Failure		 401	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		 /api/user/refresh-token [post]
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

// This endpoint should log out user
// @Summary		 should log out user
// @Description	 should log out user
// @Tags		 Auth
// @ID			 User-LogOut
// @Accept		 json
// @Produce		 json
// @Param		 params body auth.LogOutParams false "LogOut-Params"
// @Success		 200	{object}	ResponseSuccess
// @Failure		 401	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		 /api/user/logout [post]
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

// This endpoint should update user password
// @Summary		 should update user password
// @Description	 should update user password
// @Tags		 Auth
// @ID			 User-Update-Password
// @Accept		 json
// @Produce		 json
// @Security	 ApiKeyAuth
// @Param		 params body auth.UpdatePasswordParams false "Update-Password-Params"
// @Success		 200	{object}	ResponseSuccess
// @Failure		 401	{object}	ResponseFailure
// @Failure		 403	{object}	ResponseFailure
// @Failure		 404	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		 /api/user/update-password [put]
func (h *AuthHandler) UpdatePassword(c *gin.Context) {
	userId, isExist := readUserIDFromContext(c)
	if !isExist {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			"Invalid or expired token")
		return
	}
	accessToken := middleware.ExtractTokenFromRequest(c.Request)
	params := auth.UpdatePasswordParams{}
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
	params.UserId = userId
	params.AccessToken = accessToken
	err = h.authService.UpdatePassword(c.Request.Context(), params)
	if err != nil && errors.Is(err, user.ErrUserNotFound) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusNotFound,
			err.Error())
		return
	}
	if err != nil && errors.Is(err, user.ErrWrongPassword) {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusForbidden,
			err.Error())
		return
	}
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
	MakeSuccessResponse(c.Writer, nil, "password updated successfully")
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
