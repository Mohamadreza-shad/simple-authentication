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

// This endpoint fetch user profile
// @Summary		 fetch user profile
// @Description	 fetch user profile
// @Tags		 Auth
// @ID			 User-Profile
// @Accept		 json
// @Produce		 json
// @Security	 ApiKeyAuth
// @Success		 200	{object}	ResponseSuccess{data=user.User}
// @Failure		 404	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		/api/v1/user [get]
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

// This endpoint update user profile
// @Summary		 update user profile
// @Description	 update user profile
// @Tags		 Auth
// @ID			 User-Update-Profile
// @Accept		 json
// @Produce		 json
// @Security	 ApiKeyAuth
// @Param		 params body user.UpdateUserProfileParams false "Update-User-Profile-Params"
// @Success		 200	{object}	ResponseSuccess
// @Failure		 403	{object}	ResponseFailure
// @Failure		 400	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		/api/v1/user/update-profile [put]
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

// This endpoint update username
// @Summary		 update username
// @Description	 update username
// @Tags		 Auth
// @ID			 User-Update-Username
// @Accept		 json
// @Produce		 json
// @Security	 ApiKeyAuth
// @Param		 params body user.UpdateUsernameParams false "Update-Username-Params"
// @Success		 200	{object}	ResponseSuccess
// @Failure		 403	{object}	ResponseFailure
// @Failure		 400	{object}	ResponseFailure
// @Failure		 500	{object}	ResponseFailure
// @Router		 /api/v1/user/update-username [put]
func (h *UserHandler) UpdateUsername(c *gin.Context) {
	userId, isExist := readUserIDFromContext(c)
	if !isExist {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			"Invalid or expired token")
		return
	}
	params := user.UpdateUsernameParams{}
	err := c.BindJSON(&params)
	if err != nil {
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusUnauthorized,
			"Invalid request")
		return
	}
	params.UserId = userId
	err = h.userService.UpdateUsername(c.Request.Context(), params)
	if err != nil && errors.Is(err,user.ErrUsernameCannotBeEmpty){
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusBadRequest,
			user.ErrUsernameCannotBeEmpty.Error())
		return
	}
	if err != nil && errors.Is(err,user.ErrUsernameIsAlreadyTaken){
		MakeErrorResponseWithCode(
			c.Writer,
			http.StatusForbidden,
			user.ErrUsernameIsAlreadyTaken.Error())
		return
	}
	if err != nil {
		MakeErrorResponseWithoutCode(c.Writer, err)
		return
	}
	MakeSuccessResponse(c.Writer, nil, "username has been updated successfully")
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
