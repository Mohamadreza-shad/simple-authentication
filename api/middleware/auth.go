package middleware

import (
	"net/http"
	"strings"

	"github.com/Mohamadreza-shad/simple-authentication/service/auth"
	"github.com/gin-gonic/gin"
	jwtLib "github.com/golang-jwt/jwt/v5"
)

const (
	Authorization = "Authorization"
	Bearing       = "Bearing"
	SubjectPrefix = "userId:"
	UserIdKey     = "UserId"
)

func AuthMiddleware(s *auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		signedAccessToken := ExtractTokenFromRequest(c.Request)
		if strings.EqualFold(signedAccessToken, "") {
			c.AbortWithStatusJSON(
				http.StatusBadRequest,
				gin.H{
					"success": false,
					"error": gin.H{
						"code":    http.StatusUnauthorized,
						"message": "token is empty",
					},
				},
			)
			return
		}
		token, err := s.IsAccessTokenValid(c.Request.Context(), signedAccessToken)
		if err != nil {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{
					"success": false,
					"error": gin.H{
						"code":    http.StatusUnauthorized,
						"message": "invalid or expired token",
					},
				},
			)
			return
		}
		if token == nil {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{
					"success": false,
					"error": gin.H{
						"code":    http.StatusUnauthorized,
						"message": "invalid token",
					},
				})
			return
		}
		if !token.Valid {
			c.AbortWithStatusJSON(
				http.StatusUnauthorized,
				gin.H{
					"success": false,
					"error": gin.H{
						"code":    http.StatusUnauthorized,
						"message": "invalid or expired token",
					},
				})
			return
		}
		userId := fetchUserIdFromToken(token)
		c.Set(UserIdKey, userId)
		c.Next()
	}
}

func ExtractTokenFromRequest(r *http.Request) (token string) {
	token = r.Header.Get(Authorization)
	token = strings.Trim(token, `"`)
	if strings.Contains(token, Bearing) {
		token = strings.TrimPrefix(token, Bearing+" ")
	}
	return
}

func fetchUserIdFromToken(token *jwtLib.Token) string {
	claims, ok := token.Claims.(*jwtLib.RegisteredClaims)
	if !ok {
		return ""
	}
	userId := strings.TrimPrefix(claims.Subject, SubjectPrefix)
	return userId
}
