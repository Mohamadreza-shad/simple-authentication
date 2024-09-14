package api

import (
	"encoding/json"
	"net/http"

	"google.golang.org/grpc/status"
)

var (
	ContentTypeMessage     = "Content-Type"
	ApplicationJsonMessage = "application/json"
)

type ResponseSuccess struct {
	Success bool        `json:"success" example:"true"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

type ResponseFailure struct {
	Success bool      `json:"success" example:"false"`
	Error   ErrorCode `json:"error,omitempty" `
}

type ErrorCode struct {
	Code    int    `json:"code" example:"404"`
	Message string `json:"message" example:"item not find"`
}

func MakeSuccessResponse(w http.ResponseWriter, data interface{}, message string) {
	responseJson := ResponseSuccess{
		Success: true,
		Message: message,
		Data:    data,
	}
	jData, err := json.Marshal(&responseJson)
	if err != nil {
		MakeErrorResponseWithoutCode(w, err)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Header().Set(ContentTypeMessage, ApplicationJsonMessage)
	w.Write(jData)
}

func MakeErrorResponseWithoutCode(w http.ResponseWriter, err error) {
	code := 500
	message := "something went wrong"
	e, ok := status.FromError(err)
	if ok {
		if int(e.Code()) > 200 {
			code = int(e.Code())
		}
		message = e.Message()
	}

	responseJson := ResponseFailure{
		Success: false,
		Error: ErrorCode{
			Code:    int(code),
			Message: message,
		},
	}
	jData, _ := json.Marshal(&responseJson)
	w.WriteHeader(code)
	w.Header().Set(ContentTypeMessage, ApplicationJsonMessage)
	w.Write(jData)
}

func MakeErrorResponseWithCode(w http.ResponseWriter, code int, message string) {
	responseJson := ResponseFailure{
		Success: false,
		Error: ErrorCode{
			Code:    code,
			Message: message,
		},
	}
	jData, _ := json.Marshal(&responseJson)
	w.WriteHeader(code)
	w.Header().Set(ContentTypeMessage, ApplicationJsonMessage)
	w.Write(jData)
}
