package controller_utils

import appcontext "secureops/backend-go/api/context"

func HandleError(ec *appcontext.EchoContext, status int, err error, message string) bool {
	if err == nil {
		return false
	}

	ec.Logger().Printf("request error status=%d error=%v message=%q", status, err, message)
	ec.String(status, message)
	return true
}
