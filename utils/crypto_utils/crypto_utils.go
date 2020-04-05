package crypto_utils

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"github.com/chiuwah/fd_users-api/utils/errors"
	"golang.org/x/crypto/bcrypt"
	"net/http"
)

func GetMd5(input string) string {
	hash := md5.New()
	defer hash.Reset()
	hash.Write([]byte(input))
	return hex.EncodeToString(hash.Sum(nil))
}

func HashPassword(input string) (string, *errors.RestErr) {
	password := []byte(input)
	hashedPassword, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	if err != nil {
		return "", &errors.RestErr{
			Message: fmt.Sprintf("error encrypting password %s", err.Error()),
			Status:  http.StatusInternalServerError,
			Error:   "internal_server_error",
		}
	}
	// Use bcrypt.CompareHashAndPassword(hashedPassword, password) to compare the password with hash
	return string(hashedPassword), nil
}
