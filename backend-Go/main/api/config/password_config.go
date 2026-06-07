package config

import "golang.org/x/crypto/bcrypt"

func PasswordCost() int {
	return bcrypt.DefaultCost
}

