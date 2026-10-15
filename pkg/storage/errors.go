package storage

import (
	"errors"
)

var (
	ErrNotFound      = errors.New("not found")
	ErrTokenNotOwned = errors.New("token was not issued for this client")
)

func IgnoreNotFoundError(err error) error {
	if err == nil || err == ErrNotFound {
		return nil
	}
	return err
}
