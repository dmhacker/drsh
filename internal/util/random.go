package util

import (
	"encoding/base64"
	"github.com/google/uuid"
)

func RandomName() (string, error) {
	name, err := uuid.NewRandom()
    if err != nil {
        return "", err
    }
	return base64.RawURLEncoding.EncodeToString(name[:]), nil
}
