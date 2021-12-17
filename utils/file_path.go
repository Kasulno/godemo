package utils

import (
	"errors"
	"os"
	"path/filepath"
)

func FormatPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("path不是绝对路径")
	}

	dir, _ := filepath.Split(path)
	if dir == "" {
		return "", errors.New("非法路径")
	}

	pathRunes := []rune(path)
	if pathRunes[len(pathRunes)-1] != os.PathSeparator {
		path = string(pathRunes) + string(os.PathSeparator)
	}
	return path, nil
}
