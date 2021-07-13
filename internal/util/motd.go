package util

import (
	"io/ioutil"
	"os"
)

func Motd() string {
	filepaths := [3]string{
		"/etc/motd",
		"/var/run/motd.dynamic.new",
		"/var/run/motd.dynamic",
	}
	for _, filepath := range filepaths {
		if _, err := os.Stat(filepath); err != nil {
			continue
		}
		data, err := ioutil.ReadFile(filepath)
		if err != nil {
			continue
		}
		return string(data)
	}
	return ""
}
