package utils

import (
	"strconv"
	"time"
)

func GetSecondTimeStamp() string {
	ts := time.Now().Unix()
	return strconv.Itoa(int(ts))
}

func GetMilliSecondTimeStamp() string {
	ts := time.Now().UnixNano() / 1e6
	return strconv.Itoa(int(ts))
}

func GetNanoSecondTimeStamp() string {
	ts := time.Now().UnixNano()
	return strconv.Itoa(int(ts))
}

func GetyyyyMMddHHmmssTimeStamp() string {
	now := time.Now()
	return now.Format("20060102150405")
}
