package utils

import "time"

func GetEndOfToday() string {
	timeDate := time.Now().Format("2006-01-02")
	now, _ := time.ParseInLocation("2006-01-02 15:04:05", timeDate+" 23:59:59", time.Local)
	return now.Format("2006-01-02 15:04:05")
}

func GetStartOfTomorrow() string {
	timeDate := time.Now().Format("2006-01-02")
	now, _ := time.ParseInLocation("2006-01-02 15:04:05", timeDate+" 00:00:00", time.Local)
	return now.AddDate(0, 0, 1).Format("2006-01-02 15:04:05")
}
