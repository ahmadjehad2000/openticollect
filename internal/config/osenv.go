package config

import "os"

func getenvOS(key string) string { return os.Getenv(key) }
