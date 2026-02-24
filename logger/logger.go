package logger

import (
	"log/slog"
	"os"
	"strings"
)

var (
	Log *slog.Logger
	levelVar = new(slog.LevelVar)
)

func init() {
	levelVar.Set(slog.LevelInfo) // Default
	Log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: levelVar,
	}))
}

func SetLevel(level string) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		levelVar.Set(slog.LevelDebug)
	case "INFO":
		levelVar.Set(slog.LevelInfo)
	case "WARN":
		levelVar.Set(slog.LevelWarn)
	case "ERROR":
		levelVar.Set(slog.LevelError)
	}
}

func Debug(msg string, args ...any) {
	Log.Debug(msg, args...)
}

func Info(msg string, args ...any) {
	Log.Info(msg, args...)
}

func Error(msg string, args ...any) {
	Log.Error(msg, args...)
}

func Warn(msg string, args ...any) {
	Log.Warn(msg, args...)
}
