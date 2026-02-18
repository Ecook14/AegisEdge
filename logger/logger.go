package logger

import (
	"log/slog"
	"os"
)

var Log *slog.Logger

func init() {
	Log = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
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
