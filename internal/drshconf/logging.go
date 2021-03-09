package drshconf

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

func NewLogger(hostType string, cfg *Config) *zap.Logger {
	filename := cfg.Client.LogFile
	if hostType == "server" {
		filename = cfg.Server.LogFile
	}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()),
		zapcore.AddSync(&lumberjack.Logger{
			Filename:   filename,
			MaxSize:    500,
			MaxBackups: 3,
			MaxAge:     28,
			Compress:   true,
		}),
		zap.InfoLevel,
	)
	logger := zap.New(core)
	return logger
}
