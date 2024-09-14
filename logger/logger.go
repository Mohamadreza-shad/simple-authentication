package logger

import (
	"os"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Logger struct {
	*zap.Logger
}

func New() (*Logger, error) {
	defaultLogLevel := zapcore.DebugLevel
	encoderCfg := zapcore.EncoderConfig{
		MessageKey:    "msg",
		LevelKey:      "level",
		EncodeLevel:   zapcore.LowercaseLevelEncoder,
		TimeKey:       "ts",
		EncodeTime:    zapcore.RFC3339TimeEncoder,
		CallerKey:     "caller",
		EncodeCaller:  zapcore.ShortCallerEncoder,
		StacktraceKey: "trace",
	}
	core := zapcore.NewCore(
		zapcore.NewJSONEncoder(encoderCfg),
		zapcore.AddSync(os.Stdout),
		defaultLogLevel,
	)
	logger := zap.New(
		core,
		zap.AddStacktrace(defaultLogLevel),
	)
	return &Logger{logger}, nil
}
