package logger

import (
	"log"
	"os"
)

// LogLevel represents different logging levels
type LogLevel int

const (
	INFO LogLevel = iota
	DEBUG
)

// Logger wraps the standard logger with level support
type Logger struct {
	level  LogLevel
	logger *log.Logger
}

// Global logger instance
var defaultLogger *Logger

func init() {
	defaultLogger = New(INFO)
}

// New creates a new logger with the specified level
func New(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		logger: log.New(os.Stdout, "", log.LstdFlags),
	}
}

// SetLevel sets the logging level for the default logger
func SetLevel(level LogLevel) {
	defaultLogger.level = level
}

// SetDebug enables debug logging for the default logger
func SetDebug() {
	SetLevel(DEBUG)
}

// Info logs an info message
func Info(v ...interface{}) {
	defaultLogger.logger.Print(v...)
}

// Infof logs a formatted info message
func Infof(format string, v ...interface{}) {
	defaultLogger.logger.Printf(format, v...)
}

// Debug logs a debug message (only when debug level is enabled)
func Debug(v ...interface{}) {
	if defaultLogger.level >= DEBUG {
		args := append([]interface{}{"[DEBUG] "}, v...)
		defaultLogger.logger.Print(args...)
	}
}

// Debugf logs a formatted debug message (only when debug level is enabled)
func Debugf(format string, v ...interface{}) {
	if defaultLogger.level >= DEBUG {
		defaultLogger.logger.Printf("[DEBUG] "+format, v...)
	}
}

// Fatal logs a fatal message and exits
func Fatal(v ...interface{}) {
	defaultLogger.logger.Fatal(v...)
}

// Fatalf logs a formatted fatal message and exits
func Fatalf(format string, v ...interface{}) {
	defaultLogger.logger.Fatalf(format, v...)
}

// IsDebugEnabled returns true if debug logging is enabled
func IsDebugEnabled() bool {
	return defaultLogger.level >= DEBUG
}
