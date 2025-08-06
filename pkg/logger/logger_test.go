package logger

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestLogLevels(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer

	// Create a logger with INFO level
	logger := New(INFO)
	logger.logger = log.New(&buf, "", 0) // Remove timestamp for testing

	// Test INFO level logging
	logger.logger.Print("info message")
	if !strings.Contains(buf.String(), "info message") {
		t.Errorf("Expected info message to be logged")
	}

	// Reset buffer
	buf.Reset()

	// Test DEBUG level should not show with INFO level
	if logger.level >= DEBUG {
		logger.logger.Print("[DEBUG] debug message")
	}
	if strings.Contains(buf.String(), "debug message") {
		t.Errorf("Debug message should not be logged at INFO level")
	}
}

func TestDebugLogging(t *testing.T) {
	// Capture log output
	var buf bytes.Buffer

	// Create a logger with DEBUG level
	logger := New(DEBUG)
	logger.logger = log.New(&buf, "", 0)

	// Test that debug messages appear at DEBUG level
	if logger.level >= DEBUG {
		logger.logger.Print("[DEBUG] debug message")
	}
	if !strings.Contains(buf.String(), "debug message") {
		t.Errorf("Debug message should be logged at DEBUG level")
	}
}

func TestGlobalLogger(t *testing.T) {
	// Save original logger
	originalLogger := defaultLogger
	defer func() {
		defaultLogger = originalLogger
	}()

	// Create test logger
	var buf bytes.Buffer
	defaultLogger = New(DEBUG)
	defaultLogger.logger = log.New(&buf, "", 0)

	// Test global functions
	Info("test info")
	if !strings.Contains(buf.String(), "test info") {
		t.Errorf("Global Info should work")
	}

	buf.Reset()
	Debug("test debug")
	if !strings.Contains(buf.String(), "[DEBUG] test debug") {
		t.Errorf("Global Debug should work")
	}

	buf.Reset()
	Infof("formatted %s", "info")
	if !strings.Contains(buf.String(), "formatted info") {
		t.Errorf("Global Infof should work")
	}

	buf.Reset()
	Debugf("formatted %s", "debug")
	if !strings.Contains(buf.String(), "[DEBUG] formatted debug") {
		t.Errorf("Global Debugf should work")
	}
}

func TestSetLevel(t *testing.T) {
	// Save original logger
	originalLogger := defaultLogger
	defer func() {
		defaultLogger = originalLogger
	}()

	// Test SetLevel
	SetLevel(DEBUG)
	if defaultLogger.level != DEBUG {
		t.Errorf("SetLevel should change the default logger level")
	}

	// Test SetDebug
	SetLevel(INFO)
	SetDebug()
	if defaultLogger.level != DEBUG {
		t.Errorf("SetDebug should set level to DEBUG")
	}
}

func TestIsDebugEnabled(t *testing.T) {
	// Save original logger
	originalLogger := defaultLogger
	defer func() {
		defaultLogger = originalLogger
	}()

	SetLevel(INFO)
	if IsDebugEnabled() {
		t.Errorf("IsDebugEnabled should return false for INFO level")
	}

	SetLevel(DEBUG)
	if !IsDebugEnabled() {
		t.Errorf("IsDebugEnabled should return true for DEBUG level")
	}
}
