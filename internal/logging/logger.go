// Package logging provides a minimal, leveled logging utility for the
// application. It uses the standard log package and avoids external
// dependencies to keep the binary small and statically linked.
package logging

import (
    "fmt"
    "log"
    "os"
    "strings"
)

// LogLevel defines the severity of a log message.
type LogLevel int

const (
    LevelDebug LogLevel = iota
    LevelInfo
    LevelWarn
    LevelError
)

// Logger is a leveled logger implementation.
type Logger struct {
    stdLogger *log.Logger
    level     LogLevel
}

// New creates a new Logger at the specified level string (debug, info, warn, error).
func New(level string) *Logger {
    var lvl LogLevel
    switch strings.ToLower(level) {
    case "debug":
        lvl = LevelDebug
    case "warn", "warning":
        lvl = LevelWarn
    case "error":
        lvl = LevelError
    case "info":
        fallthrough
    default:
        lvl = LevelInfo
    }

    return &Logger{
        stdLogger: log.New(os.Stdout, "", log.Ldate|log.Ltime|log.Lmicroseconds),
        level:     lvl,
    }
}

func (l *Logger) logf(lvl LogLevel, prefix, format string, args ...interface{}) {
    if lvl < l.level {
        return
    }
    msg := fmt.Sprintf(format, args...)
    l.stdLogger.Printf("%s %s", prefix, msg)
}

// Debugf logs a debug message.
func (l *Logger) Debugf(format string, args ...interface{}) {
    l.logf(LevelDebug, "[DEBUG]", format, args...)
}

// Infof logs an info message.
func (l *Logger) Infof(format string, args ...interface{}) {
    l.logf(LevelInfo, "[INFO] ", format, args...)
}

// Warnf logs a warning message.
func (l *Logger) Warnf(format string, args ...interface{}) {
    l.logf(LevelWarn, "[WARN] ", format, args...)
}

// Errorf logs an error message.
func (l *Logger) Errorf(format string, args ...interface{}) {
    l.logf(LevelError, "[ERROR]", format, args...)
}

// Fatalf logs an error message and exits the program with status 1.
func (l *Logger) Fatalf(format string, args ...interface{}) {
    l.logf(LevelError, "[FATAL]", format, args...)
    os.Exit(1)
}
