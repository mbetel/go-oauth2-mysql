package mq

// Logger is the Mysql store logger interface
type Logger interface {
	Printf(format string, v ...interface{})
}
