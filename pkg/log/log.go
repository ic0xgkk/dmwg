package log

import (
	gobgplog "github.com/osrg/gobgp/v3/pkg/log"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang/glog"
)

type BgpServerLogger struct{}

func (BgpServerLogger) Panic(msg string, fields gobgplog.Fields) {
	glog.FatalDepthf(1, "Panic: %s /// %s", msg, spew.Sdump(fields))
}

func (BgpServerLogger) Fatal(msg string, fields gobgplog.Fields) {
	glog.ExitDepthf(1, "Fatal: %s /// %s", msg, spew.Sdump(fields))
}

func (BgpServerLogger) Error(msg string, fields gobgplog.Fields) {
	glog.ErrorDepthf(1, "Error: %s /// %s", msg, spew.Sdump(fields))
}

func (BgpServerLogger) Warn(msg string, fields gobgplog.Fields) {
	glog.WarningDepthf(1, "Warn: %s /// %s", msg, spew.Sdump(fields))
}

func (BgpServerLogger) Info(msg string, fields gobgplog.Fields) {
	glog.InfoDepthf(1, "Info: %s /// %s", msg, spew.Sdump(fields))
}

func (BgpServerLogger) Debug(msg string, fields gobgplog.Fields) {
	if glog.V(1) {
		glog.V(1).InfoDepthf(1, "Debug: %s /// %s", msg, spew.Sdump(fields))
	}
}

func (BgpServerLogger) SetLevel(level gobgplog.LogLevel) {}

func (BgpServerLogger) GetLevel() gobgplog.LogLevel {
	return gobgplog.LogLevel(0)
}
