package models

import (
	"github.com/google/certificate-transparency/go"
)

type CTLogEntryType int

const (
	CT_QUIT CTLogEntryType = iota
	CT_CERT
	CT_PRECERT
)

type MonEvent struct {
	Type     CTLogEntryType
	LogEntry *ct.LogEntry
}
