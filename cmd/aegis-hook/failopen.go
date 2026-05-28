package main

import (
	"encoding/json"
	"os"
)

// writeFailOpen appends a FailOpenEntry as a JSON line to logPath.
// Errors are silenced so a log failure never blocks the fail-open allow path (A5).
func writeFailOpen(logPath string, entry FailOpenEntry) error {
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}
