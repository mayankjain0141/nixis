package reload_test

import (
	"errors"
	"testing"

	"go.uber.org/goleak"
)

var errReloadFailed = errors.New("reload failed")

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}
