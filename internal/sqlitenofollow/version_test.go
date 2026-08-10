package sqlite

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestUpstreamModulePin(t *testing.T) {
	_, testFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate pin assertion source file")
	}
	goMod, err := os.ReadFile(filepath.Join(filepath.Dir(testFile), "..", "..", "go.mod"))
	if err != nil {
		t.Fatalf("read module pin: %v", err)
	}
	want := UpstreamModulePath + " " + UpstreamModuleVersion
	if !strings.Contains(string(goMod), want) {
		t.Fatalf("go.mod does not pin %s", want)
	}
}
