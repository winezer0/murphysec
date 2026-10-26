package model

import (
	"encoding/json"
	"testing"
)

func TestScanStrategyMarshalText(t *testing.T) {
	cases := []struct {
		strategy ScanStrategy
		want     string
	}{
		{ScanStrategyBackup, "backup"},
		{ScanStrategyNormal, "normal"},
		// The zero value must stay "normal": it is what an unset field has
		// always meant on the wire.
		{"", "normal"},
	}
	for _, c := range cases {
		b, err := json.Marshal(struct {
			Strategy ScanStrategy `json:"scan_strategy"`
		}{c.strategy})
		if err != nil {
			t.Fatalf("marshal %q: %v", c.strategy, err)
		}
		want := `{"scan_strategy":"` + c.want + `"}`
		if string(b) != want {
			t.Errorf("marshal %q = %s, want %s", c.strategy, b, want)
		}
	}
}
