package bundler

import (
	"strings"
	"testing"
)

// TestGemfileRetainsAllRangeTerms prevents an upper boundary being discarded.
func TestGemfileRetainsAllRangeTerms(t *testing.T) {
	var file gemfile
	file.Parse(strings.NewReader("gem 'example', '>= 1.0', '< 2.0'\n"))
	if len(file.Gems) != 1 || file.Gems[0].Version != ">= 1.0, < 2.0" {
		t.Fatalf("gems=%#v", file.Gems)
	}
}
