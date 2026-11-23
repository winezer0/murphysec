package resolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePipListJSON(t *testing.T) {
	data := `[{"name":"certifi","version":"2022.9.24"},{"name":"requests","version":"2.27.1"}]`
	packages, err := parsePipListJSON([]byte(data))
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"certifi": "2022.9.24", "requests": "2.27.1"}, packages)
}

func TestParsePipListDefaultFormat(t *testing.T) {
	data := "DEPRECATION: ignored\ncertifi (2022.9.24)\nrequests (2.27.1)\n"
	packages, err := parsePipListDefault([]byte(data))
	assert.NoError(t, err)
	assert.Equal(t, map[string]string{"certifi": "2022.9.24", "requests": "2.27.1"}, packages)
}
