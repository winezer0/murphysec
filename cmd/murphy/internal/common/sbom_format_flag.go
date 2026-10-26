package common

import (
	"fmt"

	"github.com/spf13/pflag"
)

// Supported SBOM output formats.
//
// msdx1.1+json is murphysec's own format. It carries the full dependency
// tree, the scan strategy and the degradation warnings, but it has no purl,
// so no third-party tool can match it against a vulnerability database.
//
// spdx-json is SPDX 2.3. Each package carries a purl in externalRefs, which
// is what osv-scanner consumes when scanning an SBOM offline:
//
//	osv-scanner --offline --lockfile out.spdx.json
const (
	SBOMFormatMSDX = "msdx1.1+json"
	SBOMFormatSPDX = "spdx-json"
)

type SBOMFormatFlag struct {
	// Valid reports that the user asked for SBOM-only output. It also puts
	// the scan into offline mode (no API calls, no terminal UI).
	Valid bool
	// Format is the requested format; empty means SBOMFormatMSDX.
	Format string
}

func (t *SBOMFormatFlag) String() string {
	if !t.Valid {
		return "invalid"
	}
	if t.Format == "" {
		return SBOMFormatMSDX
	}
	return t.Format
}

func (t *SBOMFormatFlag) Set(s string) error {
	switch s {
	case "", SBOMFormatMSDX:
		t.Format = SBOMFormatMSDX
	case SBOMFormatSPDX, "spdx":
		// "spdx" is accepted as a shorthand; the document written out is
		// always the JSON serialisation.
		t.Format = SBOMFormatSPDX
	default:
		return fmt.Errorf("unsupported format: %s (supported: %s, %s)", s, SBOMFormatMSDX, SBOMFormatSPDX)
	}
	t.Valid = true
	return nil
}

func (t *SBOMFormatFlag) Type() string {
	return "sbomFormatFlag"
}

// IsSPDX reports whether the SPDX writer should be used.
func (t *SBOMFormatFlag) IsSPDX() bool {
	return t.Format == SBOMFormatSPDX
}

var _ pflag.Value = (*SBOMFormatFlag)(nil)
