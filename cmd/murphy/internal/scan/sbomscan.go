package scan

import (
	"github.com/murphysecurity/murphysec/cmd/murphy/internal/common"
	"github.com/spf13/cobra"
)

// SbomScan is the dedicated "generate an SBOM" command.
//
// It is a thin alias for `dfscan --sbom-format spdx-json`. The work is done by
// the same code path, so the two spellings cannot drift apart. Delegating also
// means sbom inherits what it used to lack: the output filters and the
// document annotations that record a degraded scan or packages no consumer can
// identify.
func SbomScan() *cobra.Command {
	var out string
	cmd := &cobra.Command{
		Use:   "sbom <DIR>",
		Short: "Scan project dependencies and write an SPDX-JSON SBOM (alias for dfscan --sbom-format spdx-json)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if out == "" {
				out = "spdx.json"
			}
			sbomOutputConfig = out
			sbomOutputType = common.SBOMFormatFlag{Valid: true, Format: common.SBOMFormatSPDX}
			dfScanRun(cmd, args)
		},
	}
	cmd.Flags().StringVar(&out, "out", "", "output file path, use \"-\" to output to stdout (default spdx.json)")
	cmd.Flags().BoolVar(&noBuild, "no-build", false, "skip project building")
	cmd.Flags().BoolVar(&excludeDevDeps, "exclude-dev", false, "omit dev/test/provided dependencies from the SBOM")
	cmd.Flags().BoolVar(&directOnlyDeps, "direct-only", false, "omit transitive dependencies from the SBOM")
	return cmd
}
