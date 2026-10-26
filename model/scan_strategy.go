package model

type ScanStrategy string

const (
	ScanStrategyBackup ScanStrategy = "backup"
	ScanStrategyNormal ScanStrategy = "normal"
)

// MarshalText writes the strategy that actually ran.
//
// It used to return ScanStrategyNormal unconditionally, ignoring the
// receiver, so a degraded run serialised as "normal" and no consumer could
// tell whether the dependency graph came from the fallback resolver. The
// zero value still marshals as "normal" to keep older documents readable.
func (s ScanStrategy) MarshalText() ([]byte, error) {
	if s == "" {
		return []byte(ScanStrategyNormal), nil
	}
	return []byte(s), nil
}
