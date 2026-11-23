package model

type Component struct {
	DeclaredVersion string `json:"declared_version,omitempty"`
	VersionSource   string `json:"version_source,omitempty"`
	CompName        string `json:"comp_name"`
	CompVersion     string `json:"comp_version"`
	EcoRepo
}

type EcoRepo struct {
	Ecosystem  string `json:"ecosystem"`
	Repository string `json:"repository"`
}
