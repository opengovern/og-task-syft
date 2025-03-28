package task

type ArtifactSbom struct {
	ImageURL   string      `json:"imageUrl"`
	ArtifactID string      `json:"artifactId"`
	SbomFormat string      `json:"sbomFormat"`
	Sbom       interface{} `json:"sbom"`
}

func (r ArtifactSbom) UniqueID() string {
	return r.ArtifactID
}

type GrypeOutput struct {
	Matches []VulnerabilityMatch `json:"matches"`
}

type VulnerabilityMatch struct {
	Vulnerability          Vulnerability   `json:"vulnerability"`
	RelatedVulnerabilities []Vulnerability `json:"relatedVulnerabilities"`
	MatchDetail            interface{}     `json:"matchDetail"`
	Artifact               interface{}     `json:"artifact"`
}

type Vulnerability struct {
	ID          string             `json:"id"`
	DataSource  string             `json:"dataSource"`
	Namespace   string             `json:"namespace"`
	Severity    string             `json:"severity"`
	URLs        []string           `json:"urls"`
	Description string             `json:"description"`
	CVSs        []VulnerabilityCVS `json:"cvss"`
	Fix         VulnerabilityFix   `json:"fix"`
	Advisories  interface{}        `json:"advisories"`
}

type VulnerabilityCVS struct {
	Source         string            `json:"source"`
	Type           string            `json:"type"`
	Version        string            `json:"version"`
	Vector         string            `json:"vector"`
	Metrics        map[string]string `json:"metrics"`
	VendorMetadata map[string]string `json:"vendorMetadata"`
}

type VulnerabilityFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}
