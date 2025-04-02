package task

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

type ArtifactSbom struct {
	ImageURL          string      `json:"image_url"`
	ArtifactID        string      `json:"artifact_id"`
	Packages          []Package   `json:"packages"`
	SbomSpdxJson      interface{} `json:"sbom_spdx_json"`
	SbomCyclonedxJson interface{} `json:"sbom_cyclonedx_json"`
}

type ArtifactPackageList struct {
	ImageURL   string    `json:"image_url"`
	ArtifactID string    `json:"artifact_id"`
	Packages   []Package `json:"packages"`
}

func (r ArtifactSbom) UniqueID() string {
	return r.ArtifactID
}

func (r ArtifactPackageList) UniqueID() string {
	return r.ArtifactID
}
