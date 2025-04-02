package task

type ArtifactSbom struct {
	ImageURL          string      `json:"image_url"`
	ArtifactID        string      `json:"artifact_id"`
	Packages          []string    `json:"packages"`
	SbomSpdxJson      interface{} `json:"sbom_spdx_json"`
	SbomCyclonedxJson interface{} `json:"sbom_cyclonedx_json"`
}

func (r ArtifactSbom) UniqueID() string {
	return r.ArtifactID
}
