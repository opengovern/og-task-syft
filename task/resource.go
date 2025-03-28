package task

type ArtifactSbom struct {
	ImageURL   string      `json:"image_url"`
	ArtifactID string      `json:"artifact_id"`
	SbomFormat string      `json:"sbom_format"`
	Sbom       interface{} `json:"sbom"`
}

func (r ArtifactSbom) UniqueID() string {
	return r.ArtifactID
}
