package syft

import (
	"context"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin/transform"

	"github.com/opengovern/og-task-syft/cloudql/syft/client"
	"github.com/turbot/steampipe-plugin-sdk/v5/grpc/proto"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func tablePlatformArtifactSboms(_ context.Context) *plugin.Table {
	return &plugin.Table{
		Name:        "platform_artifact_sbom",
		Description: "Platform Artifact SBOMs",
		Cache: &plugin.TableCacheOptions{
			Enabled: false,
		},
		List: &plugin.ListConfig{
			Hydrate: client.ListArtifactSboms,
		},
		Columns: []*plugin.Column{
			{
				Name:      "image_url",
				Transform: transform.FromField("Description.ImageURL"),
				Type:      proto.ColumnType_STRING,
			},
			{
				Name:      "artifact_id",
				Transform: transform.FromField("Description.ArtifactID"),
				Type:      proto.ColumnType_STRING,
			},
			{
				Name:      "packages",
				Transform: transform.FromField("Description.Packages"),
				Type:      proto.ColumnType_JSON,
			},
			{
				Name:      "sbom_spdx_json",
				Transform: transform.FromField("Description.SbomSpdxJson"),
				Type:      proto.ColumnType_JSON,
			},
			{
				Name:      "sbom_cyclonedx_json",
				Transform: transform.FromField("Description.SbomCyclonedxJson"),
				Type:      proto.ColumnType_JSON,
			},
			{
				Name:        "platform_description",
				Type:        proto.ColumnType_JSON,
				Description: "The full model description of the resource",
				Transform:   transform.FromField("Description").Transform(marshalJSON),
			},
		},
	}
}
