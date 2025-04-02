package task

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/CycloneDX/cyclonedx-go"
	"github.com/opengovern/og-task-syft/envs"
	authApi "github.com/opengovern/og-util/pkg/api"
	"github.com/opengovern/og-util/pkg/es"
	"github.com/opengovern/og-util/pkg/httpclient"
	"github.com/opengovern/og-util/pkg/jq"
	"github.com/opengovern/og-util/pkg/opengovernance-es-sdk"
	"github.com/opengovern/og-util/pkg/tasks"
	coreApi "github.com/opengovern/opensecurity/services/core/api"
	coreClient "github.com/opengovern/opensecurity/services/core/client"
	"github.com/opengovern/opensecurity/services/tasks/scheduler"
	purl "github.com/package-url/packageurl-go"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

type Artifact struct {
	OciArtifactUrl string `json:"oci_artifact_url"`
	ArtifactID     string `json:"artifact_id"`
}

type ArtifactResult struct {
	OciArtifactUrl string `json:"oci_artifact_url"`
	ArtifactID     string `json:"artifact_id"`
	Result         string `json:"result"`
	FailureReason  string `json:"failure_message"`
}

type TaskResult struct {
	ArtifactsDoneNumber      int64            `json:"artifacts_done_number"`
	ArtifactsSucceededNumber int64            `json:"artifacts_succeeded_number"`
	Artifacts                []ArtifactResult `json:"artifacts"`
}

func RunTask(ctx context.Context, jq *jq.JobQueue, coreServiceEndpoint string, esClient opengovernance.Client, logger *zap.Logger, request tasks.TaskRequest, response *scheduler.TaskResponse) error {
	var artifacts []Artifact
	var artifactsUrls []string
	var err error
	if _, ok := request.TaskDefinition.Params["query_id"]; ok {
		inventoryClient := coreClient.NewCoreServiceClient(coreServiceEndpoint)
		artifacts, err = GetArtifactsFromQueryID(inventoryClient, request.TaskDefinition.Params)
		if err != nil {
			err = fmt.Errorf("failed getting artifacts from query by id: %s", err.Error())
			return err
		}
	} else if _, ok := request.TaskDefinition.Params["query_to_execute"]; ok {
		inventoryClient := coreClient.NewCoreServiceClient(coreServiceEndpoint)
		artifacts, err = GetArtifactsFromInlineQuery(inventoryClient, request.TaskDefinition.Params)
		if err != nil {
			err = fmt.Errorf("failed getting artifacts from inline query: %s", err.Error())
			return err
		}
	} else if v, ok := request.TaskDefinition.Params["artifacts"]; !ok {
		return fmt.Errorf("OCI artifact url parameter is not provided")
	} else {
		artifactsInterface, ok := v.([]interface{})
		if !ok {
			return fmt.Errorf("artifacts type is not []interface{}")
		}
		for _, artifact := range artifactsInterface {
			artifactMap, ok := artifact.(map[string]interface{})
			if !ok {
				panic(fmt.Errorf("artifact is not a map[string]interface{}"))
			}

			var a Artifact
			artifactBytes, _ := json.Marshal(artifactMap)
			err := json.Unmarshal(artifactBytes, &a)
			if err != nil {
				panic(fmt.Errorf("failed to unmarshal artifact: %w", err))
			}

			artifacts = append(artifacts, a)
		}
	}

	for _, ar := range artifacts {
		artifactsUrls = append(artifactsUrls, ar.OciArtifactUrl)
	}
	logger.Info("running task on artifacts", zap.Strings("artifacts", artifactsUrls))

	taskResult := &TaskResult{}

	for _, artifact := range artifacts {
		ScanArtifact(esClient, logger, artifact, request, taskResult)
		jsonBytes, err := json.Marshal(taskResult)
		if err != nil {
			return err
		}
		response.Result = jsonBytes

		responseJson, err := json.Marshal(response)
		if err != nil {
			logger.Error("failed Marshaling task result", zap.Error(err))
			err = fmt.Errorf("failed Marshaling task result: %s", err.Error())
			return err
		}
		if _, err := jq.Produce(ctx, envs.ResultTopicName, responseJson, fmt.Sprintf("task-run-update-%s-%d", artifact.ArtifactID, request.TaskDefinition.RunID)); err != nil {
			logger.Error("failed to publish job result", zap.String("jobResult", string(responseJson)), zap.Error(err))
		}
	}
	jsonBytes, err := json.Marshal(taskResult)
	if err != nil {
		err = fmt.Errorf("failed Marshaling task result: %s", err.Error())
		return err
	}
	response.Result = jsonBytes

	return nil
}

func ScanArtifact(esClient opengovernance.Client, logger *zap.Logger, artifact Artifact, request tasks.TaskRequest, taskResult *TaskResult) {
	logger.Info("Fetching image", zap.String("image", artifact.OciArtifactUrl))

	var err error
	var index, id string

	defer func() {
		if err == nil {
			taskResult.Artifacts = append(taskResult.Artifacts, ArtifactResult{
				OciArtifactUrl: artifact.OciArtifactUrl,
				ArtifactID:     artifact.ArtifactID,
				Result:         fmt.Sprintf("Responses stored in elasticsearch index %s by id: %v", index, id),
			})
			taskResult.ArtifactsDoneNumber += 1
			taskResult.ArtifactsSucceededNumber += 1
		} else {
			taskResult.Artifacts = append(taskResult.Artifacts, ArtifactResult{
				OciArtifactUrl: artifact.OciArtifactUrl,
				ArtifactID:     artifact.ArtifactID,
				FailureReason:  err.Error(),
			})
			taskResult.ArtifactsDoneNumber += 1
		}
	}()

	// Run the SYFT with spdx json
	spdxCmd := exec.Command("syft", artifact.OciArtifactUrl, "--scope", "all-layers", "-o", "spdx-json")
	spdxOutput, err := spdxCmd.CombinedOutput()
	logger.Info("spdxOutput", zap.String("spdxOutput", string(spdxOutput)))
	if err != nil {
		logger.Error("failed while scanning image", zap.Error(err))
		err = fmt.Errorf("failed while scanning image: %s", err.Error())
		return
	}
	var spdxSbom interface{}
	err = json.Unmarshal(spdxOutput, &spdxSbom)

	// Run the SYFT with spdx json
	cyclonedxCmd := exec.Command("syft", artifact.OciArtifactUrl, "--scope", "all-layers", "-o", "cyclonedx-json")
	cyclonedxOutput, err := cyclonedxCmd.CombinedOutput()
	logger.Info("cyclonedxOutput", zap.String("cyclonedxOutput", string(cyclonedxOutput)))
	if err != nil {
		logger.Error("failed while scanning image", zap.Error(err))
		err = fmt.Errorf("failed while scanning image: %s", err.Error())
		return
	}
	var cyclonedxSbom interface{}
	err = json.Unmarshal(cyclonedxOutput, &cyclonedxSbom)

	packages, err := GetPackageIDs(cyclonedxSbom)
	if err != nil {
		logger.Error("failed to get package ids", zap.Error(err))
		err = fmt.Errorf("failed to get package ids: %s", err.Error())
		return
	}

	result := ArtifactSbom{
		ImageURL:          artifact.OciArtifactUrl,
		ArtifactID:        artifact.ArtifactID,
		Packages:          packages,
		SbomSpdxJson:      spdxSbom,
		SbomCyclonedxJson: cyclonedxSbom,
	}

	esResult := &es.TaskResult{
		PlatformID:   fmt.Sprintf("%s:::%s:::%s", request.TaskDefinition.TaskType, "artifact_sbom", result.UniqueID()),
		ResourceID:   result.UniqueID(),
		ResourceName: artifact.OciArtifactUrl,
		Description:  result,
		ResultType:   strings.ToLower(request.TaskDefinition.ResultType),
		TaskType:     request.TaskDefinition.TaskType,
		Metadata:     nil,
		DescribedAt:  time.Now().Unix(),
		DescribedBy:  strconv.FormatUint(uint64(request.TaskDefinition.RunID), 10),
	}

	keys, idx := esResult.KeysAndIndex()
	esResult.EsID = es.HashOf(keys...)
	esResult.EsIndex = "artifact_sbom"

	err = sendDataToOpensearch(esClient.ES(), esResult, "artifact_sbom")
	if err != nil {
		logger.Error("failed sending data to OpenSearch", zap.Error(err))
		err = fmt.Errorf("failed sending data to OpenSearch: %s", err.Error())
		return
	}
	index = idx
	id = es.HashOf(keys...)

	// add packages
	packagesResult := ArtifactPackageList{
		ImageURL:   artifact.OciArtifactUrl,
		ArtifactID: artifact.ArtifactID,
		Packages:   packages,
	}

	packagesEsResult := &es.TaskResult{
		PlatformID:   fmt.Sprintf("%s:::%s:::%s", request.TaskDefinition.TaskType, "artifact_package_list", packagesResult.UniqueID()),
		ResourceID:   result.UniqueID(),
		ResourceName: artifact.OciArtifactUrl,
		Description:  packagesResult,
		ResultType:   strings.ToLower(request.TaskDefinition.ResultType),
		TaskType:     request.TaskDefinition.TaskType,
		Metadata:     nil,
		DescribedAt:  time.Now().Unix(),
		DescribedBy:  strconv.FormatUint(uint64(request.TaskDefinition.RunID), 10),
	}

	keys, idx = packagesEsResult.KeysAndIndex()
	packagesEsResult.EsID = es.HashOf(keys...)
	packagesEsResult.EsIndex = "artifact_package_list"

	err = sendDataToOpensearch(esClient.ES(), packagesEsResult, "artifact_package_list")
	if err != nil {
		logger.Error("failed sending data to OpenSearch", zap.Error(err))
		err = fmt.Errorf("failed sending data to OpenSearch: %s", err.Error())
		return
	}
	index = idx
	id = es.HashOf(keys...)
}

func GetArtifactsFromQueryID(coreServiceClient coreClient.CoreServiceClient, params map[string]any) ([]Artifact, error) {
	var queryParamsInterface map[string]interface{}
	queryParams := make(map[string]string)
	if v, ok := params["query_params"]; ok {
		queryParamsInterface, ok = v.(map[string]interface{})
		if ok {
			for key, value := range queryParamsInterface {
				queryParams[key] = value.(string)
			}
		}
	}
	queryLimit := 50
	if v, ok := params["query_limit"]; ok {
		if vv, ok := v.(int); ok {
			queryLimit = vv
		}
	}
	if v, ok := params["query_id"]; ok {
		if vv, ok := v.(string); !ok {
			return nil, fmt.Errorf("query id should be a string")
		} else {
			queryResponse, err := coreServiceClient.RunQueryByID(&httpclient.Context{UserRole: authApi.AdminRole}, coreApi.RunQueryByIDRequest{
				ID:          vv,
				Type:        "named_query",
				QueryParams: queryParams,
				Page: coreApi.Page{
					No:   1,
					Size: queryLimit,
				},
			})
			if err != nil {
				return nil, err
			}
			var artifacts []Artifact
			for _, r := range queryResponse.Result {
				artifact := Artifact{}
				for i, rc := range r {
					if queryResponse.Headers[i] == "name" {
						artifact.OciArtifactUrl = rc.(string)
					}
					if queryResponse.Headers[i] == "digest" {
						artifact.ArtifactID = rc.(string)
					}
				}
				artifacts = append(artifacts, artifact)
			}
			return artifacts, nil
		}
	} else {
		return nil, fmt.Errorf("query id should be a string")
	}
}

func GetArtifactsFromInlineQuery(coreServiceClient coreClient.CoreServiceClient, params map[string]any) ([]Artifact, error) {
	queryLimit := 50
	if v, ok := params["query_limit"]; ok {
		if vv, ok := v.(int); ok {
			queryLimit = vv
		}
	}
	if v, ok := params["query_to_execute"]; ok {
		if vv, ok := v.(string); !ok {
			return nil, fmt.Errorf("query id should be a string")
		} else {
			queryResponse, err := coreServiceClient.RunQuery(&httpclient.Context{UserRole: authApi.AdminRole}, coreApi.RunQueryRequest{
				Query: &vv,
				Page: coreApi.Page{
					No:   1,
					Size: queryLimit,
				},
			})
			if err != nil {
				return nil, err
			}
			var artifacts []Artifact
			for _, r := range queryResponse.Result {
				artifact := Artifact{}
				for i, rc := range r {
					if queryResponse.Headers[i] == "name" {
						artifact.OciArtifactUrl = rc.(string)
					}
					if queryResponse.Headers[i] == "digest" {
						artifact.ArtifactID = rc.(string)
					}
				}
				artifacts = append(artifacts, artifact)
			}
			return artifacts, nil
		}
	} else {
		return nil, fmt.Errorf("query id should be a string")
	}
}

func GetPackageIDs(cyclonedxSbom interface{}) ([]Package, error) {
	sbomBytes, err := GetBytesFromInterface(cyclonedxSbom)
	if err != nil {
		return nil, fmt.Errorf("failed to get bytes from SbomCyclonedxJson: %w", err)
	}

	bom := new(cyclonedx.BOM)
	decoder := cyclonedx.NewBOMDecoder(bytes.NewReader(sbomBytes), cyclonedx.BOMFileFormatJSON)
	err = decoder.Decode(bom)
	if err != nil {
		return nil, fmt.Errorf("decoding CycloneDX BOM: %w", err) // Return error
	}

	var packageIds []Package
	if bom.Components != nil {
		for _, c := range *bom.Components {
			var standardEcosystem string
			var err error
			if c.PackageURL != "" {
				standardEcosystem, err = getStandardEcosystemFromPURL(c.PackageURL)
				if err != nil {
					standardEcosystem = ""
				}
			} else {
				standardEcosystem = "" // Use default if PURL is missing
			}
			packageIds = append(packageIds, Package{
				Ecosystem: standardEcosystem,
				Name:      c.Name,
				Version:   c.Version,
			})
		}
	}
	return packageIds, nil
}

func GetBytesFromInterface(source interface{}) ([]byte, error) {
	var data []byte
	var err error

	switch content := source.(type) {
	case []byte:
		data = content
	case string:
		data = []byte(content)
	case io.Reader:
		data, err = io.ReadAll(content)
		if err != nil {
			return nil, fmt.Errorf("reading data (io.Reader): %w", err)
		}
	case map[string]interface{}:
		data, err = json.Marshal(content)
		if err != nil {
			return nil, fmt.Errorf("cannot re-marshal map[string]interface{} to JSON: %w", err)
		}
	case nil:
		return nil, fmt.Errorf("input source is nil")
	default:
		return nil, fmt.Errorf("unsupported input type for data source: %T", source)
	}

	return data, nil
}

// --- PURL Parsing and Ecosystem Mapping ---
var purlTypeToOSVEcosystem = map[string]string{
	"almalinux": "AlmaLinux", "alpine": "Alpine", "apk": "Alpine", "bitnami": "Bitnami", "cargo": "crates.io",
	"conan": "ConanCenter", "cran": "CRAN", "deb": "Debian", "composer": "Packagist", "gem": "RubyGems",
	"generic": "OSS-Fuzz", "ghc": "GHC", "github": "OSS-Fuzz", "go": "Go", "golang": "Go",
	"hackage": "Hackage", "hex": "Hex", "linux": "Linux", "mageia": "Mageia", "maven": "Maven",
	"npm": "npm", "nuget": "NuGet", "opensuse": "openSUSE", "photon": "Photon OS", "pub": "Pub",
	"pypi": "PyPI", "rhel": "Red Hat", "rocky": "Rocky Linux", "rpm": "OSS-Fuzz", "suse": "SUSE",
	"swift": "SwiftURL", "ubuntu": "Ubuntu", "wolfi": "Wolfi",
}
var distroQualifierToOSVEcosystem = map[string]string{
	"almalinux": "AlmaLinux", "alpine": "Alpine", "debian": "Debian", "mageia": "Mageia",
	"opensuse": "openSUSE", "photon": "Photon OS", "rhel": "Red Hat",
	"rockylinux": "Rocky Linux", "suse": "SUSE", "ubuntu": "Ubuntu", "wolfi": "Wolfi",
}

func getStandardEcosystemFromPURL(purlString string) (string, error) {
	if purlString == "" {
		return "", errors.New("PURL string is empty")
	}
	purlObj, err := purl.FromString(purlString)
	if err != nil {
		return "", fmt.Errorf("failed to parse PURL '%s': %w", purlString, err)
	}
	purlTypeLower := strings.ToLower(purlObj.Type)
	if distro, ok := purlObj.Qualifiers.Map()["distro"]; ok && distro != "" {
		distroLower := strings.ToLower(distro)
		if ecosystem, found := distroQualifierToOSVEcosystem[distroLower]; found {
			return ecosystem, nil
		}
	}
	if ecosystem, found := purlTypeToOSVEcosystem[purlTypeLower]; found {
		return ecosystem, nil
	}
	return "", fmt.Errorf("cannot map PURL type '%s' (from PURL '%s') to a standard OSV ecosystem", purlTypeLower, purlString)
}
