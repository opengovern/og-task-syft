package task

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/opengovern/opensecurity/services/tasks/db/models"
	"io"
	"log"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

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

	// --- Docker Login via Task Parameters ---
	usernameParam, userOk := request.TaskDefinition.Params["github_username"]
	tokenParam, tokenOk := request.TaskDefinition.Params["github_token"]

	if userOk && tokenOk {
		username, userStrOk := usernameParam.(string)
		token, tokenStrOk := tokenParam.(string)

		if userStrOk && tokenStrOk && username != "" && token != "" {
			logger.Info("Attempting docker login for ghcr.io using provided parameters", zap.String("username", username))
			// Use docker login ... --password-stdin
			cmd := exec.Command("docker", "login", "ghcr.io", "--username", username, "--password-stdin")

			stdin, pipeErr := cmd.StdinPipe()
			if pipeErr != nil {
				logger.Error("Failed to get stdin pipe for docker login", zap.Error(pipeErr))
				err = fmt.Errorf("failed to get stdin pipe for docker login: %w", pipeErr)
				return err
			}

			var loginOutput bytes.Buffer
			cmd.Stdout = &loginOutput
			cmd.Stderr = &loginOutput // Capture both stdout and stderr

			startErr := cmd.Start()
			if startErr != nil {
				logger.Error("Failed to start docker login command", zap.Error(startErr))
				err = fmt.Errorf("failed to start docker login command: %w", startErr)
				return err
			}

			// Write the token to stdin in a separate goroutine to avoid blocking
			go func() {
				defer func() {
					if err := stdin.Close(); err != nil {
						logger.Warn("Failed to close stdin pipe for docker login", zap.Error(err))
					}
				}()
				_, writeErr := io.WriteString(stdin, token)
				if writeErr != nil {
					// Log the error, but let cmd.Wait() below handle the overall failure
					logger.Error("Failed to write token to docker login stdin", zap.Error(writeErr))
				}
			}()

			waitErr := cmd.Wait()
			loginLog := logger.With(zap.String("output", loginOutput.String())) // Add output context
			if waitErr != nil {
				loginLog.Error("Docker login command failed", zap.Error(waitErr))
				// Assign error to the 'err' variable captured by the defer func.
				tmp := models.TaskSecretHealthStatusUnhealthy
				response.CredentialsHealthStatus = &tmp
				responseJson, err := json.Marshal(response)
				if err != nil {
					log.Printf("failed to create response json: %v", zap.Error(err))
					return err
				}

				if _, err = jq.Produce(ctx, envs.ResultTopicName, responseJson, fmt.Sprintf("task-run-inprogress-%d", request.TaskDefinition.RunID)); err != nil {
					log.Printf("failed to publish job in progress", zap.String("response", string(responseJson)), zap.Error(err))
				}

				err = fmt.Errorf("docker login failed for user %s: %w. Output: %s", username, waitErr, loginOutput.String())
				return err
			} else {
				tmp := models.TaskSecretHealthStatusHealthy
				response.CredentialsHealthStatus = &tmp
				responseJson, err := json.Marshal(response)
				if err != nil {
					log.Printf("failed to create response json: %v", zap.Error(err))
					return err
				}

				if _, err = jq.Produce(ctx, envs.ResultTopicName, responseJson, fmt.Sprintf("task-run-inprogress-%d", request.TaskDefinition.RunID)); err != nil {
					log.Printf("failed to publish job in progress", zap.String("response", string(responseJson)), zap.Error(err))
				}
				loginLog.Info("Docker login succeeded")
			}
		} else {
			logger.Info("github_username or github_token parameters provided but are empty or not strings. Skipping docker login.")
		}
	} else {
		logger.Info("github_username or github_token parameters not found in request. Relying on existing docker credentials.")
	}

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
	logger.Info("Scanning artifact", zap.String("image", artifact.OciArtifactUrl), zap.String("artifact_id", artifact.ArtifactID))

	var err error
	var index, id string

	defer func() {
		if r := recover(); r != nil {
			// Log panic
			logger.Error("Panic recovered during ScanArtifact", zap.Any("panic_info", r), zap.Stack("stacktrace"))
			// Ensure error is set for the task result
			if err == nil {
				err = fmt.Errorf("panic occurred: %v", r)
			}
		}

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

	// Helper function to run syft with platform fallback
	runSyft := func(format string) ([]byte, error) {
		baseArgs := []string{artifact.OciArtifactUrl, "--scope", "all-layers", "-o", format}

		// Attempt 1: Run without explicit platform
		cmd := exec.Command("syft", baseArgs...)
		logger.Info("Running syft (attempt 1)", zap.String("command", cmd.String()))
		output, attempt1Err := cmd.CombinedOutput()
		if attempt1Err == nil {
			logger.Info("Syft initial attempt succeeded", zap.String("format", format))
			return output, nil // Success on first try
		}

		// Check if error is the specific platform error
		errMsg := string(output) // CombinedOutput includes stderr
		if strings.Contains(errMsg, "no child with platform") {
			logger.Warn("Syft failed (attempt 1) with platform error, retrying with --platform linux/amd64", zap.String("original_error_output", errMsg))
			// Attempt 2: Run with --platform linux/amd64
			amd64Args := append([]string{"--platform", "linux/amd64"}, baseArgs...)
			cmd = exec.Command("syft", amd64Args...)
			logger.Info("Running syft (attempt 2 - fallback)", zap.String("command", cmd.String()))
			output, attempt2Err := cmd.CombinedOutput()
			if attempt2Err == nil {
				logger.Info("Syft fallback attempt succeeded", zap.String("format", format))
				return output, nil // Success on fallback try
			}
			// Fallback failed, return the error from the fallback attempt
			logger.Error("Syft fallback attempt (attempt 2) also failed", zap.Error(attempt2Err), zap.String("output", string(output)))
			return nil, fmt.Errorf("syft fallback scan failed (%s): %w; Output: %s", format, attempt2Err, string(output))
		}

		// Original command failed for a different reason (not platform error)
		logger.Error("Syft initial scan failed (attempt 1)", zap.Error(attempt1Err), zap.String("output", errMsg))
		return nil, fmt.Errorf("syft initial scan failed (%s): %w; Output: %s", format, attempt1Err, errMsg)
	}

	// Run Syft for SPDX JSON
	spdxOutput, err := runSyft("spdx-json")
	if err != nil {
		logger.Error("failed while scanning image", zap.Error(err))
		err = fmt.Errorf("failed while scanning image: %s", err.Error())
		return
	}
	var spdxSbom interface{}
	err = json.Unmarshal(spdxOutput, &spdxSbom)
	if err != nil {
		logger.Error("Failed to unmarshal spdx-json output", zap.Error(err), zap.String("raw_output", string(spdxOutput)))
		err = fmt.Errorf("failed to unmarshal spdx-json output: %w", err)
		return
	}
	logger.Info("Successfully generated SPDX SBOM")

	// Run Syft for CycloneDX JSON
	cyclonedxOutput, err := runSyft("cyclonedx-json")
	if err != nil {
		// Error is already logged and formatted by runSyft
		// The defer function will capture and report this error
		return
	}
	var cyclonedxSbom interface{}
	err = json.Unmarshal(cyclonedxOutput, &cyclonedxSbom)
	if err != nil {
		logger.Error("Failed to unmarshal cyclonedx-json output", zap.Error(err), zap.String("raw_output", string(cyclonedxOutput)))
		err = fmt.Errorf("failed to unmarshal cyclonedx-json output: %w", err)
		return
	}
	logger.Info("Successfully generated CycloneDX SBOM")

	// --- Process SBOMs and Store Results ---

	packages, err := GetPackageIDs(cyclonedxSbom)
	if err != nil {
		// Error already includes context from GetPackageIDs
		logger.Error("Failed to get package IDs from CycloneDX SBOM", zap.Error(err))
		// Defer will capture this error
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
		ResultType:   strings.ToLower("artifact_sbom"),
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
		ResultType:   strings.ToLower("artifact_package_list"),
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

	numWorkers := runtime.NumCPU()

	// Create Options struct
	opts := Options{
		NumWorkers:       numWorkers,
		Sbom:             sbomBytes,
		DefaultEcosystem: "",
	}

	// === Execute Core Logic ===
	startTime := time.Now()
	results, err := run(context.Background(), opts)
	if err != nil {
		log.Printf("Error running SBOM processing: %v", err)
		return nil, fmt.Errorf("failed during SBOM processing: %w", err)
	}
	totalDuration := time.Since(startTime)

	// === Final Summary Logging ===
	log.Printf("--- Processing Summary ---")
	if results != nil && results.ParseStats != nil {
		parseStats := results.ParseStats
		var totalSkipped int64 = 0
		for _, count := range parseStats.SkippedCountByType {
			totalSkipped += count
		}
		log.Printf("SBOM Parsing: Found %d components, Parsed %d packages, Skipped %d components.",
			parseStats.ComponentsFound, parseStats.PackagesParsed, totalSkipped)

		// Log breakdown of skipped components if any were skipped
		if totalSkipped > 0 {
			log.Printf("  Skipped Component Breakdown:")
			// Define order for consistent logging if desired
			knownReasons := []SkipReason{SkipReasonNonPackage, SkipReasonInvalid, SkipReasonNoEcosystem}
			loggedReasons := make(map[SkipReason]bool)

			for _, reason := range knownReasons {
				if count, ok := parseStats.SkippedCountByType[reason]; ok && count > 0 {
					log.Printf("    - %s: %d", reason, count)
					loggedReasons[reason] = true
				}
			}
			// Log any other unexpected reasons found
			for reason, count := range parseStats.SkippedCountByType {
				if !loggedReasons[reason] && count > 0 {
					log.Printf("    - %s (Other): %d", reason, count)
				}
			}
		}

		if totalSkipped > 0 {
			log.Printf("Tip: %d components were skipped. Use -output-skipped <file> to save details.", totalSkipped)
		}

	} else {
		log.Printf("SBOM Parsing: Stats unavailable (likely due to early error).")
	}

	log.Printf("Total execution time: %v", totalDuration)

	if results == nil {
		return nil, nil
	}

	var packages []Package
	for _, p := range results.Packages {
		packages = append(packages, Package{
			Ecosystem: p.Ecosystem,
			Name:      p.PackageName,
			Version:   p.Version,
		})
	}

	return packages, nil
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

// --- Struct Definitions ---

// InputPackage represents the final output structure for each package found.
type InputPackage struct {
	PackageName string `json:"package_name"`
	Ecosystem   string `json:"ecosystem"` // Case-sensitive standard ecosystem (mapped from PURL or default)
	Version     string `json:"version"`
}

// cdxComponent holds component data during processing.
type cdxComponent struct {
	BOMRef     string
	Type       string
	Name       string
	Version    string
	PackageURL string
}

// --- Skip Reason Handling ---

type SkipReason string

const (
	SkipReasonNonPackage  SkipReason = "NON_PACKAGE_TYPE"        // Component type is File, OS, Device, etc.
	SkipReasonInvalid     SkipReason = "INVALID_COMPONENT_DATA"  // Missing Name or Version.
	SkipReasonNoEcosystem SkipReason = "NO_ECOSYSTEM_DETERMINED" // Could not determine ecosystem (failed PURL map AND no default provided).
)

// SkippedComponentInfo holds structured details about skipped components.
type SkippedComponentInfo struct {
	Reason           SkipReason `json:"reason"`
	Message          string     `json:"message"`
	ComponentName    string     `json:"component_name,omitempty"`    // Add context
	ComponentVersion string     `json:"component_version,omitempty"` // Add context
	ComponentBOMRef  string     `json:"component_bom_ref,omitempty"` // Add context for traceability
}

// --- Statistics and Error Reporting ---

// conversionStats tracks SBOM parsing statistics.
type conversionStats struct {
	ComponentsFound    int64
	PackagesParsed     int
	SkippedCountByType map[SkipReason]int64 // Count skips by category
}

// processResults holds the final results and stats from the parsing process.
type processResults struct {
	ParseStats   *conversionStats       // Contains the skip breakdown map
	SkippedInfos []SkippedComponentInfo // Stores structured info about skipped components
	Packages     []InputPackage         // The final list of extracted packages
}

// --- Configuration Options ---

// Options holds the configuration for the program execution.
type Options struct {
	NumWorkers       int
	DefaultEcosystem string
	Sbom             []byte
}

// --- PURL Parsing and Ecosystem Mapping ---
// This map helps standardize ecosystem names, crucial for consumers of the output.
var purlTypeToStandardEcosystem = map[string]string{
	"almalinux": "AlmaLinux", "alpine": "Alpine", "apk": "Alpine", "bitnami": "Bitnami", "cargo": "crates.io",
	"conan": "ConanCenter", "cran": "CRAN", "deb": "Debian", "composer": "Packagist", "gem": "RubyGems",
	"generic": "generic", "ghc": "GHC", "github": "GitHub", "go": "Go", "golang": "Go", // Note: OSV uses 'Go', 'GitHub' not typically an ecosystem itself but maps well here
	"hackage": "Hackage", "hex": "Hex", "linux": "Linux", "mageia": "Mageia", "maven": "Maven",
	"npm": "npm", "nuget": "NuGet", "opensuse": "openSUSE", "photon": "Photon OS", "pub": "Pub",
	"pypi": "PyPI", "rhel": "Red Hat", "rocky": "Rocky Linux", "rpm": "RPM", "suse": "SUSE", // Note: OSV often uses OSS-Fuzz for generic/rpm, 'RPM' might be clearer here
	"swift": "SwiftURL", "ubuntu": "Ubuntu", "wolfi": "Wolfi",
}
var distroQualifierToStandardEcosystem = map[string]string{
	"almalinux": "AlmaLinux", "alpine": "Alpine", "debian": "Debian", "mageia": "Mageia",
	"opensuse": "openSUSE", "photon": "Photon OS", "rhel": "Red Hat",
	"rockylinux": "Rocky Linux", "suse": "SUSE", "ubuntu": "Ubuntu", "wolfi": "Wolfi",
}

// getStandardEcosystemFromPURL attempts to map a PURL to a common ecosystem identifier.
func getStandardEcosystemFromPURL(purlString string) (string, error) {
	if purlString == "" {
		return "", errors.New("PURL string is empty")
	}
	purlObj, err := purl.FromString(purlString)
	if err != nil {
		return "", fmt.Errorf("failed to parse PURL '%s': %w", purlString, err)
	}
	purlTypeLower := strings.ToLower(purlObj.Type)

	// Prioritize distribution qualifier for OS packages
	if distro, ok := purlObj.Qualifiers.Map()["distro"]; ok && distro != "" {
		distroLower := strings.ToLower(distro)
		if ecosystem, found := distroQualifierToStandardEcosystem[distroLower]; found {
			return ecosystem, nil
		}
		// Fallback: Use the distro qualifier itself if not in the map? Could be risky.
		// log.Printf("Warning: Unmapped PURL distro qualifier '%s' for PURL '%s'. Using PURL type.", distroLower, purlString)
	}

	// Map based on PURL type
	if ecosystem, found := purlTypeToStandardEcosystem[purlTypeLower]; found {
		return ecosystem, nil
	}

	// Fallback: Use the PURL type itself if no specific mapping exists
	log.Printf("Warning: Cannot map PURL type '%s' (from PURL '%s') to a standard ecosystem. Using PURL type '%s' as ecosystem.", purlTypeLower, purlString, purlTypeLower)
	if purlTypeLower != "" {
		return purlTypeLower, nil // Return the type itself as a last resort
	}

	return "", fmt.Errorf("cannot determine ecosystem from PURL '%s'", purlString)
}

// --- Worker Goroutine (SBOM Parsing Stage) ---
// Processes individual components from the SBOM.
func worker(id int, wg *sync.WaitGroup, components <-chan *cdxComponent, results chan<- InputPackage, skipInfos chan<- SkippedComponentInfo, defaultEcosystem string) {
	defer wg.Done()
	for component := range components {
		// Capture component info early for context in skip messages
		compName := component.Name
		if compName == "" {
			compName = "<missing>"
		}
		compVersion := component.Version
		if compVersion == "" {
			compVersion = "<missing>"
		}
		compBOMRef := component.BOMRef

		pkgName := component.Name
		pkgVersion := component.Version
		purlString := component.PackageURL
		compType := cyclonedx.ComponentType(component.Type)

		// --- Skip Reason: Non-package Type ---
		// We only care about library/application/framework/os/container components.
		// Using the correct constants from the cyclonedx-go library.
		if compType != cyclonedx.ComponentTypeLibrary &&
			compType != cyclonedx.ComponentTypeApplication &&
			compType != cyclonedx.ComponentTypeFramework &&
			compType != cyclonedx.ComponentTypeOS &&
			compType != cyclonedx.ComponentTypeContainer &&
			compType != "" { // Allow empty type which often defaults to library/application
			// Explicitly skip File and Device
			if compType == cyclonedx.ComponentTypeFile || compType == cyclonedx.ComponentTypeDevice {
				message := fmt.Sprintf("component (%s, BOM-Ref: %s): skipped type '%s'", compName, compBOMRef, compType)
				skipInfos <- SkippedComponentInfo{
					Reason:           SkipReasonNonPackage,
					Message:          message,
					ComponentName:    compName,
					ComponentVersion: compVersion,
					ComponentBOMRef:  compBOMRef,
				}
				continue
			}
			// Log other types we aren't explicitly skipping but might not be typical packages
			// log.Printf("Info: Processing component (%s, BOM-Ref: %s) with non-standard package type '%s'", compName, compBOMRef, compType)
		}

		// --- Skip Reason: Invalid (Missing Name/Version) ---
		// Name and Version are essential for identifying a package.
		var validationErrorMsg string
		if pkgName == "" {
			validationErrorMsg = "missing name"
		} else if pkgVersion == "" || pkgVersion == "<missing>" { // Check explicit "<missing>" too
			// Allow missing version for OS/Container types, but log it
			if compType != cyclonedx.ComponentTypeOS && compType != cyclonedx.ComponentTypeContainer {
				validationErrorMsg = "missing version"
			} else {
				log.Printf("Info: Component (%s, BOM-Ref: %s, Type: %s) has missing version, proceeding.", compName, compBOMRef, compType)
				pkgVersion = "<missing>" // Ensure it's explicitly marked
			}
		}
		if validationErrorMsg != "" {
			message := fmt.Sprintf("component (%s@%s, BOM-Ref: %s): invalid - %s", compName, compVersion, compBOMRef, validationErrorMsg)
			skipInfos <- SkippedComponentInfo{
				Reason:           SkipReasonInvalid,
				Message:          message,
				ComponentName:    compName,
				ComponentVersion: compVersion, // Use original captured version for skip message
				ComponentBOMRef:  compBOMRef,
			}
			continue
		}

		// --- Determine Ecosystem ---
		var standardEcosystem string
		var err error
		if purlString != "" {
			standardEcosystem, err = getStandardEcosystemFromPURL(purlString)
			if err != nil {
				// Log warning but proceed to check default ecosystem if PURL mapping failed
				log.Printf("Warning: component (%s@%s, BOM-Ref: %s): PURL processing failed (%v). Using default ecosystem '%s' if specified.", pkgName, pkgVersion, component.BOMRef, err, defaultEcosystem)
				standardEcosystem = defaultEcosystem // Try default
			}
		} else {
			standardEcosystem = defaultEcosystem // Use default if PURL is missing entirely
			if standardEcosystem == "" {
				// If no PURL and no default, try to guess based on type for OS/Container
				if compType == cyclonedx.ComponentTypeOS {
					log.Printf("Info: component (%s@%s, BOM-Ref: %s): No PURL and no default ecosystem. Using 'os' as ecosystem based on component type.", pkgName, pkgVersion, component.BOMRef)
					standardEcosystem = "os"
				} else if compType == cyclonedx.ComponentTypeContainer {
					log.Printf("Info: component (%s@%s, BOM-Ref: %s): No PURL and no default ecosystem. Using 'container' as ecosystem based on component type.", pkgName, pkgVersion, component.BOMRef)
					standardEcosystem = "container"
				}
			}
		}

		// --- Skip Reason: No Ecosystem ---
		// If ecosystem is *still* empty (no PURL match/guess and no default provided)
		if standardEcosystem == "" {
			message := fmt.Sprintf("component (%s@%s, BOM-Ref: %s): skipped - could not determine ecosystem (no PURL/mapping/guess and no default provided)", pkgName, pkgVersion, component.BOMRef)
			skipInfos <- SkippedComponentInfo{
				Reason:           SkipReasonNoEcosystem,
				Message:          message,
				ComponentName:    pkgName,
				ComponentVersion: pkgVersion,
				ComponentBOMRef:  compBOMRef,
			}
			continue
		}

		// --- Success: Prepare Output Package ---
		outputPkg := InputPackage{
			PackageName: pkgName,
			Ecosystem:   standardEcosystem,
			Version:     pkgVersion, // Use potentially updated pkgVersion (e.g., "<missing>")
		}
		results <- outputPkg
	}
}

// --- Helper to get all components ---
// Recursively extracts all components and sub-components from the BOM.
func getAllComponents(components *[]cyclonedx.Component) []cyclonedx.Component {
	if components == nil {
		return nil
	}
	all := make([]cyclonedx.Component, 0, len(*components))
	for _, comp := range *components {
		all = append(all, comp)
		// Recursively add sub-components
		if comp.Components != nil {
			all = append(all, getAllComponents(comp.Components)...)
		}
	}
	return all
}

// --- writePackageListOutput ---
// Writes the final list of extracted packages to the specified output writer.
func writePackageListOutput(output io.Writer, packages []InputPackage) error {
	outputJSON, err := json.MarshalIndent(packages, "", "  ")
	if err != nil {
		return fmt.Errorf("error marshalling final package list JSON: %w", err)
	}
	_, err = output.Write(outputJSON)
	if err != nil {
		return fmt.Errorf("error writing final package list JSON: %w", err)
	}
	_, err = output.Write([]byte("\n")) // Add trailing newline
	if err != nil {
		log.Printf("warning: failed to write final newline to package list: %v", err)
		// Don't treat failure to write newline as a fatal error
	}
	return nil
}

// --- run function containing the core logic ---
func run(ctx context.Context, opts Options) (*processResults, error) {

	results := &processResults{ // Initialize results struct
		ParseStats: &conversionStats{
			SkippedCountByType: make(map[SkipReason]int64),
		},
		SkippedInfos: make([]SkippedComponentInfo, 0),
		Packages:     make([]InputPackage, 0, 1024), // Initialize package slice
	}
	parseStats := results.ParseStats // Assign pointer for convenience

	// === Stage 1: Parse SBOM ===
	parseStart := time.Now()

	// --- Read Input File ---
	// Handles large files efficiently as io.ReadAll reads in chunks.
	// Max memory usage here is proportional to file size (up to 200MB as requested).

	readDuration := time.Since(parseStart)
	log.Printf("Finished reading %d bytes from input file in %v.", len(opts.Sbom), readDuration)

	if len(opts.Sbom) == 0 {
		log.Println("Warning: Input file is empty.")
		return results, nil // Return successfully with zero packages
	}

	// --- Decode BOM ---
	// Handles large files efficiently as the decoder streams.
	decodeStart := time.Now()
	log.Printf("Decoding CycloneDX BOM (%d bytes)...", len(opts.Sbom))
	bom := new(cyclonedx.BOM)
	decoder := cyclonedx.NewBOMDecoder(bytes.NewReader(opts.Sbom), cyclonedx.BOMFileFormatJSON)
	err := decoder.Decode(bom)
	if err != nil {
		// Provide more context on JSON decoding errors
		var syntaxError *json.SyntaxError
		var unmarshalTypeError *json.UnmarshalTypeError
		if errors.As(err, &syntaxError) {
			return results, fmt.Errorf("decoding CycloneDX BOM: JSON syntax error at offset %d: %w", syntaxError.Offset, err)
		} else if errors.As(err, &unmarshalTypeError) {
			return results, fmt.Errorf("decoding CycloneDX BOM: JSON type mismatch error at offset %d (field '%s'): %w", unmarshalTypeError.Offset, unmarshalTypeError.Field, err)
		}
		// Generic decode error
		return results, fmt.Errorf("decoding CycloneDX BOM: %w", err)
	}
	decodeDuration := time.Since(decodeStart)
	log.Printf("Successfully decoded CycloneDX BOM in %v.", decodeDuration)

	// *** BOM Format Validation (Post-Decode) ***
	if bom.BOMFormat != "CycloneDX" {
		log.Printf("Error: Decoded BOM format is '%s', but expected 'CycloneDX'.", bom.BOMFormat)
		return results, fmt.Errorf("invalid BOM format: expected 'CycloneDX', got '%s'", bom.BOMFormat)
	}
	log.Printf("BOM format validated as 'CycloneDX'.")

	// --- Setup Workers and Channels ---
	componentsChan := make(chan *cdxComponent, opts.NumWorkers*2) // Buffer channels
	resultsChan := make(chan InputPackage, opts.NumWorkers*2)
	skipInfosChan := make(chan SkippedComponentInfo, 200) // Generous buffer for skips
	var workersWg sync.WaitGroup
	var collectorWg sync.WaitGroup

	log.Printf("Starting %d workers for SBOM processing...", opts.NumWorkers)
	for i := 0; i < opts.NumWorkers; i++ {
		workersWg.Add(1)
		go worker(i+1, &workersWg, componentsChan, resultsChan, skipInfosChan, opts.DefaultEcosystem)
	}

	// --- Collector Goroutine ---
	// Collects results and skipped info from workers.
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		resultsOpen := true
		skipInfosOpen := true
		for resultsOpen || skipInfosOpen {
			select {
			case pkg, ok := <-resultsChan:
				if !ok {
					resultsChan = nil // Mark channel as closed
					resultsOpen = false
				} else {
					results.Packages = append(results.Packages, pkg)
				}
			case info, ok := <-skipInfosChan:
				if !ok {
					skipInfosChan = nil // Mark channel as closed
					skipInfosOpen = false
				} else {
					results.SkippedInfos = append(results.SkippedInfos, info)
				}
			}
		}
	}()

	// --- Dispatch Components ---
	log.Printf("Dispatching components to workers...")
	allBomComponents := getAllComponents(bom.Components)
	parseStats.ComponentsFound = int64(len(allBomComponents))
	var dispatchErr error // Use a more specific name

dispatchLoop:
	for i := range allBomComponents {
		// Create a copy or use the index to avoid capturing the loop variable directly if needed by goroutines (not strictly needed here as we pass pointer below)
		comp := allBomComponents[i]
		// Create the intermediate struct to send
		internalComp := cdxComponent{
			BOMRef:     comp.BOMRef,
			Type:       string(comp.Type),
			Name:       comp.Name,
			Version:    comp.Version,
			PackageURL: comp.PackageURL,
		}
		select {
		case <-ctx.Done(): // Check for context cancellation
			dispatchErr = ctx.Err()
			log.Printf("Component dispatch interrupted by context cancellation: %v", dispatchErr)
			break dispatchLoop
		case componentsChan <- &internalComp: // Send pointer to component data
			// Sent successfully
		}
	}
	// Handle case where BOM might be valid but have no components
	if parseStats.ComponentsFound == 0 {
		log.Println("Info: No components found in the BOM's component list.")
	}
	close(componentsChan) // IMPORTANT: Close channel once all components are sent
	log.Printf("Finished dispatching %d components.", parseStats.ComponentsFound)

	// --- Wait for Workers and Collector ---
	log.Println("Waiting for SBOM workers to finish...")
	workersWg.Wait()
	log.Println("SBOM workers finished.")
	close(resultsChan)   // IMPORTANT: Close results channel *after* workers finish
	close(skipInfosChan) // IMPORTANT: Close skip channel *after* workers finish

	log.Println("Waiting for collector goroutine to finish...")
	collectorWg.Wait()
	log.Println("Collector goroutine finished.")

	// --- Finalize Parsing Stats ---
	var totalSkipped int64 = 0
	for _, skippedInfo := range results.SkippedInfos {
		parseStats.SkippedCountByType[skippedInfo.Reason]++
		totalSkipped++
	}
	parseStats.PackagesParsed = len(results.Packages)

	// Handle dispatch error after cleanup
	if dispatchErr != nil && !errors.Is(dispatchErr, context.Canceled) {
		// Return the specific dispatch error if it wasn't just cancellation
		return results, fmt.Errorf("component dispatch failed: %w", dispatchErr)
	}

	// --- Log Parsing Summary ---
	totalParseDuration := time.Since(parseStart) // Includes reading, decoding, and processing
	if parseStats.PackagesParsed == 0 {
		if parseStats.ComponentsFound > 0 {
			log.Printf("Warning: No valid packages extracted from %d components found in the BOM. Check skipped component logs/file if generated.", parseStats.ComponentsFound)
		} else {
			// Message already logged if ComponentsFound is 0 during dispatch
		}
		// No error, just no packages found/parsed.
	}
	log.Printf("SBOM Parsing Stage Complete (%v): Found %d components, extracted %d packages, skipped %d components.",
		totalParseDuration, parseStats.ComponentsFound, parseStats.PackagesParsed, totalSkipped)

	// === Stage 2: Write Output Package List ===
	log.Printf("--- Stage 2: Writing Output Package List ---")
	writeStart := time.Now()
	var writeErr error // Capture potential write error

	// Write the final package list
	if len(results.Packages) > 0 {
		// Log only if writing to a file (stdout message logged above)
		//if packageListWriter != os.Stdout {
		//	log.Printf("Writing %d extracted packages to %s", len(results.Packages), packageListDest)
		//}
		//err = writePackageListOutput(packageListWriter, results.Packages)
		//if err != nil {
		//	writeErr = fmt.Errorf("writing final package list to %s: %w", packageListDest, err)
		//	log.Printf("Error: %v", writeErr) // Log the error
		//	// Clean up potentially partially written file if writing to file failed
		//	if packageListFile != nil {
		//		packageListFile.Close()        // Close explicitly before removing
		//		_ = os.Remove(opts.OutputFile) // Attempt removal, ignore error
		//	}
		//} else {
		//	// Log success only if writing to a file
		//	if packageListWriter != os.Stdout {
		//		log.Printf("Successfully wrote package list to %s.", packageListDest)
		//	}
		//}
	} else {
		//log.Printf("No packages extracted, skipping write to %s.", packageListDest)
		//// If writing to a file, should we create an empty file or write `[]`?
		//// Current behaviour: do nothing if Packages is empty, which is reasonable.
		//if packageListFile != nil && opts.OutputFile != "" {
		//	// Optionally write empty JSON array if file output was specified
		//	_, _ = packageListWriter.Write([]byte("[]\n"))
		//	log.Printf("Wrote empty array to %s as no packages were extracted.", packageListDest)
		//}
	}

	// Sync stdout if used
	//if packageListWriter == os.Stdout {
	//	_ = os.Stdout.Sync()
	//}

	log.Printf("Finished writing output (%v).", time.Since(writeStart))

	// Return results and the potential write error
	return results, writeErr
}
