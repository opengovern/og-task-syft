package task

import (
	"encoding/json"
	"fmt"
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
	"go.uber.org/zap"
	"golang.org/x/net/context"
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

	//err = fetchImage(registryType, fmt.Sprintf("run-%v", request.TaskDefinition.RunID), artifact.OciArtifactUrl, getCredsFromParams(request.TaskDefinition.Params))
	//if err != nil {
	//	logger.Error("failed to fetch image", zap.String("image", artifact.OciArtifactUrl), zap.Error(err))
	//	err = fmt.Errorf("failed while fetching image: %s", err.Error())
	//	return
	//}

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

	result := ArtifactSbom{
		ImageURL:          artifact.OciArtifactUrl,
		ArtifactID:        artifact.ArtifactID,
		SbomSpdxJson:      spdxSbom,
		SbomCyclonedxJson: cyclonedxSbom,
	}

	esResult := &es.TaskResult{
		PlatformID:   fmt.Sprintf("%s:::%s:::%s", request.TaskDefinition.TaskType, request.TaskDefinition.ResultType, result.UniqueID()),
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
	esResult.EsIndex = idx

	err = sendDataToOpensearch(esClient.ES(), esResult)
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
