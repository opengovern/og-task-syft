package task

import (
	"archive/tar"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/opengovern/resilient-bridge/utils"
	"golang.org/x/net/context"
	"io"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// MaxSizeMiB is the maximum allowed size of the image in MiB, defaulting to 2 GiB.
const MaxSizeMiB = 2048 // 2 GiB
var maxSizeBytes = int64(MaxSizeMiB) * 1024 * 1024

// MaxRetries for pulling and processing the artifact
const MaxRetries = 3

// BackoffBaseDelay is the base delay for exponential backoff between retries.
const BackoffBaseDelay = 2 * time.Second

type AuthConfig struct {
	Auth string `json:"auth,omitempty"`
}

type DockerConfig struct {
	Auths map[string]AuthConfig `json:"auths"`
}

type RegistryType string

const (
	RegistryGHCR RegistryType = "ghcr"
	RegistryECR  RegistryType = "ecr"
	RegistryACR  RegistryType = "acr"
)

type Credentials struct {
	GithubUsername string `json:"github_username"`
	GithubToken    string `json:"github_token"`

	ECRAccountID string `json:"ecr_account_id"`
	ECRRegion    string `json:"ecr_region"`

	ACRLoginServer string `json:"acr_login_server"`
	ACRTenantID    string `json:"acr_tenant_id"`
}

// AllowedMediaTypes defines the permitted OCI and Docker-compatible media types that are acceptable.
var AllowedMediaTypes = []string{
	"application/vnd.oci.descriptor.v1+json",
	"application/vnd.oci.layout.header.v1+json",
	"application/vnd.oci.image.index.v1+json",
	"application/vnd.oci.image.manifest.v1+json",
	"application/vnd.oci.image.config.v1+json",
	"application/vnd.oci.image.layer.v1.tar",
	"application/vnd.oci.image.layer.v1.tar+gzip",
	"application/vnd.oci.image.layer.v1.tar+zstd",
	"application/vnd.oci.empty.v1+json",

	// Non-distributable (deprecated) layers
	"application/vnd.oci.image.layer.nondistributable.v1.tar",
	"application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
	"application/vnd.oci.image.layer.nondistributable.v1.tar+zstd",

	// Docker compatible types if needed:
	"application/vnd.docker.distribution.manifest.v2+json",
	"application/vnd.docker.image.rootfs.diff.tar.gzip",
	"application/vnd.docker.container.image.v1+json",
}

func fetchImage(registryType, outputDir, ociArtifactURI string, creds Credentials) error {
	flag.Parse()

	// Ensure output directory exists
	if err := os.MkdirAll(outputDir, 0700); err != nil {
		return fmt.Errorf("Error creating output directory: %v\n", err)
	}

	// Remove existing image.tar if exists
	imageTarPath := filepath.Join(outputDir, "image.tar")
	if _, err := os.Stat(imageTarPath); err == nil {
		if err := os.Remove(imageTarPath); err != nil {
			return fmt.Errorf("Error removing existing image.tar: %v\n", err)
		}
	}

	// Initialize a DockerConfig structure
	cfg := DockerConfig{
		Auths: make(map[string]AuthConfig),
	}

	ghInputJSON := fmt.Sprintf(`{
			"github": {
				"username": %q,
				"token": %q
			}
		}`, creds.GithubUsername, creds.GithubToken)

	ghcrCreds, err := utils.GetAllCredentials([]byte(ghInputJSON), "")
	if err != nil {
		return fmt.Errorf("GHCR error: %v\n", err)
	}

	ghcrAuth := map[string]AuthConfig{}
	for host, val := range ghcrCreds {
		ghcrAuth[host] = AuthConfig{Auth: val}
	}
	mergeAuths(cfg.Auths, ghcrAuth)

	// If user requested, write out the credentials to a file or print them
	configBytes, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("Error marshaling config to JSON: %v\n", err)
	}

	fmt.Println(string(configBytes))

	// Attempt pulling and creating Docker archive with retries
	for i := 1; i <= MaxRetries; i++ {
		err = pullAndCreateDockerArchive(ociArtifactURI, cfg, outputDir)
		if err == nil {
			fmt.Printf("Successfully created image.tar for %s.\n", ociArtifactURI)
			break
		}

		if isNoSpaceError(err) {
			// Attempt cleanup before retry
			cleanupIntermediateFiles(outputDir)
			if i == MaxRetries {
				// Out of retries
				return fmt.Errorf("Failed due to no space left on device even after cleanup: %v\n", err)
			}
		} else if isAccessError(err) || isNotFoundError(err) {
			// Don't retry on access or not found errors
			return fmt.Errorf("%v\n", err)
		} else {
			// Other errors
			cleanupIntermediateFiles(outputDir)
			if i == MaxRetries {
				return fmt.Errorf("Failed after %d attempts: %v\n", MaxRetries, err)
			}
		}

		// Exponential backoff before next retry
		backoffDelay := BackoffBaseDelay * time.Duration(i)
		fmt.Fprintf(os.Stderr, "Retrying in %s...\n", backoffDelay)
		time.Sleep(backoffDelay)
	}

	return nil
}

func loadDockerConfigFile(path string) (DockerConfig, error) {
	var dc DockerConfig
	bytes, err := os.ReadFile(path)
	if err != nil {
		return dc, fmt.Errorf("failed to read file: %w", err)
	}
	if err := json.Unmarshal(bytes, &dc); err != nil {
		return dc, fmt.Errorf("failed to unmarshal docker config.json: %w", err)
	}
	if dc.Auths == nil {
		dc.Auths = make(map[string]AuthConfig)
	}
	return dc, nil
}

func pullAndCreateDockerArchive(ociArtifactURI string, cfg DockerConfig, outputDir string) error {
	ctx := context.Background()

	ref, err := registry.ParseReference(ociArtifactURI)
	if err != nil {
		return fmt.Errorf("invalid oci-artifact-uri: %w", err)
	}

	credentialsFunc := auth.CredentialFunc(func(ctx context.Context, host string) (auth.Credential, error) {
		if a, ok := cfg.Auths[host]; ok {
			decoded, err := base64.StdEncoding.DecodeString(a.Auth)
			if err != nil {
				return auth.Credential{}, err
			}
			parts := strings.SplitN(string(decoded), ":", 2)
			if len(parts) != 2 {
				return auth.Credential{}, fmt.Errorf("invalid auth format for %s", host)
			}
			return auth.Credential{
				Username: parts[0],
				Password: parts[1],
			}, nil
		}
		return auth.Credential{}, fmt.Errorf("no credentials for host %s", host)
	})

	authClient := &auth.Client{
		Credential: credentialsFunc,
	}

	repo, err := remote.NewRepository(ref.String())
	if err != nil {
		return fmt.Errorf("failed to create repository object: %w", err)
	}
	repo.Client = authClient

	// Create custom copy options with concurrency = 1 for low bandwidth resilience
	opts := oras.DefaultCopyOptions
	opts.Concurrency = 1 // single-threaded fetch

	desc, err := oras.Copy(ctx, repo, ref.Reference, memoryStore, "", opts)
	if err != nil {
		// Check if unauthorized or not found by message
		errMsg := err.Error()
		if strings.Contains(strings.ToLower(errMsg), "unauthorized") || strings.Contains(strings.ToLower(errMsg), "forbidden") {
			return fmt.Errorf("access denied: the credentials provided do not have permission to access %s", ociArtifactURI)
		}
		if strings.Contains(strings.ToLower(errMsg), "not found") {
			return fmt.Errorf("the artifact %s was not found in the registry", ociArtifactURI)
		}
		return fmt.Errorf("oras pull failed: %w", err)
	}

	rc, err := memoryStore.Fetch(ctx, desc)
	if err != nil {
		return fmt.Errorf("failed to fetch manifest: %w", err)
	}
	defer rc.Close()

	manifestContent, err := io.ReadAll(rc)
	if err != nil {
		return fmt.Errorf("failed to read manifest: %w", err)
	}

	var manifest ocispec.Manifest
	if err := json.Unmarshal(manifestContent, &manifest); err != nil {
		return fmt.Errorf("failed to unmarshal manifest: %w", err)
	}

	// Validate that all media types in manifest are allowed
	if err := validateOCIMediaTypes(manifest); err != nil {
		return fmt.Errorf("media type validation failed: %w", err)
	}

	// Check for a valid artifact: must have config and at least one layer
	if manifest.Config.Size == 0 || len(manifest.Layers) == 0 {
		return fmt.Errorf("the artifact appears invalid: missing config or layers")
	}

	// Check total size of image
	var totalSize int64
	totalSize += manifest.Config.Size
	for _, layer := range manifest.Layers {
		totalSize += layer.Size
	}
	if totalSize > maxSizeBytes {
		return fmt.Errorf("image size %d bytes exceeds maximum allowed size of %d bytes", totalSize, maxSizeBytes)
	}

	ociManifestPath := filepath.Join(outputDir, "oci-manifest.json")
	if err := writeFile(ociManifestPath, manifestContent); err != nil {
		return fmt.Errorf("failed to write oci-manifest.json: %w", err)
	}

	// Fetch config
	configDesc := manifest.Config
	configRC, err := memoryStore.Fetch(ctx, configDesc)
	if err != nil {
		return fmt.Errorf("failed to fetch config: %w", err)
	}
	defer configRC.Close()
	configBytes, err := io.ReadAll(configRC)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	configPath := filepath.Join(outputDir, "config.json")
	if err := writeFile(configPath, configBytes); err != nil {
		return fmt.Errorf("failed to write config.json: %w", err)
	}

	// Fetch layers and write them out
	var layerFiles []string
	for i, layerDesc := range manifest.Layers {
		layerRC, err := memoryStore.Fetch(ctx, layerDesc)
		if err != nil {
			return fmt.Errorf("failed to fetch layer: %w", err)
		}
		layerBytes, err := io.ReadAll(layerRC)
		layerRC.Close()
		if err != nil {
			return fmt.Errorf("failed to read layer: %w", err)
		}
		layerFileName := fmt.Sprintf("layer%d.tar", i+1)
		layerPath := filepath.Join(outputDir, layerFileName)
		if err := writeFile(layerPath, layerBytes); err != nil {
			return fmt.Errorf("failed to write layer to disk: %w", err)
		}
		layerFiles = append(layerFiles, layerFileName)
	}

	repoTag := ref.String()
	dockerManifest := []map[string]interface{}{
		{
			"Config":   "config.json",
			"RepoTags": []string{repoTag},
			"Layers":   layerFiles,
		},
	}
	dockerManifestBytes, err := json.MarshalIndent(dockerManifest, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal docker manifest.json: %w", err)
	}
	manifestPath := filepath.Join(outputDir, "manifest.json")
	if err := writeFile(manifestPath, dockerManifestBytes); err != nil {
		return fmt.Errorf("failed to write manifest.json: %w", err)
	}

	// Create image.tar
	filesToTar := append([]string{"manifest.json", "config.json", "oci-manifest.json"}, layerFiles...)
	if err := createTar(filepath.Join(outputDir, "image.tar"), filesToTar, outputDir); err != nil {
		return fmt.Errorf("failed to create tar: %w", err)
	}

	// Remove manifest.json and oci-manifest.json after creating the tar
	if err := os.Remove(manifestPath); err != nil {
		return fmt.Errorf("failed to remove manifest.json: %w", err)
	}
	if err := os.Remove(ociManifestPath); err != nil {
		return fmt.Errorf("failed to remove oci-manifest.json: %w", err)
	}

	return nil
}

func validateOCIMediaTypes(manifest ocispec.Manifest) error {
	if !isAllowedMediaType(manifest.Config.MediaType) {
		return fmt.Errorf("config media type %q is not allowed", manifest.Config.MediaType)
	}
	for _, layer := range manifest.Layers {
		if !isAllowedMediaType(layer.MediaType) {
			return fmt.Errorf("layer media type %q is not allowed", layer.MediaType)
		}
	}
	return nil
}

func isAllowedMediaType(mt string) bool {
	for _, allowed := range AllowedMediaTypes {
		if mt == allowed {
			return true
		}
	}
	return false
}

func createTar(tarPath string, files []string, baseDir string) error {
	tarFile, err := os.Create(tarPath)
	if err != nil {
		return err
	}
	defer tarFile.Close()

	tw := tar.NewWriter(tarFile)
	defer tw.Close()

	for _, file := range files {
		fullPath := filepath.Join(baseDir, file)
		info, err := os.Stat(fullPath)
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", fullPath, err)
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return fmt.Errorf("failed to create tar header for %s: %w", fullPath, err)
		}
		header.Name = file
		if err := tw.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write header for %s: %w", fullPath, err)
		}
		fh, err := os.Open(fullPath)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", fullPath, err)
		}
		_, copyErr := io.Copy(tw, fh)
		fh.Close()
		if copyErr != nil {
			return fmt.Errorf("failed to copy file data for %s: %w", fullPath, copyErr)
		}
	}
	return nil
}

func mergeAuths(dst, src map[string]AuthConfig) {
	for k, v := range src {
		dst[k] = v
	}
}

// memoryStore is a global in-memory content store used for oras.Copy operations.
var memoryStore = memory.New()

// writeFile attempts to write data to the specified path, returning an error if it fails.
func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0644)
}

// cleanupIntermediateFiles removes intermediate files (manifest.json, oci-manifest.json, config.json, layer*.tar)
// from the output directory, if they exist.
func cleanupIntermediateFiles(outputDir string) {
	files, err := os.ReadDir(outputDir)
	if err != nil {
		return
	}
	for _, f := range files {
		name := f.Name()
		if name == "config.json" || name == "oci-manifest.json" || name == "manifest.json" ||
			(strings.HasPrefix(name, "layer") && strings.HasSuffix(name, ".tar")) {
			os.Remove(filepath.Join(outputDir, name))
		}
	}
}

// isNoSpaceError checks if the error message contains a known substring indicating no space left.
func isNoSpaceError(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "no space left on device")
}

func isAccessError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "access denied") || strings.Contains(msg, "unauthorized") || strings.Contains(msg, "forbidden") || strings.Contains(msg, "permission")
}

func isNotFoundError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "not found")
}
