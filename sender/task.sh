#!/bin/bash

curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

syft ghcr.io/opengovern/steampipe-plugin-aws:v0.1.6 --scope all-layers -o syft-text
syft ghcr.io/opengovern/steampipe-plugin-azure:v0.1.7 --scope all-layers -o syft-text
syft ghcr.io/opengovern/steampipe-plugin-entraid:v0.2.2 --scope all-layers -o syft-text
syft ghcr.io/opengovern/steampipe-plugin-opengovernance:v0.465.10 --scope all-layers -o syft-text
syft ghcr.io/opengovern/inventory-service:v0.512.18 --scope all-layers -o syft-text
syft ghcr.io/opengovern/integration:v0.512.14 --scope all-layers -o syft-text
syft ghcr.io/opengovern/compliance-service:v0.512.18 --scope all-layers -o syft-text
syft ghcr.io/opengovern/metadata-service:v0.508.5 --scope all-layers -o syft-text
syft ghcr.io/opengovern/steampipe-plugin-digitalocean:v0.0.7 --scope all-layers -o syft-text
syft ghcr.io/opengovern/auth-service:v0.508.3 --scope all-layers -o syft-text
syft ghcr.io/opengovern/describe-scheduler:v0.466.1 --scope all-layers -o syft-text
syft ghcr.io/opengovern/steampipe-plugin-cloudflare:v0.4.0 --scope all-layers -o syft-text
syft ghcr.io/opengovern/compliance-report-worker:v0.466.4 --scope all-layers -o syft-text
syft ghcr.io/opengovern/compliance-summarizer:v0.465.10 --scope all-layers -o syft-text
syft ghcr.io/opengovern/import-data-script:v0.512.15 --scope all-layers -o syft-text
syft ghcr.io/opengovern/steampipe-plugin-openai:v0.1.11 --scope all-layers -o syft-text
syft ghcr.io/opengovern/query-runner-worker:v0.466.4 --scope all-layers -o syft-text
syft ghcr.io/opengovern/steampipe-plugin-cohereai:v0.3.1 --scope all-layers -o syft-text
syft ghcr.io/opengovern/checkup-worker:v0.465.10 --scope all-layers -o syft-text
syft ghcr.io/opengovern/compliance-report-job:v0.512.19 --scope all-layers -o syft-text
syft ghcr.io/opengovern/post-install-job:v0.512.18 --scope all-layers -o syft-text
syft ghcr.io/opengovern/describe-scheduler-service:v0.503.18 --scope all-layers -o syft-text
syft ghcr.io/opengovern/og-describer-cohereai:local-v0.3.1 --scope all-layers -o syft-text
syft ghcr.io/opengovern/og-describer-linode:local-v0.2.0 --scope all-layers -o syft-text

