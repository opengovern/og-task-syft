package main

import (
	"github.com/opengovern/og-task-syft/cloudql/syft"
	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{PluginFunc: syft.Plugin})
}
