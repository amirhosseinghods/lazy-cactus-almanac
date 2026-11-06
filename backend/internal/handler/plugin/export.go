package plugin

import "nasnet-panel/pkg/routeros"

// Helpers other handler packages (V2Ray clients, DNS leak guard) run plugin-style containers with.
const (
	ContainersBridge    = pluginContainersBridge
	InstallTimeout      = pluginInstallTimeout
	InstallPollInterval = pluginInstallPollInterval
)

func StoragePrefix(client *routeros.Client) string { return pluginStoragePrefix(client) }

func PrepareVolumeDir(client *routeros.Client, pluginID, src string) (string, error) {
	return preparePluginVolumeDir(client, pluginID, src)
}

func RemoveVolumeDir(client *routeros.Client, pluginID string) (string, error) {
	return removePluginVolumeDir(client, pluginID)
}

func JoinEnvPairs(env map[string]string) string { return joinEnvPairs(env) }
