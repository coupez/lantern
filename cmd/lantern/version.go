package main

import "runtime/debug"

func buildVersion() string {
	info, _ := debug.ReadBuildInfo()
	return versionLabel(version, info)
}
func versionLabel(override string, info *debug.BuildInfo) string {
	if override != "" {
		return override
	}
	if info != nil && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "0.1.0-dev"
}
