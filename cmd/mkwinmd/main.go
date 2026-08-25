// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command mkwinmd runs the pinned go-winmd generator with Win32 metadata from NuGet.
package main

import (
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	goWinMDModule       = "github.com/microsoft/go-winmd"
	goWinMDVersion      = "v0.0.0-20260825140017-369639105e55"
	metadataPackage     = "Microsoft.Windows.SDK.Win32Metadata"
	metadataVersion     = "71.0.20-preview"
	metadataArchivePath = "Windows.Win32.winmd"
)

func main() {
	goTool, err := exec.LookPath("go")
	if err != nil {
		log.Fatal(err)
	}
	source := downloadMetadata(goTool)

	args := []string{"run", goWinMDModule + "/cmd/gowinmd@" + goWinMDVersion, "-source", source}
	args = append(args, os.Args[1:]...)
	runGo(goTool, args...)
}

func downloadMetadata(goTool string) string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(cacheDir, "go-crypto-winnative", metadataPackage, metadataVersion, metadataArchivePath)
	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		return path
	}

	runGo(goTool,
		"run", goWinMDModule+"/cmd/getwinmd@"+goWinMDVersion,
		"-version", metadataVersion,
		"-output", path,
	)
	return path
}

func runGo(goTool string, args ...string) {
	cmd := exec.Command(goTool, args...)
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
