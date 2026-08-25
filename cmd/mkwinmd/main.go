// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command mkwinmd runs the pinned go-winmd generator with Win32 metadata from NuGet.
package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	goWinMDModule       = "github.com/microsoft/go-winmd"
	goWinMDVersion      = "v0.0.0-20260825131323-f8f72ba7b114"
	metadataPackage     = "Microsoft.Windows.SDK.Win32Metadata"
	metadataVersion     = "71.0.20-preview"
	metadataURL         = "https://www.nuget.org/api/v2/package/" + metadataPackage + "/" + metadataVersion
	metadataSHA256      = "64e7d92c8e08780570d5d1ce954d03f73e162f13e9b03fc5bb98f44edef26b9e"
	metadataArchivePath = "Windows.Win32.winmd"
)

func main() {
	goTool, err := exec.LookPath("go")
	if err != nil {
		log.Fatal(err)
	}
	source := downloadMetadata()

	args := []string{"run", goWinMDModule + "/cmd/gowinmd@" + goWinMDVersion, "-source", source}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(goTool, args...)
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func downloadMetadata() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		log.Fatal(err)
	}
	path := filepath.Join(cacheDir, "go-crypto-winnative", metadataPackage, metadataVersion, metadataArchivePath)
	if data, err := os.ReadFile(path); err == nil && fmt.Sprintf("%x", sha256.Sum256(data)) == metadataSHA256 {
		return path
	}

	response, err := http.Get(metadataURL)
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		log.Fatalf("download %s: %s", metadataURL, response.Status)
	}
	packageData, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	archive, err := zip.NewReader(bytes.NewReader(packageData), int64(len(packageData)))
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range archive.File {
		if file.Name != metadataArchivePath {
			continue
		}
		metadata, err := readZipFile(file)
		if err != nil {
			log.Fatal(err)
		}
		if checksum := fmt.Sprintf("%x", sha256.Sum256(metadata)); checksum != metadataSHA256 {
			log.Fatalf("unexpected %s checksum: got %s, want %s", metadataArchivePath, checksum, metadataSHA256)
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Fatal(err)
		}
		if err := os.WriteFile(path, metadata, 0o644); err != nil {
			log.Fatal(err)
		}
		return path
	}
	log.Fatalf("%s not found in %s %s", metadataArchivePath, metadataPackage, metadataVersion)
	return ""
}

func readZipFile(file *zip.File) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	return io.ReadAll(reader)
}
