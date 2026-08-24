// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Command mkwinmd runs the pinned go-winmd generator with its bundled Win32 metadata.
package main

import (
	"encoding/json"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	goWinMDModule  = "github.com/microsoft/go-winmd"
	goWinMDVersion = "v0.0.0-20260805212740-c29d37683275"
)

func main() {
	goTool, err := exec.LookPath("go")
	if err != nil {
		log.Fatal(err)
	}
	moduleDir := downloadModule(goTool)
	source := filepath.Join(moduleDir, "winmd", "testdata", "Windows.Win32.winmd")

	args := []string{"run", goWinMDModule + "/cmd/gowinmd@" + goWinMDVersion, "-source", source}
	args = append(args, os.Args[1:]...)
	cmd := exec.Command(goTool, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}

func downloadModule(goTool string) string {
	cmd := exec.Command(goTool, "mod", "download", "-json", goWinMDModule+"@"+goWinMDVersion)
	output, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}

	var module struct {
		Dir   string
		Error *struct{ Err string }
	}
	if err := json.Unmarshal(output, &module); err != nil {
		log.Fatal(err)
	}
	if module.Error != nil {
		log.Fatal(module.Error.Err)
	}
	if module.Dir == "" {
		log.Fatal("go-winmd module directory is missing")
	}
	return module.Dir
}
