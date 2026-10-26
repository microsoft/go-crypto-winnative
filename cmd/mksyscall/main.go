// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const mkwinsyscallVersion = "v0.37.0"

const description = `
Example:

  go run ./cmd/mksyscall -output zsyscall_windows.go bcrypt_windows.go

mksyscall wraps golang.org/x/sys/windows/mkwinsyscall and runs it as if
it was generating syscalls for the standard library. This avoids a dependency
with golang.org/x/sys, which would difficult integrating go-crypto-winnative
into the standard library.
`

var output = flag.String("output", "", "output file name (standard output if omitted)")

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "\nUsage:\n")
		flag.PrintDefaults()
		fmt.Fprintf(flag.CommandLine.Output(), "%s\n\n", description)
	}
	flag.Parse()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")

	listCmd := exec.Command(goTool, "list", "-m")
	listCmd.Env = append(os.Environ(), "GO111MODULE=on")

	out, err := listCmd.Output()
	if err != nil || string(bytes.TrimSpace(out)) != "github.com/microsoft/go-crypto-winnative" {
		// Nobody outside go-crypto-winnative should be using this wrapper.
		log.Fatal("WARNING: Please switch from using:\n    go run ./cmd/mksyscall\nto using:\n    go run golang.org/x/sys/windows/mkwinsyscall\n")
	}

	install(goTool)
	zsys := generateSyscalls()

	if *output == "" {
		os.Stdout.Write(zsys)
	} else {
		err = os.WriteFile(*output, zsys, 0o666)
		if err != nil {
			log.Fatal(err)
		}
	}
}

// install makes sure mkwinsyscall can be called by
// running go install golang.org/x/sys/windows/mkwinsyscall.
func install(goTool string) {
	// mkwinsyscall is hardcoded here instead of adding it to go.mod so
	// it doesn't appear in go.sum, which will reduce the likelihood
	// of having patch conflicts when vendoring go-crypto-winnative.
	args := []string{"install", "golang.org/x/sys/windows/mkwinsyscall@" + mkwinsyscallVersion}
	cmd := exec.Command(goTool, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "GO111MODULE=on")
	err := cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
}

// generateSyscalls runs mkwinsyscall with GOROOT set to the current working directory.
// This fools mkwinsyscall into believing it is generating syscalls for the standard library.
// When this happens, mkwinsyscall doesn't import "golang.org/x/sys/windows" but
// "syscall" and "internal/syscall/windows/sysdll". This last import is used
// to avoid DLL preloading attacks. As sysdll is a std internal package, this function
// replaces the generated code's sysdll import with our own version located at
// "./internal/sysdll".
func generateSyscalls() []byte {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	args := flag.Args()
	// We have intercepted the output argument, so we can be sure
	// that mkwinsyscall will emit the generated file to the standard output.
	cmd := exec.Command("mkwinsyscall", args...)
	var bout bytes.Buffer
	cmd.Stdout = &bout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "GOROOT="+wd)
	err = cmd.Run()
	if err != nil {
		log.Fatal(err)
	}
	zsys := bout.Bytes()
	zsys = bytes.ReplaceAll(zsys, []byte("\"internal/syscall/windows/sysdll\""), []byte("\"github.com/microsoft/go-crypto-winnative/internal/sysdll\""))
	zsys = bytes.ReplaceAll(zsys, []byte("windows.NTStatus"), []byte("NTStatus"))
	zsys, err = addBufferSizeChecks(zsys)
	if err != nil {
		log.Fatal(err)
	}

	return zsys
}

func addBufferSizeChecks(src []byte) ([]byte, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "", src, parser.ParseComments)
	if err != nil {
		return nil, err
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		var sizes []ast.Expr
		for _, param := range fn.Type.Params.List {
			slice, ok := param.Type.(*ast.ArrayType)
			if !ok || slice.Len != nil {
				continue
			}
			for _, name := range param.Names {
				sizes = append(sizes, &ast.CallExpr{
					Fun:  ast.NewIdent("len"),
					Args: []ast.Expr{ast.NewIdent(name.Name)},
				})
			}
		}
		if len(sizes) == 0 {
			continue
		}
		var result string
		if fn.Type.Results != nil {
			for _, field := range fn.Type.Results.List {
				typ, ok := field.Type.(*ast.Ident)
				if ok && typ.Name == "error" && len(field.Names) == 1 {
					result = field.Names[0].Name
				}
			}
		}
		if result == "" {
			return nil, fmt.Errorf("%s has slice parameters but no named error result", fn.Name.Name)
		}
		check := &ast.IfStmt{
			Init: &ast.AssignStmt{
				Lhs: []ast.Expr{ast.NewIdent(result)},
				Tok: token.ASSIGN,
				Rhs: []ast.Expr{&ast.CallExpr{
					Fun:  ast.NewIdent("CheckBufferSizes"),
					Args: sizes,
				}},
			},
			Cond: &ast.BinaryExpr{
				X:  ast.NewIdent(result),
				Op: token.NEQ,
				Y:  ast.NewIdent("nil"),
			},
			Body: &ast.BlockStmt{List: []ast.Stmt{&ast.ReturnStmt{}}},
		}
		fn.Body.List = append([]ast.Stmt{check}, fn.Body.List...)
	}
	var out bytes.Buffer
	if err := format.Node(&out, fset, file); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
