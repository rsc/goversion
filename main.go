// Copyright 2017 The Go Authors. All Rights Reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Goversion scans a directory tree and, for every executable it finds,
// prints the Go version used to build that executable.
//
// Usage:
//
//	goversion [-crypto] [-v] path...
//
// The list of paths can be individual files or directories; if the latter,
// goversion scans all files in the directory tree, not following symlinks.
//
// Goversion scans inside of tar or gzipped tar archives that it finds
// (named *.tar, *.tar.gz, or *.tgz), but not recursively.
//
// The -crypto flag causes goversion to print additional information
// about the crypto libraries linked into each executable.
//
// The -v flag causes goversion to print information about every
// file it considers.
//
// Example
//
// Scan /usr/bin for Go binaries and print their versions:
//
//	$ goversion /usr/bin
//	/usr/bin/containerd go1.7.4
//	/usr/bin/containerd-shim go1.7.4
//	/usr/bin/ctr go1.7.4
//	/usr/bin/docker go1.7.4
//	/usr/bin/docker-proxy go1.7.4
//	/usr/bin/dockerd go1.7.4
//	/usr/bin/kbfsfuse go1.8.3
//	/usr/bin/kbnm go1.8.3
//	/usr/bin/keybase go1.8.3
//	/usr/bin/snap go1.7.4
//	/usr/bin/snapctl go1.7.4
//
package main // import "rsc.io/goversion"

import (
	"archive/tar"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
)

var (
	crypto  = flag.Bool("crypto", false, "check kind of crypto library")
	verbose = flag.Bool("v", false, "print verbose information")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage: goversion [-crypto] [-v] path...\n")
	flag.PrintDefaults()
	os.Exit(2)
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("goversion: ")
	flag.Usage = usage
	flag.Parse()
	if flag.NArg() == 0 {
		usage()
	}

	for _, file := range flag.Args() {
		info, err := os.Stat(file)
		if err != nil {
			log.Print(err)
			continue
		}
		if info.IsDir() {
			scandir(file)
		} else {
			scanfile(file, file, info, true)
		}
	}
}

func scandir(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if info.Mode().IsRegular() {
			scanfile(path, path, info, *verbose)
		}
		return nil
	})
}

func scanfile(file, diskFile string, info os.FileInfo, mustPrint bool) {
	if strings.HasSuffix(file, ".tar") {
		if file != diskFile {
			fmt.Fprintf(os.Stderr, "%s: not scanning tar recursively\n", file)
			return
		}
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: scanning tar archive\n", file)
		}
		scantar(file, info)
		return
	}
	if strings.HasSuffix(file, ".tar.gz") || strings.HasSuffix(file, ".tgz") {
		if file != diskFile {
			fmt.Fprintf(os.Stderr, "%s: not scanning tgz recursively\n", file)
			return
		}
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: scanning tgz archive\n", file)
		}
		scantar(file, info)
		return
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: symlink\n", file)
		}
		return
	}
	if file == diskFile && info.Mode()&0111 == 0 {
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: not executable\n", file)
		}
		return
	}
	f, err := openExe(diskFile)
	if err != nil {
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
		}
		return
	}
	defer f.Close()
	syms, symsErr := f.Symbols()
	var (
		isGo           = false
		isGccgo        = false
		buildVersion   = ""
		boringCrypto   = false
		standardCrypto = false
	)
	for _, name := range f.SectionNames() {
		if name == ".note.go.buildid" {
			isGo = true
		}
	}
	for _, sym := range syms {
		name := sym.Name
		if name == "runtime.main" || name == "main.main" {
			isGo = true
		}
		if strings.HasPrefix(name, "runtime.") && strings.HasSuffix(name, "$descriptor") {
			isGccgo = true
		}
		if name == "runtime.buildVersion" {
			isGo = true
			v, err := readBuildVersion(f, sym.Addr, sym.Size)
			if err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
				return
			}
			buildVersion = v
		}
		if strings.Contains(name, "_Cfunc__goboringcrypto_") {
			boringCrypto = true
		}
		for _, s := range standardCryptoNames {
			if strings.Contains(name, s) {
				standardCrypto = true
			}
		}
	}

	if *debugMatch {
		buildVersion = ""
	}
	if buildVersion == "" {
		g, v := readBuildVersionX86Asm(f)
		if g {
			isGo = true
			buildVersion = v
		}
	}
	if isGccgo && buildVersion == "" {
		isGo = true
		buildVersion = "gccgo (version unknown)"
	}
	if !isGo && symsErr != nil {
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: reading symbols: %v\n", file, symsErr)
		}
		return
	}

	if !isGo {
		if mustPrint {
			fmt.Fprintf(os.Stderr, "%s: not a Go executable\n", file)
		}
		return
	}
	if buildVersion == "" {
		buildVersion = "unknown Go version"
	}
	if *crypto {
		switch {
		case boringCrypto && standardCrypto:
			buildVersion += " (boring AND standard crypto!!!)"
		case boringCrypto:
			buildVersion += " (boring crypto)"
		case standardCrypto:
			buildVersion += " (standard crypto)"
		}
	}

	fmt.Printf("%s %s\n", file, buildVersion)
}

func scantar(file string, info os.FileInfo) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
		return
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(file, "z") {
		z, err := gzip.NewReader(r)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", file, err)
			return
		}
		defer z.Close()
		r = z
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if hdr.Typeflag != tar.TypeReg {
			if *verbose {
				fmt.Fprintf(os.Stderr, "%s/%s: not regular file\n", file, hdr.Name)
			}
			continue
		}
		if hdr.Mode&0111 == 0 {
			if *verbose {
				fmt.Fprintf(os.Stderr, "%s/%s: not executable\n", file, hdr.Name)
			}
			continue
		}

		// executable but not special
		tmp, err := ioutil.TempFile("", "goversion-")
		if err != nil {
			log.Fatal(err)
		}
		io.Copy(tmp, tr)
		tmpName := tmp.Name()
		info, err := tmp.Stat()
		if err != nil {
			log.Fatal(err)
		}
		tmp.Close()
		scanfile(file+"/"+hdr.Name, tmpName, info, *verbose)
		os.Remove(tmpName)
	}
}

var standardCryptoNames = []string{
	"crypto/sha1.(*digest)",
	"crypto/sha256.(*digest)",
	"crypto/rand.(*devReader)",
	"crypto/rsa.encrypt",
	"crypto/rsa.decrypt",
}

func readBuildVersion(f Exe, addr, size uint64) (string, error) {
	if size == 0 {
		size = uint64(f.AddrSize() * 2)
	}
	if size != 8 && size != 16 {
		return "", fmt.Errorf("invalid size for runtime.buildVersion")
	}
	data, err := f.ReadData(addr, size)
	if err != nil {
		return "", fmt.Errorf("reading runtime.buildVersion: %v", err)
	}

	if size == 8 {
		addr = uint64(f.ByteOrder().Uint32(data))
		size = uint64(f.ByteOrder().Uint32(data[4:]))
	} else {
		addr = f.ByteOrder().Uint64(data)
		size = f.ByteOrder().Uint64(data[8:])
	}
	if size > 1000 {
		return "", fmt.Errorf("implausible string size %d for runtime.buildVersion", size)
	}

	data, err = f.ReadData(addr, size)
	if err != nil {
		return "", fmt.Errorf("reading runtime.buildVersion string data: %v", err)
	}
	return string(data), nil
}
