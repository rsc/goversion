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
package main // import "rsc.io/goversion"

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
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
	syms, err := f.Symbols()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: reading symbols: %v\n", file, err)
		return
	}
	var (
		isGo           = false
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
		if name == "runtime.buildVersion" {
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

type Sym struct {
	Name string
	Addr uint64
	Size uint64
}

type Exe interface {
	AddrSize() int // bytes
	ReadData(addr, size uint64) ([]byte, error)
	Symbols() ([]Sym, error)
	SectionNames() []string
	Close() error
	ByteOrder() binary.ByteOrder
}

func openExe(file string) (Exe, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	data := make([]byte, 16)
	if _, err := io.ReadFull(f, data); err != nil {
		return nil, err
	}
	f.Seek(0, 0)
	if bytes.HasPrefix(data, []byte("\x7FELF")) {
		e, err := elf.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &elfExe{f, e}, nil
	}
	if bytes.HasPrefix(data, []byte("MZ")) {
		e, err := pe.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &peExe{f, e}, nil
	}
	if bytes.HasPrefix(data, []byte("\xFE\xED\xFA")) || bytes.HasPrefix(data[1:], []byte("\xFA\xED\xFE")) {
		e, err := macho.NewFile(f)
		if err != nil {
			f.Close()
			return nil, err
		}
		return &machoExe{f, e}, nil
	}
	return nil, fmt.Errorf("unrecognized executable format")
}

type elfExe struct {
	os *os.File
	f  *elf.File
}

func (x *elfExe) AddrSize() int { return 0 }

func (x *elfExe) ByteOrder() binary.ByteOrder { return x.f.ByteOrder }

func (x *elfExe) Close() error {
	return x.os.Close()
}

func (x *elfExe) ReadData(addr, size uint64) ([]byte, error) {
	data := make([]byte, size)
	for _, prog := range x.f.Progs {
		if prog.Vaddr <= addr && addr+size-1 <= prog.Vaddr+prog.Filesz-1 {
			_, err := prog.ReadAt(data, int64(addr-prog.Vaddr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *elfExe) Symbols() ([]Sym, error) {
	syms, err := x.f.Symbols()
	if err != nil {
		return nil, err
	}
	var out []Sym
	for _, sym := range syms {
		out = append(out, Sym{sym.Name, sym.Value, sym.Size})
	}
	return out, nil
}

func (x *elfExe) SectionNames() []string {
	var names []string
	for _, sect := range x.f.Sections {
		names = append(names, sect.Name)
	}
	return names
}

type peExe struct {
	os *os.File
	f  *pe.File
}

func (x *peExe) imageBase() uint64 {
	switch oh := x.f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return uint64(oh.ImageBase)
	case *pe.OptionalHeader64:
		return oh.ImageBase
	}
	return 0
}

func (x *peExe) AddrSize() int {
	if x.f.Machine == pe.IMAGE_FILE_MACHINE_AMD64 {
		return 8
	}
	return 4
}

func (x *peExe) ByteOrder() binary.ByteOrder { return binary.LittleEndian }

func (x *peExe) Close() error {
	return x.os.Close()
}

func (x *peExe) ReadData(addr, size uint64) ([]byte, error) {
	addr -= x.imageBase()
	data := make([]byte, size)
	for _, sect := range x.f.Sections {
		if uint64(sect.VirtualAddress) <= addr && addr+size-1 <= uint64(sect.VirtualAddress+sect.Size-1) {
			_, err := sect.ReadAt(data, int64(addr-uint64(sect.VirtualAddress)))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *peExe) Symbols() ([]Sym, error) {
	base := x.imageBase()
	var out []Sym
	for _, sym := range x.f.Symbols {
		if sym.SectionNumber <= 0 || int(sym.SectionNumber) > len(x.f.Sections) {
			continue
		}
		sect := x.f.Sections[sym.SectionNumber-1]
		out = append(out, Sym{sym.Name, uint64(sym.Value) + base + uint64(sect.VirtualAddress), 0})
	}
	return out, nil
}

func (x *peExe) SectionNames() []string {
	var names []string
	for _, sect := range x.f.Sections {
		names = append(names, sect.Name)
	}
	return names
}

type machoExe struct {
	os *os.File
	f  *macho.File
}

func (x *machoExe) AddrSize() int {
	if x.f.Cpu&0x01000000 != 0 {
		return 8
	}
	return 4
}

func (x *machoExe) ByteOrder() binary.ByteOrder { return x.f.ByteOrder }

func (x *machoExe) Close() error {
	return x.os.Close()
}

func (x *machoExe) ReadData(addr, size uint64) ([]byte, error) {
	data := make([]byte, size)
	for _, load := range x.f.Loads {
		seg, ok := load.(*macho.Segment)
		if !ok {
			continue
		}
		if seg.Addr <= addr && addr+size-1 <= seg.Addr+seg.Filesz-1 {
			if seg.Name == "__PAGEZERO" {
				continue
			}
			_, err := seg.ReadAt(data, int64(addr-seg.Addr))
			if err != nil {
				return nil, err
			}
			return data, nil
		}
	}
	return nil, fmt.Errorf("address not mapped")
}

func (x *machoExe) Symbols() ([]Sym, error) {
	var out []Sym
	for _, sym := range x.f.Symtab.Syms {
		out = append(out, Sym{sym.Name, sym.Value, 0})
	}
	return out, nil
}

func (x *machoExe) SectionNames() []string {
	var names []string
	for _, sect := range x.f.Sections {
		names = append(names, sect.Name)
	}
	return names
}
