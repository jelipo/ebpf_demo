// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type helloStringkey [64]int8

// loadHello returns the embedded CollectionSpec for hello.
func loadHello() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_HelloBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load hello: %w", err)
	}

	return spec, err
}

// loadHelloObjects loads hello and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*helloObjects
//	*helloPrograms
//	*helloMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadHelloObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadHello()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// helloSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type helloSpecs struct {
	helloProgramSpecs
	helloMapSpecs
}

// helloSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type helloProgramSpecs struct {
	BpfProg *ebpf.ProgramSpec `ebpf:"bpf_prog"`
}

// helloMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type helloMapSpecs struct {
	ExecveCounter *ebpf.MapSpec `ebpf:"execve_counter"`
	MyMap         *ebpf.MapSpec `ebpf:"my_map"`
}

// helloObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadHelloObjects or ebpf.CollectionSpec.LoadAndAssign.
type helloObjects struct {
	helloPrograms
	helloMaps
}

func (o *helloObjects) Close() error {
	return _HelloClose(
		&o.helloPrograms,
		&o.helloMaps,
	)
}

// helloMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadHelloObjects or ebpf.CollectionSpec.LoadAndAssign.
type helloMaps struct {
	ExecveCounter *ebpf.Map `ebpf:"execve_counter"`
	MyMap         *ebpf.Map `ebpf:"my_map"`
}

func (m *helloMaps) Close() error {
	return _HelloClose(
		m.ExecveCounter,
		m.MyMap,
	)
}

// helloPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHelloObjects or ebpf.CollectionSpec.LoadAndAssign.
type helloPrograms struct {
	BpfProg *ebpf.Program `ebpf:"bpf_prog"`
}

func (p *helloPrograms) Close() error {
	return _HelloClose(
		p.BpfProg,
	)
}

func _HelloClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed hello_bpfel.o
var _HelloBytes []byte
