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
	BpfCaptureExec *ebpf.ProgramSpec `ebpf:"bpf_capture_exec"`
}

// helloMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type helloMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
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
	Events *ebpf.Map `ebpf:"events"`
}

func (m *helloMaps) Close() error {
	return _HelloClose(
		m.Events,
	)
}

// helloPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadHelloObjects or ebpf.CollectionSpec.LoadAndAssign.
type helloPrograms struct {
	BpfCaptureExec *ebpf.Program `ebpf:"bpf_capture_exec"`
}

func (p *helloPrograms) Close() error {
	return _HelloClose(
		p.BpfCaptureExec,
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
