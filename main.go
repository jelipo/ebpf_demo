// github.com/bigwhite/experiments/ebpf-examples/helloworld-go/main.go
package main

import (
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"log"
	"os"
	"os/signal"
	"syscall"
)

//go:generate bpf2go hello c/hello_kern.c
func main() {
	stopper := make(chan os.Signal, 1)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := helloObjects{}
	if err := loadHelloObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	reader, err := perf.NewReader(objs.Event, os.Getpagesize())
	if err != nil {
		return
	}
	defer reader.Close()
	for true {
		record, err := reader.Read()
		if err != nil {
			log.Fatalf("read failed: %s", err)
			return
		}
		println("get : " + string(record.RawSample))
	}
}
