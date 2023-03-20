// github.com/bigwhite/experiments/ebpf-examples/helloworld-go/main.go
package main

import (
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type key_t stack ../c/stack/stack.c
func main() {
	listenPid := os.Args[1]
	stopper := make(chan os.Signal, 2)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := stackObjects{}
	if err := loadStackObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kp, err := link.Tracepoint("sched", "sched_switch", objs.SchedSwitch, nil)
	if err != nil {
		log.Fatalf("kprobe error: %s", err)
	}
	defer kp.Close()
	need_trace_pid, _ := strconv.ParseInt(listenPid, 10, 64)
	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(need_trace_pid))
	err = objs.ListenPidsMap.Put(bs, bs)
	if err != nil {
		log.Fatalf("write pid error")
		return
	}
	log.Println("offcpu is ready....")

	timer := time.NewTimer(10 * time.Second)

	<-timer.C
	log.Println("Received signal, read the map")

	var key stackKeyT
	var total uint64
	iterate := objs.PidStackCounter.Iterate()
	for iterate.Next(&key, &total) {
		println("userStackId: " + strconv.FormatUint(key.UserStackId, 10) +
			"    kernelStackId: " + strconv.FormatUint(key.KernelStackId, 10) +
			"    total:" + strconv.FormatUint(total/1000, 10) + "ms")
		var stacksBuffer [127]uint64

		kallsyms, err := NewKallsyms()
		if err != nil {
			log.Fatalf("NewKallsyms error %s", err)
			return
		}
		printStacksById(&objs, uint32(key.KernelStackId), stacksBuffer, kallsyms)
		//printStacksById(&objs, uint32(key.UserStackId), stacksBuffer, kallsyms)
	}

	if err := kp.Close(); err != nil {
		log.Fatalf("closing perf event reader: %s", err)
	}
}

func printStacksById(objs *stackObjects, stackId uint32, stacksBuffer [127]uint64, kallsyms *Kallsyms) {
	err := objs.StackTraces.Lookup(stackId, &stacksBuffer)
	if err != nil {
		log.Printf("lookup stack error: stackId: %s err: %s", stackId, err)
		return
	}
	for _, stack := range stacksBuffer {
		if stack == 0 {
			continue
		}
		print(kallsyms.get(stack).name + " ")
	}
	println("")
}
