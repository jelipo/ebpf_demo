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

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go --target=amd64 -type key_t stack ../c/stack/stack.c
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

	kp, err := link.Kprobe("finish_task_switch.isra.0", objs.SchedSwitch, nil)
	if err != nil {
		log.Fatalf("kprobe error: %s", err)
	}
	defer kp.Close()
	need_trace_pid, _ := strconv.ParseInt(listenPid, 10, 64)

	_, _ = NewProcsymsCache(uint32(need_trace_pid))

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
	kallsyms, err := NewKallsyms()
	for iterate.Next(&key, &total) {
		var stacksBuffer [127]uint64

		if err != nil {
			log.Fatalf("NewKallsyms error %s", err)
			return
		}
		printUserStacksById(&objs, uint32(key.UserStackId), stacksBuffer)
		print("-;")
		printKernelStacksById(&objs, uint32(key.KernelStackId), stacksBuffer, kallsyms)
		println(" " + strconv.FormatUint(total, 10))
	}

	if err := kp.Close(); err != nil {
		log.Fatalf("closing perf event reader: %s", err)
	}
}

func printKernelStacksById(objs *stackObjects, stackId uint32, stacksBuffer [127]uint64, kallsyms *Kallsyms) {
	err := objs.StackTraces.Lookup(stackId, &stacksBuffer)
	if err != nil {
		log.Printf("lookup kernel stack error: stackId: %s err: %s", stackId, err)
		return
	}
	for _, stack := range stacksBuffer {
		if stack == 0 {
			continue
		}
		print(kallsyms.get(stack).name + ";")
	}
}

func printUserStacksById(objs *stackObjects, stackId uint32, stacksBuffer [127]uint64) {
	err := objs.StackTraces.Lookup(stackId, &stacksBuffer)
	if err != nil {
		log.Printf("lookup user stack error: stackId: %s err: %s", stackId, err)
		return
	}
	for _, symbolAddr := range stacksBuffer {
		if symbolAddr == 0 {
			continue
		}
		print(strconv.FormatUint(symbolAddr, 16) + ";")
	}
}
