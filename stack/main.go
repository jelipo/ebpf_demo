// github.com/bigwhite/experiments/ebpf-examples/helloworld-go/main.go
package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -type key_t stack ../c/stack/stack.c
func main() {
	stopper := make(chan os.Signal, 1)
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

	kp, err := link.Kprobe("finish_task_switch", objs.Oncpu, nil)
	if err != nil {
		log.Fatalf("kprobe error: %s", err)
	}
	defer kp.Close()

	var need_trace_pid uint32 = 1
	err = objs.StackPidsMap.Put(need_trace_pid, nil)
	if err != nil {
		log.Fatalf("put tarce pid to map error: %s", err)
		return
	}

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("creating perf event reader: %s", err)
	}

	go func() {
		// Wait for a signal and close the perf reader,
		// which will interrupt rd.Read() and make the program exit.
		<-stopper
		log.Println("Received signal, exiting program........................................................")

		// 关闭reader
		err := reader.Close()
		if err != nil {
			log.Fatalf("closing reader: %s", err)
		}

		if err := kp.Close(); err != nil {
			log.Fatalf("closing perf event reader: %s", err)
		}
	}()

	var stackKey stackKeyT
	for true {
		record, err := reader.Read()
		if err != nil {
			return
		}
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &stackKey); err != nil {
			log.Printf("parsing perf event: %s", err)
			continue
		}
		println("name:" + unix.ByteSliceToString(stackKey.Name[:]) + " pid:" + strconv.Itoa(int(stackKey.Pid)))

	}
}

func printStacksById(objs *stackObjects, stackId uint64, stacksBuffer [127]uint64) {
	err := objs.StackTraces.Lookup(stackId, &stacksBuffer)
	if err != nil {
		log.Printf("lookup stack error: %s", err)
		return
	}
	for i, stack := range stacksBuffer {
		unix.KeyctlSearch()
	}
}
