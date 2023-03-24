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
	"golang.org/x/sys/unix"
)

// 计算offcputime
// 使用： offcputime [pid] [second]
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cflags "-I ../c/include" --target=amd64 -type key_t offcputime ../c/offcputime/offcputime.c
func main() {
	needTracePid, _ := strconv.ParseInt(os.Args[1], 10, 64)
	traceSecond, _ := strconv.ParseInt(os.Args[2], 10, 64)
	stopper := make(chan os.Signal, 2)
	signal.Notify(stopper, os.Interrupt, syscall.SIGTERM)

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := offcputimeObjects{}
	if err := loadOffcputimeObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %s", err)
	}
	defer objs.Close()

	kp, err := link.Kprobe("finish_task_switch.isra.0", objs.SchedSwitch, nil)
	if err != nil {
		log.Fatalf("kprobe error: %s", err)
	}
	defer kp.Close()

	bs := make([]byte, 4)
	binary.LittleEndian.PutUint32(bs, uint32(needTracePid))
	err = objs.ListenPidsMap.Put(bs, bs)
	if err != nil {
		log.Fatalf("write pid error")
		return
	}
	log.Println("offcpu is ready....")
	timer := time.NewTimer(time.Duration(traceSecond) * time.Second)

	<-timer.C
	log.Println("Received signal, read the map")

	var key offcputimeKeyT
	var total uint64
	iterate := objs.PidStackCounter.Iterate()
	kallsyms, _ := NewKallsyms()
	procsyscache, _ := NewProcsymsCache(uint32(needTracePid))
	for iterate.Next(&key, &total) {
		var stacksBuffer [127]uint64

		if err != nil {
			log.Fatalf("NewKallsyms error %s", err)
			return
		}
		name := unix.ByteSliceToString(key.Comm[:])
		print(name)
		printUserStacksById(&objs, uint32(key.UserStackId), stacksBuffer, procsyscache)
		print(";-")
		printKernelStacksById(&objs, uint32(key.KernelStackId), stacksBuffer, kallsyms)
		println(" " + strconv.FormatUint(total, 10))
	}

	if err := kp.Close(); err != nil {
		log.Fatalf("closing perf event reader: %s", err)
	}
}

func printKernelStacksById(objs *offcputimeObjects, stackId uint32, stacksBuffer [127]uint64, kallsyms *Kallsyms) {
	err := objs.StackTraces.Lookup(stackId, &stacksBuffer)
	if err != nil {
		log.Printf("lookup kernel stack error: stackId: %s err: %s", stackId, err)
		return
	}
	size := len(stacksBuffer)
	for i := range stacksBuffer {
		symbol := stacksBuffer[size-i-1]
		if symbol == 0 {
			continue
		}
		print(";" + kallsyms.get(symbol).name)
	}
}

func printUserStacksById(objs *offcputimeObjects, stackId uint32, stacksBuffer [127]uint64, procsyscache *ProcsymsCache) {
	err := objs.StackTraces.Lookup(stackId, &stacksBuffer)
	if err != nil {
		log.Printf("lookup user stack error: stackId: %s err: %s", stackId, err)
		return
	}
	size := len(stacksBuffer)
	for i := range stacksBuffer {
		symbol := stacksBuffer[size-i-1]
		if symbol == 0 {
			continue
		}
		name := procsyscache.search(symbol)
		print(";" + name)
	}
}
