package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sort"
)

type Ksym struct {
	addr uint64
	name string
}

type Kallsyms struct {
	syms []Ksym
}

func NewKallsyms() (*Kallsyms, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	kallsyms := Kallsyms{}
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}

		var funcName, symbol string
		var addr uint64
		count, err := fmt.Sscanf(string(line), "%x %s %s", &addr, &symbol, &funcName)
		if addr == 0 {
			continue
		}
		if err != nil || count != 3 {
			return nil, err
		}
		kallsyms.syms = append(kallsyms.syms, Ksym{
			addr: addr,
			name: funcName,
		})
	}
	syms := kallsyms.syms
	sort.Slice(syms, func(i, j int) bool {
		return syms[i].addr < syms[j].addr
	})
	kallsyms.syms = syms
	return &kallsyms, nil
}

func (k *Kallsyms) get(key uint64) *Ksym {
	var start int = 0
	var end = len(k.syms)
	var result int64
	for start < end {
		var mid = start + (end-start)/2
		result = int64(key - k.syms[mid].addr)
		if result < 0 {
			end = mid
		} else if result > 0 {
			start = mid + 1
		} else {
			return &k.syms[mid]
		}
	}

	if start >= 1 && k.syms[start-1].addr < key && key < k.syms[start].addr {
		/* valid Ksym */
		return &k.syms[start-1]
	}
	/* out of range. return _stext */
	return &k.syms[0]
}
