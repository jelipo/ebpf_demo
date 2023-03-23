package main

import (
	"bufio"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/samber/lo"
)

type ProcSymsMap struct {
	VmStart uint64
	VmEnd   uint64
	VmPgoff uint32
	FdFile  string
}

type ProcSymbol struct {
	Name        string
	Value, Size uint64
}

type ProcsymsCache struct {
	maps            []ProcSymsMap
	fileFdSymbolMap map[string][]ProcSymbol
}

func NewProcsymsCache(pid uint32) (*ProcsymsCache, error) {
	mapFile, err := os.Open("/proc/" + strconv.Itoa(int(pid)) + "/maps")
	if err != nil {
		return nil, err
	}
	defer mapFile.Close()

	var maps []ProcSymsMap
	reader := bufio.NewReader(mapFile)
	for {
		line, _, err := reader.ReadLine()
		if err == io.EOF {
			break
		}
		var vmStart, vmEnd uint64
		var vmPgoff uint32
		var vmFlags, fdDev, fdIno, fdFile string
		count, err := fmt.Sscanf(string(line), "%x-%x %s %x %s %s %s", &vmStart, &vmEnd, &vmFlags, &vmPgoff, &fdDev, &fdIno, &fdFile)
		if err != nil {
			continue
		}
		if count != 7 {
			continue
		}
		// 过滤掉不需要的fdFile
		if strings.HasPrefix(fdFile, "[") || strings.HasSuffix(fdFile, "]") {
			continue
		}
		maps = append(maps, ProcSymsMap{
			VmStart: vmStart,
			VmEnd:   vmEnd,
			VmPgoff: vmPgoff,
			FdFile:  fdFile,
		})
	}

	fileFdSymbolMap, err := linkMap(maps)
	if err != nil {
		return nil, err
	}
	return &ProcsymsCache{
		maps:            maps,
		fileFdSymbolMap: fileFdSymbolMap,
	}, nil
}

func linkMap(maps []ProcSymsMap) (map[string][]ProcSymbol, error) {
	fileFdMap := lo.GroupBy(maps, func(item ProcSymsMap) string {
		return item.FdFile
	})
	fileFdSymbolMap := make(map[string][]ProcSymbol)
	for _, fileFd := range lo.Keys(fileFdMap) {
		file, err := elf.Open(fileFd)
		if err != nil {
			continue
		}
		symbols, err := file.DynamicSymbols()
		if err != nil {
			continue
		}
		procSymbols := lo.Map(symbols, func(item elf.Symbol, i int) ProcSymbol {
			return ProcSymbol{
				Name:  item.Name,
				Value: item.Value,
				Size:  item.Size,
			}
		})
		sort.Slice(procSymbols, func(i, j int) bool {
			return procSymbols[i].Value < procSymbols[j].Value
		})
		fileFdSymbolMap[fileFd] = procSymbols
	}
	return fileFdSymbolMap, nil
}

func (p *ProcsymsCache) search(addr uint64) string {
	for _, symsMap := range p.maps {
		if !(addr > symsMap.VmStart && addr < symsMap.VmEnd) {
			continue
		}
		procSymbols, ok := p.fileFdSymbolMap[symsMap.FdFile]
		if !ok {
			return "[finderror]"
		}
		start := addr - symsMap.VmStart
		//pagesize := uint32(os.Getpagesize())
		//offset := pagesize * symsMap.VmPgoff
		position := start + uint64(symsMap.VmPgoff)

		size := len(procSymbols)
		for i := range procSymbols {
			symbol := procSymbols[size-i-1]
			if position > symbol.Value {
				if symbol.Size+symbol.Value > position {
					return symbol.Name
				}
				return "[unknown]"
			}
		}
	}
	return "[unknown]"
}
