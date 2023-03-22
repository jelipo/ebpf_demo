package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
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

type ProcsymsCache struct {
	maps []ProcSymsMap
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

	// TODO 过滤每个
	return &ProcsymsCache{
		maps: maps,
	}, nil
}

func linkMap(maps []ProcSymsMap) {
	fileFdMap := lo.GroupBy(maps, func(item ProcSymsMap) string {
		return item.FdFile
	})
	fileFds := lo.Keys(fileFdMap)

	for _, fileFd := range fileFds {
		// TODO 读取每个elf的symbols
	}

	for _, symsMap := range maps {
		symsMap
	}
}
