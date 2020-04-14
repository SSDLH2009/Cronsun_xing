package win

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/shunfei/cronsun/log"
)

type ProcessInfo struct {
	Name string
	Pid  uint32
	PPid uint32
}

type PROC_KIND int

const (
	PROC_CURRENT PROC_KIND = 1 << iota
	PROC_CHILD
	PROC_TREE = PROC_CURRENT | PROC_CHILD
)

func (p ProcessInfo) String() string {
	return fmt.Sprintf("name:%v pid:%v ppid:%v", p.Name, p.Pid, p.PPid)
}

// 根据pid获取该进程的子进程 pKind:获取进程类型
func GetProc(pid int, pKind PROC_KIND) (procs []ProcessInfo, err error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)
	var procEntry syscall.ProcessEntry32
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	if err = syscall.Process32First(snapshot, &procEntry); err != nil {
		return nil, err
	}
	for {
		if (pKind&PROC_CURRENT > 0 && procEntry.ProcessID == uint32(pid)) || (pKind&PROC_CHILD > 0 && procEntry.ParentProcessID == uint32(pid)) {
			procs = append(procs, ProcessInfo{syscall.UTF16ToString(procEntry.ExeFile[:260]), procEntry.ProcessID, procEntry.ParentProcessID})
		}
		err = syscall.Process32Next(snapshot, &procEntry)
		if err != nil {
			return procs, nil
		}
	}
}

// 根据pid杀死进程及子进程
func KillProcTree(pid int) {
	// 杀死当前进程
	p, err := os.FindProcess(pid)
	if err != nil {
		log.Warnf("process:[%d] find failed, error:[%s]\n", pid, err)
	} else {
		err = p.Kill()
		if err != nil {
			log.Errorf("process:[%d] kill failed, error:[%s]\n", pid, err)
		}
	}
	// 获取子进程
	children, err := GetProc(pid, PROC_CHILD)
	if err != nil {
		log.Errorf("get process:[%d] children failed, error:[%s]\n", pid, err)
		return
	}
	for _, v := range children {
		if v.Name == "conhost.exe" {
			continue
		}
		log.Debugf("杀死子进程:%v\n", v)
		KillProcTree(int(v.Pid))
	}
}