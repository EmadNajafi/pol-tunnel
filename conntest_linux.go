package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ctUdevRule keeps the test's short-lived polct-* TUN interfaces away from
// hotplug hooks — in particular cloud-init's network hotplug hook
// (90-cloud-init-hook-hotplug.rules, common on OpenStack images). That hook
// runs a full cloud-init per new interface, ~50s each and queued, with bursts
// of 100% CPU: on a 1-vCPU VM the server stalls for seconds right when a test
// starts or is stopped. 91-* runs after it and replaces the RUN list (=, not
// +=) for matching devices only, so the hook is dropped; 99-systemd.rules
// still adds its own RUN afterwards. (OPTIONS+="last_rule" is gone from
// systemd, so it cannot be used.) The rule lives in /run (gone at reboot) and
// stays there, so a test killed outright still leaves its devices quiet.
const (
	ctUdevRulePath = "/run/udev/rules.d/91-pol-conntest.rules"
	ctUdevRule     = "# pol connection test: keep its short-lived polct-* TUN interfaces away from\n" +
		"# hotplug hooks (cloud-init would run once per interface and stall a small VM).\n" +
		"ACTION==\"add\", SUBSYSTEM==\"net\", KERNEL==\"polct-*\", RUN=\"/bin/true\"\n"
)

func ctQuietHotplug() {
	if os.Geteuid() != 0 {
		return
	}
	if _, err := os.Stat("/run/udev"); err != nil {
		return // no udev
	}
	if b, err := os.ReadFile(ctUdevRulePath); err == nil && string(b) == ctUdevRule {
		return
	}
	if os.MkdirAll(filepath.Dir(ctUdevRulePath), 0o755) != nil {
		return
	}
	if os.WriteFile(ctUdevRulePath, []byte(ctUdevRule), 0o644) != nil {
		return
	}
	// udevd notices changed rules on its own; reload to be sure (best effort)
	exec.Command("udevadm", "control", "--reload").Run()
}

// ctEngineSysProcAttr makes the kernel send SIGTERM to an engine when the test
// process dies for any reason (SSH dropped = SIGHUP, terminal closed, kill -9,
// a crash). Without it the engines outlive the test, keep their polct-* TUN
// interfaces and RST firewall rules, and the next test's direct tunnels fail
// with "device or resource busy".
func ctEngineSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
}

// ctReapStale stops engines left behind by an earlier test whose process is
// gone (they were re-parented, so their test can no longer clean them up) and
// removes their temp dirs. SIGTERM lets each engine run its own cleanup (TUN
// interface, RST firewall rule). Engines of a test that is still running are
// left alone. Returns how many engines it stopped.
func ctReapStale() int {
	prefix := filepath.Join(os.TempDir(), "pol-conntest-")
	live := map[string]bool{} // temp dirs a running test still owns
	var orphans []int
	procs, _ := filepath.Glob("/proc/[0-9]*")
	self := os.Getpid()
	for _, p := range procs {
		pid, err := strconv.Atoi(filepath.Base(p))
		if err != nil || pid == self {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(p, "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(bytes.TrimRight(raw, "\x00")), "\x00")
		if len(args) != 3 || args[1] != "-c" || !strings.HasPrefix(args[2], prefix) {
			continue
		}
		dir := filepath.Dir(args[2])
		if ctParentIsTest(p) {
			live[dir] = true
			continue
		}
		orphans = append(orphans, pid)
	}
	for _, pid := range orphans {
		syscall.Kill(pid, syscall.SIGTERM)
	}
	// give them a moment to tear down their interfaces, then make sure
	for i := 0; i < 30 && ctAnyAlive(orphans); i++ {
		time.Sleep(100 * time.Millisecond)
	}
	for _, pid := range orphans {
		syscall.Kill(pid, syscall.SIGKILL)
	}
	dirs, _ := filepath.Glob(prefix + "*")
	for _, d := range dirs {
		if !live[d] {
			os.RemoveAll(d)
		}
	}
	return len(orphans)
}

// ctParentIsTest reports whether the process at /proc/PID was started by a
// still-running connection test (its parent is a pol process, not init).
func ctParentIsTest(proc string) bool {
	st, err := os.ReadFile(filepath.Join(proc, "stat"))
	if err != nil {
		return false
	}
	// pid (comm) state ppid ...; comm may contain spaces, so cut after ')'
	i := bytes.LastIndexByte(st, ')')
	if i < 0 {
		return false
	}
	f := strings.Fields(string(st[i+1:]))
	if len(f) < 2 {
		return false
	}
	ppid := f[1]
	if ppid == "0" || ppid == "1" {
		return false
	}
	raw, err := os.ReadFile(filepath.Join("/proc", ppid, "cmdline"))
	if err != nil {
		return false
	}
	return bytes.Contains(raw, []byte("-conntest"))
}

func ctAnyAlive(pids []int) bool {
	for _, pid := range pids {
		if syscall.Kill(pid, 0) == nil {
			return true
		}
	}
	return false
}
