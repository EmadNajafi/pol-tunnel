//go:build !linux

package main

import "syscall"

func ctEngineSysProcAttr() *syscall.SysProcAttr { return nil }

func ctReapStale() int { return 0 }
