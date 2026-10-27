//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

// acquireLock 用 flock 保证同一份配置只有一个进程在跑，
// 避免 systemd 重启与手动启动叠加出两个实例同时写 DNS。
func acquireLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("打开锁文件失败: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("已有实例在运行（%s 被占用）", path)
	}
	return f, nil
}
