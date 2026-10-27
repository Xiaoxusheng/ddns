//go:build windows

package main

import "os"

// acquireLock Windows 下只打开占位文件，不做强制互斥。
// 生产环境是 Linux（走 lock_unix.go 的 flock），这里只为让本地能编译、能跑。
func acquireLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
}
