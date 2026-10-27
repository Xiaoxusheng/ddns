package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// 独立调试片段：go run get_v6.go 不可用时，可在 ddns.go 中调用 PrintPublicIPv6()
// 与 ddns.go 同属 main 包，因此函数名不能叫 main（原代码会导致重复声明、无法编译）
func PrintPublicIPv6() {
	req, err := http.NewRequest("GET", "https://v6.ip.zxinc.org/info.php?type=json", nil)
	if err != nil {
		log.Printf("创建IPv6请求失败: %v\n", err)

	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("执行IPv6请求失败: %v\n", err)

	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Printf("关闭IPv6响应体失败: %v\n", err)
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Printf("IPv6请求返回非200状态码: %d\n", resp.StatusCode)
	}

	res, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("读取IPv6响应体失败: %v\n", err)
	}
	fmt.Println(string(res))
}
