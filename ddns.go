package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/jordan-wright/email"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type T struct {
	Code int `json:"code"`
	Data struct {
		Myip     string `json:"myip"`
		Location string `json:"location"`
		Country  string `json:"country"`
		Local    string `json:"local"`
		Ver4     string `json:"ver4"`
		Ver6     string `json:"ver6"`
		Count4   int    `json:"count4"`
		Count6   int    `json:"count6"`
	} `json:"data"`
}
type Aliyun struct {
	AccessKeyId     string `json:"accessKeyId"`
	AccessKeySecret string `json:"accessKeySecret"`
	Username        string `json:"username"`
	Password        string `json:"password"`
	To              string `json:"to"`
}

type Respnone struct {
	Ip   string `json:"ip"`
	Code int32  `json:"code"`
	Msg  string `json:"msg"`
}

var aliyun = Aliyun{}

// init 初始化函数，在程序启动时自动执行，用于读取 aliyun.json 配置文件并解析到全局变量 aliyun 中。
func init() {
	file, err := os.OpenFile("aliyun.json", os.O_RDONLY, 0644)
	if err != nil {
		log.Println(err)
	}

	err = json.NewDecoder(file).Decode(&aliyun)
	if err != nil {
		log.Println("json错误")
	}
}

// GetIpv6 通过访问外部 API 获取本机的 IPv6 地址。
// 注意：此方法可能会获取到用于出站的"临时隐私 IPv6 地址"，导致外部无法主动访问进来。作为备用方案保留。
func GetIpv6() (string, bool) {
	req, err := http.NewRequest("GET", "https://v6.ip.zxinc.org/info.php?type=json", nil)
	if err != nil {
		log.Println(err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")
	client := &http.Client{
		Timeout: time.Second * 10,
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Println(err)
		return "", false
	}
	defer func(Body io.ReadCloser) {
		err = Body.Close()
		if err != nil {
			log.Println(err)
		}
	}(resp.Body)
	res, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println(err)
		return "", false
	}
	t := new(T)
	err = json.Unmarshal(res, t)
	if err != nil {
		log.Println("json解析错误")
		return "", false
	}
	if t.Data.Myip == "" {
		return "", false
	}
	log.Println("外部API Ipv6获取成功", t.Data.Myip)
	return t.Data.Myip, true
}

// isTemporaryIPv6 判断一个 IPv6 地址是否是临时隐私地址。
// 临时地址通常由随机生成的后64位组成，而 EUI-64 固定地址的后64位中第7位(ff:fe字节对)是固定的。
// 但最可靠的方式还是通过 `ip` 命令的 "temporary" 标记，这里作为额外的启发式补充。
// 规则：如果 IPv6 地址不含 "ff:fe"（EUI-64格式），则它更可能是临时地址，优先级低。
func isLikelyStableIPv6(ip net.IP) bool {
	// EUI-64 派生的固定 IPv6 地址，其接口标识符（后64位）中固定含有 ff:fe 字节对
	// 例如：2001:db8::a1b2:ff:fe03:c4d5
	s := ip.String()
	return strings.Contains(s, "ff:fe") || strings.Contains(s, "FF:FE")
}

// GetIpv6Local 遍历本地网卡，自动寻找处于"已连接"状态的物理网卡，并提取其全局公网 IPv6 地址。
// 修复：Linux 下优先通过 `ip` 命令精确过滤 temporary/deprecated 地址；
// 降级模式下增加 EUI-64 启发式过滤，避免返回临时隐私地址。
func GetIpv6Local() (string, bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		fmt.Println("获取网络接口错误:", err)
		return "", false
	}

	for _, iface := range interfaces {
		// 1. 过滤状态：网卡必须是 Up（已启用）并且 Running（插着网线且有信号）
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagRunning == 0 {
			continue
		}

		// 2. 过滤类型：排除 Loopback (本地回环) 接口
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// 3. 过滤虚拟网卡：按前缀排除 docker、网桥(br-)、虚拟以太网(veth)等，确保定位到物理网卡
		ifName := strings.ToLower(iface.Name)
		if strings.HasPrefix(ifName, "docker") || strings.HasPrefix(ifName, "br-") ||
			strings.HasPrefix(ifName, "veth") || strings.HasPrefix(ifName, "tailscale") ||
			strings.HasPrefix(ifName, "tun") || strings.HasPrefix(ifName, "tap") {
			continue
		}

		// 针对 Linux 系统：通过 `ip` 命令精确过滤 temporary/deprecated 地址
		if runtime.GOOS == "linux" {
			out, cmdErr := exec.Command("ip", "-6", "-o", "addr", "show", "dev", iface.Name, "scope", "global").Output()
			if cmdErr == nil {
				lines := strings.Split(string(out), "\n")
				for _, line := range lines {
					// 跳过临时或将废弃的地址
					if strings.Contains(line, "temporary") || strings.Contains(line, "deprecated") {
						continue
					}
					if strings.Contains(line, "inet6") {
						parts := strings.Fields(line)
						for i, part := range parts {
							if part == "inet6" && i+1 < len(parts) {
								ipWithMask := parts[i+1]
								ipStr := strings.Split(ipWithMask, "/")[0]
								if parsedIP := net.ParseIP(ipStr); parsedIP != nil && !parsedIP.IsPrivate() && parsedIP.IsGlobalUnicast() {
									fmt.Printf("在活动物理网卡 %s 通过 ip 命令精准锁定固定 IPv6 地址: %s\n", iface.Name, ipStr)
									return ipStr, true
								}
							}
						}
					}
				}
				// ip 命令执行成功但没找到合适地址，继续下一张网卡（不降级到标准库）
				fmt.Printf("网卡 %s: ip 命令执行成功但未找到非临时公网 IPv6\n", iface.Name)
				continue
			}
			// ip 命令执行失败（可能是权限问题），才降级到标准库
			fmt.Printf("网卡 %s: ip 命令执行失败(%v)，降级到标准库\n", iface.Name, cmdErr)
		}

		// 降级方案：Go 标准库遍历（Windows/Mac 或 ip 命令失败时使用）
		// 修复：增加 EUI-64 启发式判断，优先返回含 ff:fe 的固定地址
		addrs, err := iface.Addrs()
		if err != nil {
			fmt.Println("获取接口地址错误:", err)
			continue
		}

		var stableIP string   // 含 ff:fe 的 EUI-64 固定地址（首选）
		var fallbackIP string // 普通公网 IPv6（备用）

		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if ipnet.IP.To4() != nil || !ipnet.IP.IsGlobalUnicast() || ipnet.IP.IsPrivate() {
				continue
			}
			if stableIP == "" && isLikelyStableIPv6(ipnet.IP) {
				stableIP = ipnet.IP.String()
				fmt.Printf("在活动物理网卡 %s 找到疑似固定 IPv6 (EUI-64): %s\n", iface.Name, stableIP)
			} else if fallbackIP == "" {
				fallbackIP = ipnet.IP.String()
				fmt.Printf("在活动物理网卡 %s 找到公网 IPv6 (备用): %s\n", iface.Name, fallbackIP)
			}
		}

		if stableIP != "" {
			return stableIP, true
		}
		if fallbackIP != "" {
			return fallbackIP, true
		}
	}

	fmt.Println("本地活动物理网卡没有找到 IPv6 公网地址。")
	return "", false
}

// GetIpv4 通过访问外部 API 获取本机的 IPv4 地址。
func GetIpv4() (string, bool) {
	req, err := http.NewRequest("GET", "https://v4.ip.zxinc.org/info.php?type=json", nil)
	if err != nil {
		log.Println(err)
		return "", false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("请求失败" + err.Error())
		return "", false
	}
	defer resp.Body.Close()
	res, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("读取失败" + err.Error())
		return "", false
	}
	v := new(T)
	err = json.Unmarshal(res, v)
	if err != nil {
		log.Println("json解析错误")
		return "", false
	}
	log.Println("ipv4获取成功", v.Data.Myip)
	return v.Data.Myip, true
}

// Set 调用阿里云 SDK 更新 DNS 解析记录，如果更新失败且非"记录已存在"错误，则发送商务告警邮件。
func Set(v4, v6 string) bool {
	config := sdk.NewConfig()

	credential := credentials.NewAccessKeyCredential(aliyun.AccessKeyId, aliyun.AccessKeySecret)
	client, err := alidns.NewClientWithOptions("cn-hangzhou", config, credential)
	if err != nil {
		log.Println(err)
	}

	request := alidns.CreateUpdateDomainRecordRequest()

	request.Scheme = "https"
	request.Type = "AAAA"
	request.Value = v6
	request.RR = "@"
	request.RecordId = "1953630840458695680"
	request.Lang = "en"
	request.UserClientIp = v4
	response, err := client.UpdateDomainRecord(request)
	if err != nil {
		log.Println(err.Error())
	}
	fmt.Printf("response is %#v\n", response.String())

	// 如果失败，发送 email 告警
	if !response.IsSuccess() && !strings.Contains(response.GetHttpContentString(), "The DNS record already exists.") {
		e := email.NewEmail()
		e.From = "DNS系统服务 <" + aliyun.Username + ">"
		e.To = []string{aliyun.To}
		e.Subject = "【系统告警】DNS解析更新异常通知"
		e.HTML = []byte(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>DNS解析异常告警</title>
    <style>
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; color: #333333; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-top: 4px solid #d9534f; border-radius: 4px; overflow: hidden;}
        .header { padding: 20px 30px; border-bottom: 1px solid #eeeeee; background-color: #fafafa; }
        .header h2 { margin: 0; color: #d9534f; font-size: 18px; font-weight: 600;}
        .content { padding: 30px; line-height: 1.6; font-size: 14px;}
        .error-box { background-color: #fdf7f7; border: 1px solid #eed3d7; padding: 15px; color: #b94a48; border-radius: 4px; font-family: 'Courier New', Courier, monospace; word-wrap: break-word; font-size: 13px; margin: 20px 0;}
        .footer { padding: 20px 30px; background-color: #f9f9f9; color: #999999; font-size: 12px; text-align: center; border-top: 1px solid #eeeeee; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h2>系统告警：DNS解析异常</h2></div>
        <div class="content">
            <p>尊敬的管理员，您好：</p>
            <p>DDNS 自动更新服务在执行过程中遇到错误，未能成功更新阿里云 DNS 记录。具体错误信息如下：</p>
            <div class="error-box">` + response.GetHttpContentString() + `</div>
            <p>请及时登录云控制台排查原因并处理。</p>
        </div>
        <div class="footer">此邮件由 DDNS 服务自动生成并发送，请勿直接回复。</div>
    </div>
</body>
</html>`)
		err := e.SendWithStartTLS("smtp.qq.com:587", smtp.PlainAuth("", aliyun.Username, aliyun.Password, "smtp.qq.com"), &tls.Config{InsecureSkipVerify: true, ServerName: "smtp.qq.com"})
		if err != nil {
			log.Println("stmp:", err)
		}
		log.Println("告警邮件发送成功！")
		log.Println("响应内容", response.GetHttpContentString())
	}
	return response.IsSuccess()
}

// SendEmail 发送包含当前 IPv6 和 IPv4 地址的商务风格通知邮件。
func SendEmail(v6, v4 string) {
	e := email.NewEmail()
	e.From = "服务器网络监控 <" + aliyun.Username + ">"
	e.To = []string{aliyun.To}
	e.Subject = "【系统报告】服务器公网 IP 地址变更通知"
	e.HTML = []byte(`<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>服务器 IP 地址状态报告</title>
    <style>
        body { font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; color: #333333; }
        .container { max-width: 600px; margin: 0 auto; background-color: #ffffff; border: 1px solid #e0e0e0; border-top: 4px solid #0052cc; border-radius: 4px; overflow: hidden;}
        .header { padding: 20px 30px; border-bottom: 1px solid #eeeeee; background-color: #fafafa; }
        .header h2 { margin: 0; color: #0052cc; font-size: 18px; font-weight: 600;}
        .content { padding: 30px; line-height: 1.6; font-size: 14px;}
        .ip-table { width: 100%; border-collapse: collapse; margin-top: 20px; margin-bottom: 20px;}
        .ip-table th, .ip-table td { padding: 14px 15px; border: 1px solid #dddddd; text-align: left; }
        .ip-table th { background-color: #f8f9fa; width: 30%; color: #555555; font-weight: bold; }
        .ip-table td { font-family: 'Courier New', Courier, monospace; color: #222222; font-weight: 500;}
        .footer { padding: 20px 30px; background-color: #f9f9f9; color: #999999; font-size: 12px; text-align: center; border-top: 1px solid #eeeeee; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header"><h2>系统报告：IP 地址变更，DNS 已更新</h2></div>
        <div class="content">
            <p>尊敬的管理员，您好：</p>
            <p>检测到服务器公网 IP 地址发生变更，DNS 解析已自动同步更新，新地址如下：</p>
            <table class="ip-table">
                <tr><th>IPv6 地址</th><td>` + v6 + `</td></tr>
                <tr><th>IPv4 地址</th><td>` + v4 + `</td></tr>
            </table>
        </div>
        <div class="footer">此邮件由 DDNS 服务自动生成并发送，请勿直接回复。</div>
    </div>
</body>
</html>`)

	err := e.SendWithStartTLS("smtp.qq.com:587", smtp.PlainAuth("", aliyun.Username, aliyun.Password, "smtp.qq.com"), &tls.Config{InsecureSkipVerify: true, ServerName: "smtp.qq.com"})
	if err != nil {
		log.Println("stmp:", err)
		return
	}
	log.Println("变更通知邮件发送成功！")
}

// timing 定时任务的核心逻辑，负责获取 IP、比对本地记录文件、发送邮件并触发 DNS 更新。
func timing() {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()

	file, err := os.OpenFile("ip.txt", os.O_CREATE|os.O_RDWR, 0755)
	if err != nil {
		log.Println("打开失败！" + err.Error())
		return
	}
	b := make([]byte, 1024)
	n, err := file.Read(b)
	if err != nil {
		if err == io.EOF {
			_, err2 := file.Write([]byte("123"))
			if err2 != nil {
				log.Println("写入失败！")
			}
		} else {
			log.Println("文件读取失败" + err.Error())
			return
		}
	}
	file.Close()

	// 优先从本地网卡精准获取固定 IPv6（过滤临时隐私地址）
	v6, k := GetIpv6Local()
	if !k {
		log.Println("本地自动获取失败，尝试通过外部API获取备用IPv6...")
		v6, k = GetIpv6()
		if !k {
			log.Println("外部API获取IPv6也失败！")
			return
		}
	}

	v4, ok := GetIpv4()
	if !ok {
		log.Println("IPv4获取失败，但不影响IPv6解析，继续流程...")
	}

	oldIP := strings.TrimSpace(string(b[:n]))
	log.Printf("IP对比 — 旧: %s | 新: %s | 是否变化: %v", oldIP, v6, oldIP != v6)

	// 修复：只有 IP 变化时才更新 DNS 并发送通知邮件，避免每次都发邮件
	if oldIP != v6 {
		log.Println("检测到 IPv6 变化，开始更新...")

		file, err = os.OpenFile("ip.txt", os.O_WRONLY|os.O_TRUNC, 0755)
		if err != nil {
			log.Println("打开文件失败", err)
			return
		}
		_, err = file.Write([]byte(v6))
		if err != nil {
			log.Println("文件写入失败", err)
		}
		file.Close()

		f := Set(v4, v6)
		if f {
			log.Println("DNS 更新成功，发送通知邮件...")
			SendEmail(v6, v4) // 修复：只在成功更新后才发邮件
			log.Println("设置成功")
			return
		}
		log.Println("设置失败！")
		return
	}
	log.Println("IPv6 地址未变化，无需更新。")
}

// main 程序入口，控制定时任务的触发周期。
func main() {
	const interval = 30 * time.Minute

	// 启动后立即执行一次
	log.Println("程序启动，立即执行首次检测...")
	go timing()
	log.Printf("下次检测时间: %s", time.Now().Add(interval).Format("2006-01-02 15:04:05"))

	// 之后每30分钟执行一次
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	log.Printf("定时任务已启动，每 %v 检测一次 IP 变化", interval)

	for t := range ticker.C {
		log.Println("开始执行定时检测...")
		go timing()
		next := t.Add(interval)
		log.Printf("本次检测完成，下次检测时间: %s", next.Format("2006-01-02 15:04:05"))
	}
}
