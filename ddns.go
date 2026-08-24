package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/jordan-wright/email"
)

type Config struct {
	Aliyun struct {
		AccessKeyID     string `json:"access_key_id"`
		AccessKeySecret string `json:"access_key_secret"`
		RegionID        string `json:"region_id"`
		RecordID        string `json:"record_id"`
		RR              string `json:"rr"`
		Type            string `json:"type"`
	} `json:"aliyun"`

	Email struct {
		Username string `json:"username"`
		Password string `json:"password"`
		To       string `json:"to"`
		SMTPHost string `json:"smtp_host"`
		SMTPPort int    `json:"smtp_port"`
	} `json:"email"`

	DDNS struct {
		IntervalHours         int    `json:"interval_hours"`
		IPFile                string `json:"ip_file"`
		IPv6API               string `json:"ipv6_api"`
		IPv4API               string `json:"ipv4_api"`
		RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
	} `json:"ddns"`

	Log struct {
		Directory string `json:"directory"`
		Level     string `json:"level"`
	} `json:"log"`
}

type IPResponse struct {
	Code int `json:"code"`

	Data struct {
		MyIP string `json:"myip"`
		Ver4 string `json:"ver4"`
		Ver6 string `json:"ver6"`
	} `json:"data"`
}

var (
	config Config

	logger  *log.Logger
	logFile *os.File

	httpClient *http.Client

	logMutex sync.Mutex
)

func loadConfig() error {
	data, err := os.ReadFile("config.json")
	if err != nil {
		return fmt.Errorf("读取 config.json 失败: %w", err)
	}

	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("解析 config.json 失败: %w", err)
	}

	// 默认值
	if config.DDNS.IntervalHours <= 0 {
		config.DDNS.IntervalHours = 6
	}

	if config.DDNS.RequestTimeoutSeconds <= 0 {
		config.DDNS.RequestTimeoutSeconds = 10
	}

	if config.DDNS.IPFile == "" {
		config.DDNS.IPFile = "ip.txt"
	}

	if config.DDNS.IPv6API == "" {
		config.DDNS.IPv6API = "https://v6.ip.zxinc.org/info.php?type=json"
	}

	if config.DDNS.IPv4API == "" {
		config.DDNS.IPv4API = "https://v4.ip.zxinc.org/info.php?type=json"
	}

	if config.Log.Directory == "" {
		config.Log.Directory = "logs"
	}

	if config.Email.SMTPHost == "" {
		config.Email.SMTPHost = "smtp.qq.com"
	}

	if config.Email.SMTPPort <= 0 {
		config.Email.SMTPPort = 587
	}

	if config.Aliyun.RegionID == "" {
		config.Aliyun.RegionID = "cn-hangzhou"
	}

	if config.Aliyun.Type == "" {
		config.Aliyun.Type = "AAAA"
	}

	if config.Aliyun.RR == "" {
		config.Aliyun.RR = "@"
	}

	return nil
}

func initLogger() error {
	logMutex.Lock()
	defer logMutex.Unlock()

	if err := os.MkdirAll(config.Log.Directory, 0755); err != nil {
		return fmt.Errorf("创建日志目录失败: %w", err)
	}

	fileName := fmt.Sprintf(
		"%s/ddns_%s.log",
		config.Log.Directory,
		time.Now().Format("20060102"),
	)

	var err error

	logFile, err = os.OpenFile(
		fileName,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		0644,
	)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}

	writer := io.MultiWriter(os.Stdout, logFile)

	logger = log.New(
		writer,
		"",
		log.LstdFlags|log.Lshortfile,
	)

	logger.Println("日志系统初始化完成")

	return nil
}

func initHTTPClient() {
	httpClient = &http.Client{
		Timeout: time.Duration(config.DDNS.RequestTimeoutSeconds) * time.Second,
	}
}

/*
通过公网API获取IP
*/
func getIPFromAPI(apiURL string) (string, bool) {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		logger.Printf("创建IP API请求失败: %v", err)
		return "", false
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Go-DDNS/1.0")

	resp, err := httpClient.Do(req)
	if err != nil {
		logger.Printf("IP API请求失败: %v", err)
		return "", false
	}

	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		logger.Printf("IP API HTTP状态码: %d", resp.StatusCode)
		return "", false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Printf("读取IP API响应失败: %v", err)
		return "", false
	}

	var result IPResponse
	if err := json.Unmarshal(body, &result); err != nil {
		logger.Printf("解析IP API响应失败: %v", err)
		return "", false
	}

	if result.Data.MyIP == "" {
		return "", false
	}

	return strings.TrimSpace(result.Data.MyIP), true
}

/*
IPv6总入口

第一优先级：
公网API

第二优先级：
本地网卡
*/
func GetIPv6() (string, bool) {
	logger.Println("========== 开始获取IPv6 ==========")

	// =====================================================
	// 第一优先级：公网API
	// =====================================================

	logger.Println("第一方式：通过公网IPv6 API获取")

	ip, ok := getIPFromAPI(config.DDNS.IPv6API)
	if ok {
		parsedIP := net.ParseIP(ip)
		if isUsableGlobalIPv6(parsedIP) {
			logger.Printf("公网API获取IPv6成功: %s", ip)
			return ip, true
		}

		logger.Printf("公网API返回的地址不是有效公网IPv6: %s", ip)
	} else {
		logger.Println("公网IPv6 API获取失败")
	}

	// =====================================================
	// 第二优先级：本地网卡
	// =====================================================

	logger.Println("第二方式：扫描本地网络接口获取IPv6")

	ip, ok = GetIPv6Local()
	if ok {
		logger.Printf("本地网卡IPv6获取成功: %s", ip)
		return ip, true
	}

	logger.Println("本地网卡没有找到可用公网IPv6")
	logger.Println("========== IPv6获取失败 ==========")

	return "", false
}

/*
从本地网络接口获取IPv6
*/
func GetIPv6Local() (string, bool) {
	interfaces, err := net.Interfaces()
	if err != nil {
		logger.Printf("获取网络接口失败: %v", err)
		return "", false
	}

	for _, iface := range interfaces {
		/*
		   网卡必须是 UP
		*/
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		/*
		   排除回环接口
		*/
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			logger.Printf("读取网卡 %s 地址失败: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			ip := extractIP(addr)
			if ip == nil {
				continue
			}

			/*
			   必须是公网IPv6
			*/
			if !isUsableGlobalIPv6(ip) {
				continue
			}

			logger.Printf("发现本地公网IPv6 [%s]: %s", iface.Name, ip.String())

			return ip.String(), true
		}
	}

	return "", false
}

/*
从 net.Addr 中提取 IP
*/
func extractIP(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.IPNet:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

/*
判断是否为真正可用的公网IPv6
*/
func isUsableGlobalIPv6(ip net.IP) bool {
	if ip == nil {
		return false
	}

	/*
	   IPv4地址排除
	*/
	if ip.To4() != nil {
		return false
	}

	/*
	   ::
	*/
	if ip.IsUnspecified() {
		return false
	}

	/*
	   ::1
	*/
	if ip.IsLoopback() {
		return false
	}

	/*
	   fe80::/10
	*/
	if ip.IsLinkLocalUnicast() {
		return false
	}

	/*
	   ff00::/8
	*/
	if ip.IsMulticast() {
		return false
	}

	/*
	   必须是 Global Unicast
	*/
	if !ip.IsGlobalUnicast() {
		return false
	}

	return true
}

/*
获取IPv4
*/
func GetIPv4() (string, bool) {
	logger.Println("开始获取IPv4")

	ip, ok := getIPFromAPI(config.DDNS.IPv4API)
	if !ok {
		logger.Println("IPv4获取失败")
		return "", false
	}

	logger.Printf("IPv4获取成功: %s", ip)

	return ip, true
}

/*
读取上一次IPv6
*/
func readOldIP() string {
	data, err := os.ReadFile(config.DDNS.IPFile)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Printf("读取 %s 失败: %v", config.DDNS.IPFile, err)
		}
		return ""
	}

	return strings.TrimSpace(string(data))
}

/*
保存IPv6
*/
func saveIP(ip string) error {
	return os.WriteFile(config.DDNS.IPFile, []byte(ip+"\n"), 0644)
}

/*
更新阿里云DNS
*/
func UpdateDNS(v4 string, v6 string) bool {
	logger.Println("========== 开始更新阿里云DNS ==========")

	credential := credentials.NewAccessKeyCredential(
		config.Aliyun.AccessKeyID,
		config.Aliyun.AccessKeySecret,
	)

	client, err := alidns.NewClientWithOptions(
		config.Aliyun.RegionID,
		sdk.NewConfig(),
		credential,
	)
	if err != nil {
		logger.Printf("创建阿里云客户端失败: %v", err)
		return false
	}

	request := alidns.CreateUpdateDomainRecordRequest()

	request.Scheme = "https"
	request.RecordId = config.Aliyun.RecordID
	request.RR = config.Aliyun.RR
	request.Type = config.Aliyun.Type
	request.Value = v6

	/*
	   阿里云这里可以使用IPv4。
	   如果IPv4获取不到，就不设置。
	*/
	if v4 != "" {
		request.UserClientIp = v4
	}

	logger.Printf(
		"DNS参数: RecordID=%s RR=%s Type=%s IPv6=%s",
		config.Aliyun.RecordID,
		config.Aliyun.RR,
		config.Aliyun.Type,
		v6,
	)

	response, err := client.UpdateDomainRecord(request)
	if err != nil {
		logger.Printf("阿里云DNS更新失败: %v", err)
		return false
	}

	content := response.GetHttpContentString()
	logger.Printf("阿里云返回: %s", content)

	if response.IsSuccess() {
		logger.Println("阿里云DNS更新成功")
		return true
	}

	/*
	   如果已经是这个记录，认为成功。
	*/
	if strings.Contains(content, "The DNS record already exists.") {
		logger.Println("DNS记录已经存在")
		return true
	}

	logger.Println("阿里云DNS更新失败")

	return false
}

/*
发送IP通知邮件
*/
func SendEmail(v6 string, v4 string) {
	/*
	   邮箱没有配置就跳过
	*/
	if config.Email.Username == "" ||
		config.Email.Password == "" ||
		config.Email.To == "" {
		logger.Println("邮箱配置不完整，跳过邮件发送")
		return
	}

	e := email.NewEmail()

	e.From = "服务器DDNS<" + config.Email.Username + ">"
	e.To = []string{config.Email.To}
	e.Subject = "服务器IP地址通知"

	e.HTML = []byte(fmt.Sprintf(`
<!DOCTYPE html>
<html lang="zh-CN">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width,initial-scale=1">

<title>DDNS IP地址通知</title>

<style>

body {
    margin: 0;
    padding: 30px;
    background: #f5f7fa;
    font-family:
        Arial,
        "Microsoft YaHei",
        sans-serif;
}

.card {

    max-width: 520px;

    margin: 30px auto;

    padding: 30px;

    background: white;

    border-radius: 16px;

    box-shadow:
        0 10px 30px
        rgba(0,0,0,.08);
}

h1 {

    margin-top: 0;

    color: #333;
}

.label {

    margin-top: 20px;

    margin-bottom: 8px;

    font-weight: bold;

    color: #666;
}

.ip {

    padding: 12px;

    background: #f5f5f5;

    border-radius: 8px;

    font-family: monospace;

    word-break: break-all;

    color: #333;
}

.time {

    margin-top: 20px;

    color: #999;

    font-size: 13px;
}

</style>

</head>

<body>

<div class="card">

<h1>DDNS IP 地址通知</h1>

<div class="label">
IPv6
</div>

<div class="ip">
%s
</div>

<div class="label">
IPv4
</div>

<div class="ip">
%s
</div>

<div class="time">
更新时间：%s
</div>

</div>

</body>

</html>
`,
		v6,
		v4,
		time.Now().Format("2006-01-02 15:04:05"),
	))

	addr := fmt.Sprintf(
		"%s:%d",
		config.Email.SMTPHost,
		config.Email.SMTPPort,
	)

	auth := smtp.PlainAuth(
		"",
		config.Email.Username,
		config.Email.Password,
		config.Email.SMTPHost,
	)

	err := e.SendWithStartTLS(
		addr,
		auth,
		&tls.Config{
			ServerName: config.Email.SMTPHost,
			MinVersion: tls.VersionTLS12,
		},
	)
	if err != nil {
		logger.Printf("邮件发送失败: %v", err)
		return
	}

	logger.Println("IP通知邮件发送成功")
}

/*
执行一次DDNS任务
*/
func RunOnce() {
	logger.Println("========================================")
	logger.Println("开始执行DDNS任务")
	logger.Println("========================================")

	/*
	   获取IPv6
	*/
	v6, ok := GetIPv6()
	if !ok {
		logger.Println("IPv6获取失败，本次任务结束")
		return
	}

	/*
	   获取IPv4

	   IPv4失败不会影响IPv6 DDNS。
	*/
	v4, _ := GetIPv4()

	/*
	   读取历史IPv6
	*/
	oldIP := readOldIP()

	logger.Printf("历史IPv6: %s", oldIP)
	logger.Printf("当前IPv6: %s", v6)

	/*
	   第一次运行
	*/
	if oldIP == "" {
		logger.Println("第一次运行，准备更新DNS")

		if !UpdateDNS(v4, v6) {
			logger.Println("第一次DNS更新失败")
			return
		}

		if err := saveIP(v6); err != nil {
			logger.Printf("保存IPv6失败: %v", err)
			return
		}

		logger.Println("第一次IPv6保存成功")

		SendEmail(v6, v4)

		return
	}

	/*
	   IPv6没有变化
	*/
	if oldIP == v6 {
		logger.Println("IPv6没有变化，无需更新DNS")
		return
	}

	/*
	   IPv6发生变化
	*/
	logger.Println("检测到IPv6发生变化")
	logger.Printf("旧IPv6: %s", oldIP)
	logger.Printf("新IPv6: %s", v6)

	/*
	   更新阿里云DNS
	*/
	if !UpdateDNS(v4, v6) {
		logger.Println("DNS更新失败")

		/*
		   非常重要：

		   DNS失败时不能保存新IP。

		   这样下一次任务还会继续尝试。
		*/

		return
	}

	/*
	   DNS成功以后再保存IP
	*/
	if err := saveIP(v6); err != nil {
		logger.Printf("保存IPv6失败: %v", err)
		return
	}

	logger.Println("新的IPv6已经保存")

	/*
	   发送邮件
	*/
	SendEmail(v6, v4)

	logger.Println("DDNS任务完成")
}

func main() {
	/*
	   加载配置
	*/
	if err := loadConfig(); err != nil {
		log.Fatal(err)
	}

	/*
	   初始化日志
	*/
	if err := initLogger(); err != nil {
		log.Fatal(err)
	}

	defer func() {
		if logFile != nil {
			_ = logFile.Close()
		}
	}()

	logger.Println("========================================")
	logger.Println("DDNS服务启动")
	logger.Println("========================================")

	/*
	   HTTP客户端只创建一次。

	   后面IPv4 / IPv6请求重复使用。
	*/
	initHTTPClient()

	/*
	   启动以后立即执行一次
	*/
	RunOnce()

	/*
	   定时执行
	*/
	interval := time.Duration(config.DDNS.IntervalHours) * time.Hour

	logger.Printf("下一次任务将在 %s 后执行", interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		RunOnce()

		logger.Printf("下一次任务将在 %s 后执行", interval)
	}
}
