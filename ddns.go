// ddns —— 家庭宽带 IPv6 动态解析守护程序（重写版）
//
// 与原版的差异（都是为了“更健壮”）：
//   1. 每轮与阿里云线上的真实记录对账，不再依赖 ip.txt 判断是否需要更新
//   2. 记录被删/重建/RecordID 变化后能自动重新定位，必要时直接新建
//   3. 取址时排除 deprecated / tentative / dadfailed 的地址，并支持前缀白名单
//   4. 单次任务内带退避重试；写入后回读校验，确认真的生效
//   5. 失败告警去抖（连续第 3/9/27 次才发），恢复时补一条恢复通知
//   6. 日志按天+大小轮转；状态文件原子写；进程级 flock 单实例；信号优雅退出
//   7. 零第三方依赖，只用标准库；密钥可用环境变量覆盖
//
// 用法：
//   ./ddns                以守护方式常驻（配合 systemd）
//   ./ddns -once          只跑一轮就退出
//   ./ddns -once -dry-run 只跑一轮，只读不写（安全演练）
//   ./ddns -check         打印取址与记录判定的完整过程，不做任何修改
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	appVersion     = "2.0.0"
	aliyunVersion  = "2015-01-09"
	aliyunEndpoint = "https://alidns.aliyuncs.com/"
	defaultTTL     = "600"
)

// ---------------------------------------------------------------- 配置

type Config struct {
	Aliyun struct {
		AccessKeyID     string `json:"access_key_id"`
		AccessKeySecret string `json:"access_key_secret"`
		RegionID        string `json:"region_id"`
		RecordID        string `json:"record_id"`
		Domain          string `json:"domain"` // 新增：根域名，留空则由 record_id 反查
		RR              string `json:"rr"`
		Type            string `json:"type"`
		TTL             string `json:"ttl"`
	} `json:"aliyun"`

	Email struct {
		Username string `json:"username"`
		Password string `json:"password"`
		To       string `json:"to"`
		SMTPHost string `json:"smtp_host"`
		SMTPPort int    `json:"smtp_port"`
	} `json:"email"`

	DDNS struct {
		IntervalHours         int    `json:"interval_hours"`   // 兼容旧配置
		IntervalMinutes       int    `json:"interval_minutes"` // 兼容旧配置里写了但不生效的字段
		IntervalSeconds       int    `json:"interval_seconds"` // 优先级最高
		IPFile                string `json:"ip_file"`
		StateFile             string `json:"state_file"`
		NetInterface          string `json:"net_interface"`
		PreferredPrefix       string `json:"preferred_prefix"` // 例：2409:8a4c:c416:
		IPv6API               string `json:"ipv6_api"`
		IPv4API               string `json:"ipv4_api"`
		RequestTimeoutSeconds int    `json:"request_timeout_seconds"`
	} `json:"ddns"`

	Log struct {
		Directory string `json:"directory"`
		Level     string `json:"level"`
		MaxSizeMB int    `json:"max_size_mb"`
		MaxFiles  int    `json:"max_files"`
	} `json:"log"`

	Webhook struct {
		// URL 直接填服务商给的推送地址，程序会自动追加 title/desp 参数。
		// 例：https://sctapi.ftqq.com/SCTxxxxxx.send
		URL string `json:"url"`
	} `json:"webhook"`
}

func loadConfig(path string) (*Config, error) {
	cfg := &Config{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	// 环境变量优先，避免密钥硬编码在文件里
	if v := os.Getenv("DDNS_ALIYUN_AK"); v != "" {
		cfg.Aliyun.AccessKeyID = v
	}
	if v := os.Getenv("DDNS_ALIYUN_SK"); v != "" {
		cfg.Aliyun.AccessKeySecret = v
	}

	// 默认值
	// 间隔优先级：interval_seconds > interval_minutes > interval_hours
	if cfg.DDNS.IntervalSeconds <= 0 {
		switch {
		case cfg.DDNS.IntervalMinutes > 0:
			cfg.DDNS.IntervalSeconds = cfg.DDNS.IntervalMinutes * 60
		case cfg.DDNS.IntervalHours > 0:
			cfg.DDNS.IntervalSeconds = cfg.DDNS.IntervalHours * 3600
		default:
			cfg.DDNS.IntervalSeconds = 300
		}
	}
	if cfg.DDNS.IntervalSeconds < 30 {
		cfg.DDNS.IntervalSeconds = 30 // 防止把阿里云接口打爆
	}
	if cfg.DDNS.RequestTimeoutSeconds <= 0 {
		cfg.DDNS.RequestTimeoutSeconds = 15
	}
	if cfg.DDNS.IPFile == "" {
		cfg.DDNS.IPFile = filepath.Join(filepath.Dir(path), "ip.txt")
	}
	if cfg.DDNS.StateFile == "" {
		cfg.DDNS.StateFile = filepath.Join(filepath.Dir(path), "state.json")
	}
	if cfg.DDNS.IPv6API == "" {
		cfg.DDNS.IPv6API = "https://v6.ip.zinx.org/info.php?type=json"
	}
	if cfg.DDNS.IPv4API == "" {
		cfg.DDNS.IPv4API = "https://v4.ip.zxinc.org/info.php?type=json"
	}
	if cfg.Log.Directory == "" {
		cfg.Log.Directory = filepath.Join(filepath.Dir(path), "logs")
	}
	if cfg.Log.MaxSizeMB <= 0 {
		cfg.Log.MaxSizeMB = 10
	}
	if cfg.Log.MaxFiles <= 0 {
		cfg.Log.MaxFiles = 5
	}
	if cfg.Email.SMTPHost == "" {
		cfg.Email.SMTPHost = "smtp.qq.com"
	}
	if cfg.Email.SMTPPort <= 0 {
		cfg.Email.SMTPPort = 587
	}
	if cfg.Aliyun.RegionID == "" {
		cfg.Aliyun.RegionID = "cn-hangzhou"
	}
	if cfg.Aliyun.Type == "" {
		cfg.Aliyun.Type = "AAAA"
	}
	if cfg.Aliyun.RR == "" {
		cfg.Aliyun.RR = "@"
	}
	if cfg.Aliyun.TTL == "" {
		cfg.Aliyun.TTL = defaultTTL
	}

	// 相对路径统一按“配置文件所在目录”解析，避免受工作目录影响
	base := filepath.Dir(path)
	cfg.DDNS.IPFile = resolvePath(base, cfg.DDNS.IPFile)
	cfg.DDNS.StateFile = resolvePath(base, cfg.DDNS.StateFile)
	cfg.Log.Directory = resolvePath(base, cfg.Log.Directory)

	// 关键字段校验，缺失就快速失败，别等到跑起来才报错
	var missing []string
	if cfg.Aliyun.AccessKeyID == "" {
		missing = append(missing, "aliyun.access_key_id")
	}
	if cfg.Aliyun.AccessKeySecret == "" {
		missing = append(missing, "aliyun.access_key_secret")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("配置缺少必填项: %s", strings.Join(missing, ", "))
	}

	return cfg, nil
}

// resolvePath 把相对路径按基准目录展开
func resolvePath(base, p string) string {
	if p == "" || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

// ---------------------------------------------------------------- 日志（按天 + 按大小轮转）

type rotatingWriter struct {
	mu       sync.Mutex
	dir      string
	maxBytes int64
	maxFiles int
	date     string
	file     *os.File
	size     int64
}

func newRotatingWriter(dir string, maxMB, maxFiles int) (*rotatingWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("创建日志目录失败: %w", err)
	}
	w := &rotatingWriter{dir: dir, maxBytes: int64(maxMB) * 1024 * 1024, maxFiles: maxFiles}
	if err := w.open(time.Now()); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *rotatingWriter) open(t time.Time) error {
	if w.file != nil {
		_ = w.file.Close()
	}
	w.date = t.Format("20060102")
	name := filepath.Join(w.dir, "ddns_"+w.date+".log")
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("打开日志文件失败: %w", err)
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return err
	}
	w.file, w.size = f, st.Size()
	return nil
}

func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	now := time.Now()
	if now.Format("20060102") != w.date {
		if err := w.open(now); err != nil {
			return 0, err
		}
	}
	if w.size+int64(len(p)) > w.maxBytes {
		w.rotate()
	}
	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

// rotate 把当前文件改名为 .1，旧的依次后移，超出上限的删掉
func (w *rotatingWriter) rotate() {
	base := filepath.Join(w.dir, "ddns_"+w.date+".log")
	_ = w.file.Close()

	for i := w.maxFiles - 1; i >= 1; i-- {
		old := fmt.Sprintf("%s.%d", base, i)
		newer := fmt.Sprintf("%s.%d", base, i+1)
		if _, err := os.Stat(old); err == nil {
			_ = os.Rename(old, newer)
		}
	}
	_ = os.Rename(base, base+".1")

	f, err := os.OpenFile(base, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "日志轮转后重新打开失败: %v\n", err)
		return
	}
	w.file, w.size = f, 0
}

func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// ---------------------------------------------------------------- 阿里云 DNS 客户端（自签名，无 SDK）

type aliyunClient struct {
	ak, sk string
	hc     *http.Client
}

type apiError struct {
	Code      string
	Message   string
	RequestID string
	Status    int
}

func (e *apiError) Error() string {
	return fmt.Sprintf("阿里云接口错误 [%s] %s (HTTP %d, RequestId=%s)", e.Code, e.Message, e.Status, e.RequestID)
}

func newAliyunClient(ak, sk string, timeout time.Duration) *aliyunClient {
	return &aliyunClient{
		ak: ak,
		sk: sk,
		hc: &http.Client{Timeout: timeout},
	}
}

// percentEncode 按阿里云 RPC 签名要求做 RFC3986 编码（空格转 %20，而不是 +）
func percentEncode(s string) string {
	e := url.QueryEscape(s)
	e = strings.ReplaceAll(e, "+", "%20")
	e = strings.ReplaceAll(e, "*", "%2A")
	e = strings.ReplaceAll(e, "%7E", "~")
	return e
}

func (c *aliyunClient) buildQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	pairs := make([]string, 0, len(keys))
	for _, k := range keys {
		pairs = append(pairs, percentEncode(k)+"="+percentEncode(params[k]))
	}
	canonical := strings.Join(pairs, "&")

	sts := "GET&%2F&" + percentEncode(canonical)
	mac := hmac.New(sha1.New, []byte(c.sk+"&"))
	mac.Write([]byte(sts))
	sig := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	return canonical + "&Signature=" + percentEncode(sig)
}

// call 发起一次阿里云 RPC 调用，out 为 nil 时忽略返回体
func (c *aliyunClient) call(ctx context.Context, action string, params map[string]string, out interface{}) error {
	if params == nil {
		params = map[string]string{}
	}
	params["Action"] = action
	params["Format"] = "JSON"
	params["Version"] = aliyunVersion
	params["AccessKeyId"] = c.ak
	params["SignatureMethod"] = "HMAC-SHA1"
	params["SignatureVersion"] = "1.0"
	params["SignatureNonce"] = strconv.FormatInt(time.Now().UnixNano(), 10)
	params["Timestamp"] = time.Now().UTC().Format("2006-01-02T15:04:05Z")

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		aliyunEndpoint+"?"+c.buildQuery(params), nil)
	if err != nil {
		return err
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return fmt.Errorf("请求阿里云失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("读取阿里云响应失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Code      string `json:"Code"`
			Message   string `json:"Message"`
			RequestID string `json:"RequestId"`
		}
		_ = json.Unmarshal(body, &e)
		return &apiError{Code: e.Code, Message: e.Message, RequestID: e.RequestID, Status: resp.StatusCode}
	}

	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("解析阿里云响应失败: %w (原始内容: %.200s)", err, string(body))
	}
	return nil
}

// callRetry 对网络抖动、限流、5xx 做带退避的重试
func (c *aliyunClient) callRetry(ctx context.Context, action string, params map[string]string, out interface{}) error {
	var lastErr error
	delays := []time.Duration{2 * time.Second, 6 * time.Second, 15 * time.Second}

	for attempt := 0; attempt <= len(delays); attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delays[attempt-1]):
			}
		}

		// 每轮重建参数，避免上次签名污染
		fresh := make(map[string]string, len(params))
		for k, v := range params {
			fresh[k] = v
		}

		err := c.call(ctx, action, fresh, out)
		if err == nil {
			return nil
		}
		lastErr = err

		if !retryable(err) {
			return err
		}
		log.Printf("阿里云调用 %s 失败（第 %d 次），准备重试: %v", action, attempt+1, err)
	}
	return lastErr
}

func retryable(err error) bool {
	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.Code {
		case "Throttling", "Throttling.User", "ServiceUnavailable", "InternalError":
			return true
		}
		return ae.Status >= 500
	}
	// 网络类错误一律重试
	return true
}

// ---------------------------------------------------------------- DNS 记录操作

type dnsRecord struct {
	RecordID   string `json:"RecordId"`
	RR         string `json:"RR"`
	Type       string `json:"Type"`
	Value      string `json:"Value"`
	TTL        int    `json:"TTL"`
	DomainName string `json:"DomainName"`
	Status     string `json:"Status"`
	Locked     bool   `json:"Locked"`
}

type recordInfo struct {
	RecordID   string `json:"RecordId"`
	RR         string `json:"RR"`
	Type       string `json:"Type"`
	Value      string `json:"Value"`
	TTL        int    `json:"TTL"`
	DomainName string `json:"DomainName"`
	Status     string `json:"Status"`
}

func (c *aliyunClient) describeRecordInfo(ctx context.Context, recordID string) (*recordInfo, error) {
	var out recordInfo
	err := c.callRetry(ctx, "DescribeDomainRecordInfo",
		map[string]string{"RecordId": recordID}, &out)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// listRecords 查询指定子域名的记录。
// 阿里云对根记录要求 SubDomain 形如 "@.example.com"，个别情况下只认裸域名，
// 所以这里做了回退，避免因为传参形式不同而误判“记录不存在”。
func (c *aliyunClient) listRecords(ctx context.Context, domain, sub, typ string) ([]dnsRecord, error) {
	query := func(subDomain string) ([]dnsRecord, error) {
		var out struct {
			TotalCount    int `json:"TotalCount"`
			DomainRecords struct {
				Record []dnsRecord `json:"Record"`
			} `json:"DomainRecords"`
		}
		err := c.callRetry(ctx, "DescribeSubDomainRecords", map[string]string{
			"DomainName": domain,
			"SubDomain":  subDomain,
			"Type":       typ,
		}, &out)
		if err != nil {
			return nil, err
		}
		return out.DomainRecords.Record, nil
	}

	full := sub + "." + domain
	if sub == "@" || sub == "" {
		full = "@." + domain
	}

	recs, err := query(full)
	if err == nil {
		return recs, nil
	}
	// 回退：根域名尝试裸域名形式
	if sub == "@" || sub == "" {
		if recs2, err2 := query(domain); err2 == nil {
			return recs2, nil
		}
	}
	return nil, err
}

func (c *aliyunClient) addRecord(ctx context.Context, domain, rr, typ, value, ttl string) (string, error) {
	var out struct {
		RecordID string `json:"RecordId"`
	}
	err := c.callRetry(ctx, "AddDomainRecord", map[string]string{
		"DomainName": domain,
		"RR":         rr,
		"Type":       typ,
		"Value":      value,
		"TTL":        ttl,
	}, &out)
	if err != nil {
		return "", err
	}
	return out.RecordID, nil
}

func (c *aliyunClient) updateRecord(ctx context.Context, recordID, rr, typ, value, ttl string) error {
	err := c.callRetry(ctx, "UpdateDomainRecord", map[string]string{
		"RecordId": recordID,
		"RR":       rr,
		"Type":     typ,
		"Value":    value,
		"TTL":      ttl,
	}, nil)
	if err != nil {
		// 记录已是目标值：阿里云会报 Duplicate，这不是故障
		var ae *apiError
		if errors.As(err, &ae) && ae.Code == "DomainRecordDuplicate" {
			return nil
		}
		return err
	}
	return nil
}

// ---------------------------------------------------------------- IPv6 取址

type candidate struct {
	Addr       string
	Iface      string
	Deprecated bool
	Tentative  bool
	DadFailed  bool
	ULA        bool
	LinkLocal  bool
}

// listIPv6 通过 ip 命令拿到全球地址，并解析出内核标记。
// 用 ip 而不是 Go 的 net.Interfaces，是因为 Go 拿不到 deprecated 标记。
func listIPv6(ctx context.Context, iface string) ([]candidate, error) {
	args := []string{"-6", "-o", "addr", "show", "scope", "global"}
	if iface != "" {
		args = []string{"-6", "-o", "addr", "show", "dev", iface, "scope", "global"}
	}

	out, err := exec.CommandContext(ctx, "ip", args...).Output()
	if err != nil {
		return nil, fmt.Errorf("执行 ip 命令失败: %w", err)
	}

	var list []candidate
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// 形如：3: enp4s0    inet6 2409:8a4c::5ac5/64 scope global dynamic deprecated
		name := strings.TrimSuffix(fields[1], ":")
		if iface == "" && (strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "br-") ||
			strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "virbr") ||
			strings.HasPrefix(name, "tun") || strings.HasPrefix(name, "tap") || name == "lo") {
			continue
		}

		var addr string
		for i, f := range fields {
			if f == "inet6" && i+1 < len(fields) {
				addr = strings.Split(fields[i+1], "/")[0]
				break
			}
		}
		if addr == "" {
			continue
		}

		c := candidate{Addr: addr, Iface: name}
		for _, f := range fields {
			switch f {
			case "deprecated":
				c.Deprecated = true
			case "tentative":
				c.Tentative = true
			case "dadfailed":
				c.DadFailed = true
			}
		}

		ip := net.ParseIP(addr)
		if ip == nil {
			continue
		}
		if ip.IsLinkLocalUnicast() {
			c.LinkLocal = true
		}
		if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
			c.ULA = true
		}

		list = append(list, c)
	}
	return list, nil
}

// pickIPv6 返回选中的地址与完整候选列表，方便排查
func pickIPv6(ctx context.Context, cfg *Config, logger *log.Logger) (string, []candidate, error) {
	list, err := listIPv6(ctx, cfg.DDNS.NetInterface)
	if err != nil {
		return "", nil, err
	}
	if len(list) == 0 {
		return "", list, errors.New("网卡上没有全球 IPv6 地址")
	}

	var usable []candidate
	for _, c := range list {
		if c.Deprecated || c.Tentative || c.DadFailed || c.ULA || c.LinkLocal {
			continue
		}
		usable = append(usable, c)
	}
	if len(usable) == 0 {
		return "", list, errors.New("没有可用地址（全部被 deprecated/tentative/ULA 过滤）")
	}

	// 指定了前缀白名单就优先用它（应急开关）
	if p := cfg.DDNS.PreferredPrefix; p != "" {
		for _, c := range usable {
			if strings.HasPrefix(c.Addr, p) {
				return c.Addr, list, nil
			}
		}
		logger.Printf("警告: 没有地址匹配 preferred_prefix=%s，回退到自动选择", p)
	}

	// 内核按加入顺序排列，新前缀的地址排在最后；取最后一个 = 最新的前缀
	return usable[len(usable)-1].Addr, list, nil
}

// logCandidates 打印候选地址及各自的标记，排查时非常有用
func logCandidates(logger *log.Logger, cands []candidate, chosen string) {
	for _, c := range cands {
		mark := "  "
		if c.Addr == chosen {
			mark = "->"
		}
		var flags []string
		if c.Deprecated {
			flags = append(flags, "deprecated")
		}
		if c.Tentative {
			flags = append(flags, "tentative")
		}
		if c.DadFailed {
			flags = append(flags, "dadfailed")
		}
		if c.ULA {
			flags = append(flags, "ula")
		}
		suffix := ""
		if len(flags) > 0 {
			suffix = " [" + strings.Join(flags, ",") + "]"
		}
		logger.Printf("  候选 %s %s (%s)%s", mark, c.Addr, c.Iface, suffix)
	}
}

// ---------------------------------------------------------------- 状态与通知

type State struct {
	LastGoodIP   string    `json:"last_good_ip"`
	LastChangeAt time.Time `json:"last_change_at"`
	FailStreak   int       `json:"fail_streak"`
	LastNotifyAt time.Time `json:"last_notify_at"`
}

func loadState(path string) State {
	var s State
	data, err := os.ReadFile(path)
	if err == nil {
		_ = json.Unmarshal(data, &s)
	}
	return s
}

// save 原子写，避免断电留下半截文件
func (s State) save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeFileAtomic(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// 失败告警去抖：连续第 3、9、27… 次才发
func shouldNotifyFailure(streak int) bool {
	if streak < 3 {
		return false
	}
	for n := 3; n <= 243; n *= 3 {
		if streak == n {
			return true
		}
	}
	return false
}

func tlsConfig(serverName string) *tls.Config {
	return &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}
}

func sendMail(cfg *Config, subject, htmlBody string) error {
	if cfg.Email.Username == "" || cfg.Email.Password == "" || cfg.Email.To == "" {
		return errors.New("邮件未配置，跳过")
	}

	addr := net.JoinHostPort(cfg.Email.SMTPHost, strconv.Itoa(cfg.Email.SMTPPort))
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return fmt.Errorf("连接 SMTP 失败: %w", err)
	}

	c, err := smtp.NewClient(conn, cfg.Email.SMTPHost)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("创建 SMTP 会话失败: %w", err)
	}
	defer func() { _ = c.Close() }()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(tlsConfig(cfg.Email.SMTPHost)); err != nil {
			return fmt.Errorf("STARTTLS 失败: %w", err)
		}
	}
	if ok, _ := c.Extension("AUTH"); ok {
		if err := c.Auth(smtp.PlainAuth("", cfg.Email.Username, cfg.Email.Password, cfg.Email.SMTPHost)); err != nil {
			return fmt.Errorf("SMTP 认证失败: %w", err)
		}
	}

	if err := c.Mail(cfg.Email.Username); err != nil {
		return err
	}
	if err := c.Rcpt(cfg.Email.To); err != nil {
		return err
	}

	w, err := c.Data()
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "From: 服务器DDNS <%s>\r\n", cfg.Email.Username)
	fmt.Fprintf(&buf, "To: %s\r\n", cfg.Email.To)
	fmt.Fprintf(&buf, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	buf.WriteString("MIME-Version: 1.0\r\n")
	buf.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	// 必须 base64：SMTP 规定单行不得超过 998 octet，HTML 一行写下来会被拒收
	buf.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")

	encoded := base64.StdEncoding.EncodeToString([]byte(htmlBody))
	for i := 0; i < len(encoded); i += 76 {
		end := i + 76
		if end > len(encoded) {
			end = len(encoded)
		}
		buf.WriteString(encoded[i:end])
		buf.WriteString("\r\n")
	}

	if _, err := w.Write(buf.Bytes()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func htmlNotice(title string, rows [][2]string) string {
	var b strings.Builder
	b.WriteString(`<div style="font-family:-apple-system,'Microsoft YaHei',sans-serif;max-width:520px;margin:0 auto;padding:24px;background:#fff;border:1px solid #eee;border-radius:12px">`)
	fmt.Fprintf(&b, `<h2 style="margin:0 0 16px;font-size:18px;color:#222">%s</h2>`, title)
	b.WriteString(`<table style="width:100%;border-collapse:collapse;font-size:14px">`)
	for _, r := range rows {
		fmt.Fprintf(&b, `<tr><td style="padding:8px 0;color:#888;width:88px;vertical-align:top">%s</td><td style="padding:8px 0;color:#222;word-break:break-all;font-family:ui-monospace,monospace">%s</td></tr>`, r[0], r[1])
	}
	b.WriteString(`</table></div>`)
	return b.String()
}

// ---------------------------------------------------------------- 主流程

type App struct {
	cfg    *Config
	ali     *aliyunClient
	logger  *log.Logger
	state   State
	dryRun  bool
	domain  string
	sub     string
	recType string
	ttl     string
}

// resolveTarget 定位“要维护哪条记录”。
// 旧配置只有 record_id，这里反查一次拿域名，避免改配置。
func (a *App) resolveTarget(ctx context.Context) error {
	a.domain = a.cfg.Aliyun.Domain
	a.sub = a.cfg.Aliyun.RR
	a.recType = a.cfg.Aliyun.Type
	a.ttl = a.cfg.Aliyun.TTL

	if a.domain != "" {
		return nil
	}
	if a.cfg.Aliyun.RecordID == "" {
		return errors.New("配置里 domain 和 record_id 至少要有一个")
	}

	info, err := a.ali.describeRecordInfo(ctx, a.cfg.Aliyun.RecordID)
	if err != nil {
		return fmt.Errorf("反查 record_id 失败，请直接在配置里填 domain: %w", err)
	}
	a.domain = info.DomainName
	if a.sub == "@" && info.RR != "" {
		a.sub = info.RR
	}
	if info.Type != "" {
		a.recType = info.Type
	}
	a.logger.Printf("已由 record_id 反查出目标记录: %s.%s %s (当前值 %s)",
		a.sub, a.domain, a.recType, info.Value)
	return nil
}

type Result struct {
	IP       string
	Changed  bool
	OldValue string
	Verified bool
}

func (a *App) reconcile(ctx context.Context) (Result, error) {
	var res Result

	ip, cands, err := pickIPv6(ctx, a.cfg, a.logger)
	if err != nil {
		return res, err
	}
	res.IP = ip

	logCandidates(a.logger, cands, ip)
	a.logger.Printf("本轮采用地址: %s", ip)

	records, err := a.ali.listRecords(ctx, a.domain, a.sub, a.recType)
	if err != nil {
		return res, fmt.Errorf("查询记录失败: %w", err)
	}

	if len(records) == 0 {
		a.logger.Printf("记录 %s.%s %s 不存在，准备新建", a.sub, a.domain, a.recType)
		if a.dryRun {
			a.logger.Printf("[dry-run] 跳过新建")
			return res, nil
		}
		id, err := a.ali.addRecord(ctx, a.domain, a.sub, a.recType, ip, a.ttl)
		if err != nil {
			return res, fmt.Errorf("新建记录失败: %w", err)
		}
		a.logger.Printf("新建记录成功，RecordId=%s", id)
		res.Changed = true
		res.Verified = true
		return res, nil
	}

	// 多条同名记录时，优先用配置里指定的 RecordId，其次取第一条
	cur := records[0]
	if a.cfg.Aliyun.RecordID != "" {
		for _, r := range records {
			if r.RecordID == a.cfg.Aliyun.RecordID {
				cur = r
				break
			}
		}
	}
	res.OldValue = cur.Value

	if cur.Value == ip {
		a.logger.Printf("记录已是目标值 %s，无需变更", ip)
		return res, nil
	}

	a.logger.Printf("记录需要更新: %s -> %s", cur.Value, ip)
	if a.dryRun {
		a.logger.Printf("[dry-run] 跳过写入")
		return res, nil
	}

	if err := a.ali.updateRecord(ctx, cur.RecordID, a.sub, a.recType, ip, a.ttl); err != nil {
		return res, fmt.Errorf("更新记录失败: %w", err)
	}
	res.Changed = true

	// 写后回读，确认真的落库
	after, err := a.ali.listRecords(ctx, a.domain, a.sub, a.recType)
	if err != nil {
		a.logger.Printf("警告: 写后回读失败（写入可能已成功）: %v", err)
		return res, nil
	}
	for _, r := range after {
		if r.RecordID == cur.RecordID && r.Value == ip {
			res.Verified = true
			a.logger.Printf("回读校验通过，记录已生效")
			return res, nil
		}
	}
	return res, fmt.Errorf("回读校验失败: 写入后记录值仍不是 %s", ip)
}

// ---------------------------------------------------------------- 入口

func main() {
	configPath := flag.String("c", "config.json", "配置文件路径")
	once := flag.Bool("once", false, "只执行一轮后退出")
	dryRun := flag.Bool("dry-run", false, "只读演练，不写入 DNS")
	check := flag.Bool("check", false, "打印取址与判定过程后退出")
	showVersion := flag.Bool("v", false, "显示版本")
	flag.Parse()

	if *showVersion {
		fmt.Println("ddns", appVersion)
		return
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "配置错误:", err)
		os.Exit(2)
	}

	rw, err := newRotatingWriter(cfg.Log.Directory, cfg.Log.MaxSizeMB, cfg.Log.MaxFiles)
	if err != nil {
		fmt.Fprintln(os.Stderr, "日志初始化失败:", err)
		os.Exit(2)
	}
	defer func() { _ = rw.Close() }()

	logger := log.New(io.MultiWriter(os.Stdout, rw), "", log.LstdFlags|log.Lshortfile)
	// 让内部库调用（如重试日志）也落到同一个文件
	log.SetOutput(io.MultiWriter(os.Stdout, rw))
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 单实例：防止 systemd 重启叠加出两个进程同时写 DNS
	lockPath := filepath.Join(filepath.Dir(*configPath), ".ddns.lock")
	lock, err := acquireLock(lockPath)
	if err != nil {
		logger.Fatalf("%v", err)
	}
	defer func() { _ = lock.Close() }()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	app := &App{
		cfg:    cfg,
		ali:    newAliyunClient(cfg.Aliyun.AccessKeyID, cfg.Aliyun.AccessKeySecret, time.Duration(cfg.DDNS.RequestTimeoutSeconds)*time.Second),
		logger: logger,
		state:  loadState(cfg.DDNS.StateFile),
		dryRun: *dryRun,
	}

	logger.Printf("ddns %s 启动，配置文件 %s", appVersion, *configPath)

	targetCtx, cancelTarget := context.WithTimeout(ctx, 30*time.Second)
	err = app.resolveTarget(targetCtx)
	cancelTarget()
	if err != nil {
		logger.Fatalf("定位目标记录失败: %v", err)
	}
	logger.Printf("目标记录: %s.%s %s，TTL %s", app.sub, app.domain, app.recType, app.ttl)

	if *check {
		runCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
		ip, cands, perr := pickIPv6(runCtx, cfg, logger)
		cancel()
		logCandidates(logger, cands, ip)
		if perr != nil {
			logger.Printf("取址检查未通过: %v", perr)
		} else {
			logger.Printf("将采用地址: %s", ip)
		}
		recCtx, cancel2 := context.WithTimeout(ctx, 60*time.Second)
		recs, lerr := app.ali.listRecords(recCtx, app.domain, app.sub, app.recType)
		cancel2()
		if lerr != nil {
			logger.Printf("记录查询失败: %v", lerr)
		}
		for _, r := range recs {
			logger.Printf("线上记录: %s.%s %s = %s (TTL %d, RecordId %s)", r.RR, r.DomainName, r.Type, r.Value, r.TTL, r.RecordID)
		}
		if len(recs) == 0 {
			logger.Printf("线上没有匹配记录")
		}
		return
	}

	interval := time.Duration(cfg.DDNS.IntervalSeconds) * time.Second
	logger.Printf("检查间隔 %s，dry-run=%v", interval, *dryRun)

	for {
		runCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		res, err := app.reconcile(runCtx)
		cancel()

		next := interval
		if err != nil {
			app.state.FailStreak++
			logger.Printf("本轮失败（连续第 %d 次）: %v", app.state.FailStreak, err)

			if shouldNotifyFailure(app.state.FailStreak) {
				notify(app, "DDNS 更新失败",
					[][2]string{{"连续失败", fmt.Sprintf("%d 次", app.state.FailStreak)}, {"原因", err.Error()}})
			}
			// 失败后先快速重试几次，别干等一个周期
			switch {
			case app.state.FailStreak <= 3:
				next = 60 * time.Second
			case app.state.FailStreak <= 6:
				next = 5 * time.Minute
			}
		} else {
			if app.state.FailStreak >= 3 {
				logger.Printf("已恢复（此前连续失败 %d 次）", app.state.FailStreak)
				notify(app, "DDNS 已恢复", [][2]string{{"当前地址", res.IP}})
			}
			app.state.FailStreak = 0

			if res.Changed {
				app.state.LastChangeAt = time.Now()
				app.state.LastGoodIP = res.IP
				logger.Printf("更新完成并已校验，新地址 %s", res.IP)
				notify(app, "服务器 IPv6 已变更", [][2]string{
					{"新地址", res.IP},
					{"原地址", res.OldValue},
					{"域名", app.sub + "." + app.domain},
					{"时间", time.Now().Format("2006-01-02 15:04:05")},
				})
			} else if app.state.LastGoodIP != res.IP {
				app.state.LastGoodIP = res.IP
			}
		}

		if err := app.state.save(cfg.DDNS.StateFile); err != nil {
			logger.Printf("保存状态失败: %v", err)
		}
		if res.IP != "" {
			if err := writeFileAtomic(cfg.DDNS.IPFile, res.IP+"\n"); err != nil {
				logger.Printf("写 ip.txt 失败: %v", err)
			}
		}

		if *once {
			if err != nil {
				os.Exit(1)
			}
			return
		}

		timer := time.NewTimer(next)
		select {
		case <-ctx.Done():
			timer.Stop()
			logger.Printf("收到退出信号，停止服务")
			return
		case <-timer.C:
		}
	}
}

func notify(app *App, title string, rows [][2]string) {
	sent := false

	if app.cfg.Email.Username != "" && app.cfg.Email.Password != "" && app.cfg.Email.To != "" {
		app.state.LastNotifyAt = time.Now()
		if err := sendMail(app.cfg, title, htmlNotice(title, rows)); err != nil {
			app.logger.Printf("发送邮件通知失败: %v", err)
		} else {
			app.logger.Printf("通知邮件已发送: %s", title)
			sent = true
		}
	}

	if u := app.cfg.Webhook.URL; u != "" {
		var body strings.Builder
		fmt.Fprintf(&body, "**%s**\n\n", title)
		for _, r := range rows {
			fmt.Fprintf(&body, "- %s：%s\n", r[0], r[1])
		}
		if err := sendWebhook(u, title, body.String()); err != nil {
			app.logger.Printf("推送通知失败: %v", err)
		} else {
			app.logger.Printf("推送通知已发送: %s", title)
			sent = true
		}
	}

	if !sent {
		app.logger.Printf("未配置任何通知渠道，仅记录日志: %s", title)
	}
}

// sendWebhook 以 GET + query 参数推送，兼容 Server酱 / Bark 这类服务
func sendWebhook(baseURL, title, desp string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return fmt.Errorf("webhook 地址不合法: %w", err)
	}
	q := u.Query()
	q.Set("title", title)
	q.Set("desp", desp)
	u.RawQuery = q.Encode()

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %.200s", resp.StatusCode, string(body))
	}
	return nil
}
