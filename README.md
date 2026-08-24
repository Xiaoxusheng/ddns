# DDNS 动态解析

基于 Go 的 DDNS 动态解析程序，适用于 Linux 服务器。

程序会定期获取服务器当前公网 IPv4 / IPv6 地址。当 IPv6 地址发生变化时，自动更新阿里云 DNS 的 AAAA 记录，并通过邮件发送当前 IP 信息。

## 功能

* 支持阿里云 DNS IPv6（AAAA）动态解析
* IPv6 获取采用“公网 API 优先、本地网卡兜底”
* IPv4 获取公网地址
* 自动检测 IPv6 是否发生变化
* IPv6 变化后自动更新阿里云 DNS
* DNS 更新成功后保存当前 IPv6
* 支持 QQ 邮箱 SMTP 发送通知邮件
* 支持 systemd 开机自启动
* 支持日志文件记录
* 支持通过 `config.json` 独立配置，不需要修改 Go 源码

## 项目结构

```text
ddns/
├── ddns
├── config.json
├── ip.txt
└── logs/
    └── ddns_YYYYMMDD.log
```

其中：

* `ddns`：编译后的程序
* `config.json`：程序配置文件
* `ip.txt`：保存上一次成功同步的 IPv6 地址，由程序自动生成
* `logs/`：运行日志目录

## 配置

程序使用 `config.json`，不再把 AccessKey、邮箱等信息直接写在代码中。

示例：

```json
{
  "aliyun": {
    "access_key_id": "你的阿里云AccessKeyID",
    "access_key_secret": "你的阿里云AccessKeySecret",
    "region_id": "cn-hangzhou",
    "record_id": "你的DNS记录ID",
    "rr": "@",
    "type": "AAAA"
  },
  "email": {
    "username": "你的QQ邮箱@qq.com",
    "password": "你的QQ邮箱SMTP授权码",
    "to": "接收通知的邮箱@qq.com",
    "smtp_host": "smtp.qq.com",
    "smtp_port": 587
  },
  "ddns": {
    "interval_hours": 6,
    "ip_file": "./ip.txt",
    "ipv6_api": "https://v6.ip.zxinc.org/info.php?type=json",
    "ipv4_api": "https://v4.ip.zxinc.org/info.php?type=json",
    "request_timeout_seconds": 10
  },
  "log": {
    "directory": "./logs",
    "level": "info"
  }
}
```

### 阿里云配置

`record_id` 为需要更新的阿里云 DNS 解析记录 ID。

例如：

```text
域名：example.com
类型：AAAA
主机记录：@
```

表示更新：

```text
example.com
```

如果：

```text
主机记录：home
```

则更新：

```text
home.example.com
```

### 邮箱配置

程序使用 SMTP 发送 IP 通知邮件。

以 QQ 邮箱为例：

```json
{
  "username": "123456@qq.com",
  "password": "SMTP授权码",
  "to": "接收邮件的邮箱@qq.com",
  "smtp_host": "smtp.qq.com",
  "smtp_port": 587
}
```

`password` 填写邮箱的 **SMTP 授权码**，不是 QQ 邮箱登录密码。

## IPv6 获取逻辑

程序获取 IPv6 时按照以下顺序执行：

```text
公网 IPv6 API
      │
      ├── 获取成功
      │      ↓
      │    使用该 IPv6
      │
      └── 获取失败
             ↓
       扫描 Linux 本地网卡
             ↓
       查找公网 IPv6
             ↓
          使用该 IPv6
```

本地网卡获取时会排除：

```text
IPv4
::1
::
fe80::/10 链路本地地址
IPv6 组播地址
非 Global Unicast 地址
```

因此不依赖公网 API 时，也可以直接从服务器本地网卡获取公网 IPv6。

## 编译

安装 Go 后执行：

```bash
go mod tidy
go build -o ddns .
```

编译完成：

```text
ddns
```

## 手动运行

进入程序目录：

```bash
cd /home/ipv4
```

执行：

```bash
./ddns
```

启动后会立即执行一次 DDNS 检查。

## 使用 `go run`

开发测试时可以：

```bash
go run ddns.go
```

不建议生产环境长期使用：

```bash
nohup go run ddns.go &
```

生产环境建议编译成二进制：

```bash
go build -o ddns .
```

然后使用 systemd 管理。

## systemd 开机启动

假设程序目录：

```text
/home/ipv4/
```

文件：

```text
/home/ipv4/ddns
/home/ipv4/config.json
/home/ipv4/ip.txt
/home/ipv4/logs/
```

创建：

```text
/etc/systemd/system/ddns.service
```

内容：

```ini
[Unit]
Description=IPv6 DDNS Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/ipv4
ExecStart=/home/ipv4/ddns
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

重新加载：

```bash
systemctl daemon-reload
```

设置开机启动：

```bash
systemctl enable ddns.service
```

启动：

```bash
systemctl start ddns.service
```

查看状态：

```bash
systemctl status ddns.service
```

确认是否已经启用：

```bash
systemctl is-enabled ddns.service
```

正常返回：

```text
enabled
```

## 查看日志

程序日志：

```bash
ls -lh /home/ipv4/logs/
```

实时查看 systemd 日志：

```bash
journalctl -u ddns.service -f
```

查看最近日志：

```bash
journalctl -u ddns.service -n 100
```

## IPv6 记录保存

程序会在：

```text
/home/ipv4/ip.txt
```

保存上一次**成功同步到阿里云 DNS** 的 IPv6 地址。

例如：

```text
2409:xxxx:xxxx:xxxx::1234
```

只有当当前 IPv6 与 `ip.txt` 中保存的 IPv6 不同时，程序才会执行 DNS 更新。

如果阿里云 DNS 更新失败，则不会覆盖原来的 `ip.txt`，下一次任务仍会继续尝试。

## 执行周期

默认：

```json
"interval_hours": 6
```

即：

```text
启动
 ↓
立即检查一次
 ↓
等待 6 小时
 ↓
再次检查
 ↓
循环
```

可以修改，例如每 1 小时检查：

```json
"interval_hours": 1
```

每天一次：

```json
"interval_hours": 24
```

## 邮件通知

当检测到 IPv6 地址变化并且 DNS 更新成功后，程序会发送 IP 通知邮件。

邮件包含：

```text
IPv6
IPv4
更新时间
```

例如：

```text
IPv6:
2409:xxxx:xxxx::1234

IPv4:
152.xxx.xxx.xxx

更新时间:
2026-08-24 12:00:00
```

## 安全建议

`config.json` 包含阿里云 AccessKey 和邮箱 SMTP 授权码，建议限制文件权限：

```bash
chmod 600 /home/ipv4/config.json
```

不要将真实的：

```text
AccessKeyID
AccessKeySecret
SMTP授权码
```

提交到 GitHub 或其他公开仓库。

建议将：

```text
config.json
ip.txt
logs/
ddns
```

加入 `.gitignore`。

## 常用命令

启动：

```bash
systemctl start ddns
```

停止：

```bash
systemctl stop ddns
```

重启：

```bash
systemctl restart ddns
```

查看状态：

```bash
systemctl status ddns
```

开机启动：

```bash
systemctl enable ddns
```

关闭开机启动：

```bash
systemctl disable ddns
```

实时日志：

```bash
journalctl -u ddns -f
```
