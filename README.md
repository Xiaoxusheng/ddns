# DDNS 动态解析（v2）

基于 Go 的 IPv6 DDNS 程序，把服务器的公网 IPv6 自动维护到阿里云 DNS 的 AAAA 记录上。

v2 是重写版：**零第三方依赖**（纯标准库，`go build` 不需要联网拉包），并且把「是否要更新」的判断从本地文件改成了**与阿里云线上记录对账**。

## 与旧版的关键区别

| 项目 | 旧版 | v2 |
| --- | --- | --- |
| 判断依据 | 读 `ip.txt` 与当前 IP 比较 | 每轮查阿里云线上的真实记录值 |
| 记录被删 | 永久失败（RecordID 写死） | 自动重新定位，不存在则新建 |
| RecordID 变化 | 永久失败 | 按域名 + 主机记录 + 类型重新查找 |
| 取址 | 取网卡上第一个公网地址 | 排除 deprecated / tentative / dadfailed / ULA，取最新一个，支持前缀白名单 |
| 失败重试 | 等下一个周期 | 单轮内退避重试 + 失败后 60s 快速重试 |
| 写后校验 | 无 | 写入后回读确认 |
| 告警 | 每次失败都发邮件 | 连续第 3/9/27 次才发，恢复时补一条 |
| 通知渠道 | 仅邮件 | 邮件 + Webhook（Server酱 / Bark 等） |
| 日志 | 按天 | 按天 + 按大小轮转 |
| 单实例 | 无 | flock 互斥 |
| 依赖 | 阿里云 SDK + email 库 | 无 |

## 工作原理

```text
启动 / 每 5 分钟
      ↓
读网卡上的全球 IPv6（排除已废弃的旧前缀地址）
      ↓
查阿里云：@.example.com 的 AAAA 记录现在是什么
      ↓
  一致 ──→ 什么都不做（静默）
      ↓
  不一致 ─→ 写入 → 回读校验 → 发通知
      ↓
  记录不存在 ─→ 直接新建 → 发通知
```

## 项目结构

```text
ddns/
├── ddns.go          主程序
├── lock_unix.go     Linux 单实例锁（flock）
├── lock_windows.go  Windows 占位实现（仅为本地能编译）
├── config.json      配置
├── ip.txt           上一次同步成功的地址（仅作记录）
├── state.json       失败计数等运行状态
└── logs/            ddns_YYYYMMDD.log
```

## 配置

```json
{
  "aliyun": {
    "access_key_id": "你的AccessKeyID",
    "access_key_secret": "你的AccessKeySecret",
    "region_id": "cn-hangzhou",
    "record_id": "",
    "domain": "example.com",
    "rr": "@",
    "type": "AAAA",
    "ttl": "600"
  },
  "email": {
    "username": "你的QQ邮箱@qq.com",
    "password": "SMTP授权码",
    "to": "接收通知的邮箱@qq.com",
    "smtp_host": "smtp.qq.com",
    "smtp_port": 587
  },
  "ddns": {
    "interval_minutes": 5,
    "ip_file": "./ip.txt",
    "state_file": "./state.json",
    "net_interface": "",
    "preferred_prefix": "",
    "ipv6_api": "https://v6.ip.zxinc.org/info.php?type=json",
    "ipv4_api": "https://v4.ip.zxinc.org/info.php?type=json",
    "request_timeout_seconds": 10
  },
  "log": {
    "directory": "./logs",
    "level": "info",
    "max_size_mb": 10,
    "max_files": 5
  },
  "webhook": {
    "url": ""
  }
}
```

### 阿里云

- **推荐只填 `domain` + `rr` + `type`**，程序每次按名字查记录，不再依赖固定 ID
- `record_id` 留空即可；如果只填了 `record_id`，启动时会自动反查出域名
  （注意：记录被删过之后旧 ID 会失效，此时必须改用 `domain`）
- `rr` 为 `@` 表示根域名，填 `home` 表示 `home.example.com`

### 更新频率

三个字段都支持，优先级从高到低：

```text
interval_seconds  >  interval_minutes  >  interval_hours
```

推荐直接写：

```json
"interval_minutes": 5
```

最小 30 秒，防止把阿里云接口打爆。默认 300 秒。

> 旧版只认 `interval_hours`，当年写进去的 `interval_minutes` 是不生效的，v2 修好了。

### 取址

- `net_interface` 留空 = 自动挑选物理网卡（自动跳过 docker/veth/br- 等虚拟网卡）
- 指定网卡可写成 `"enp4s0"`
- `preferred_prefix` 是应急开关，例如 `"2409:8a4c:c416:"`，只认这个前缀的地址

## 编译

```bash
go build -trimpath -ldflags "-s -w" -o ddns .
```

交叉编译到 Linux（在 Windows 上也可以）：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ddns .
```

## 运行

```bash
# 常驻（配合 systemd 使用）
./ddns -c /home/ipv4/config.json

# 只跑一轮就退出
./ddns -c config.json -once

# 只读演练：只打印判定过程，绝不写 DNS（改配置前先用它验证）
./ddns -c config.json -once -dry-run

# 自检：打印候选地址、选中哪一个、线上记录是什么
./ddns -c config.json -check

# 版本
./ddns -v
```

`-check` 的输出示例：

```text
已由 record_id 反查出目标记录: @.xyx.homes AAAA (当前值 2409:8a4c:c416:f074:...)
目标记录: @.xyx.homes AAAA，TTL 600
  候选    2409:8a4c:c415:5c04:... (enp4s0)     ← 旧前缀，已不可达
  候选 -> 2409:8a4c:c416:f074:... (enp4s0)     ← 实际采用
线上记录: @.xyx.homes AAAA = 2409:8a4c:c416:f074:... (TTL 600)
```

## systemd

`/etc/systemd/system/ddns.service`：

```ini
[Unit]
Description=IPv6 DDNS Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/home/ipv4
ExecStart=/home/ipv4/ddns -c /home/ipv4/config.json
Restart=always
RestartSec=10
KillSignal=SIGTERM
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable --now ddns.service
systemctl status ddns.service
```

## 通知

### 邮件

填了 `email.username` / `password` / `to` 才会发。`password` 是 SMTP 授权码，不是登录密码。

发送时机：

- 地址变更并写入成功
- 连续失败第 3、9、27 次
- 从失败状态恢复

### Webhook（Server酱 / Bark）

```json
"webhook": {
  "url": "https://sctapi.ftqq.com/SCT******.send"
}
```

程序会自动追加 `title` 和 `desp` 参数，Server酱、Bark 这类都适用。

## 日志与状态

```bash
tail -f /home/ipv4/logs/ddns_$(date +%Y%m%d).log
journalctl -u ddns.service -f
```

- 日志按天新建，单文件超过 `max_size_mb` 会轮转，保留 `max_files` 份
- `state.json` 记录失败计数与上次成功地址，删掉只会让告警重新计数
- `ip.txt` 只作人工排查用，不再是判断依据

## 排错

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `已有实例在运行` | 已有进程持有 `.ddns.lock` | `systemctl stop ddns` 后重试 |
| `反查 record_id 失败` | 记录被删过，旧 ID 失效 | 配置里改填 `domain` |
| `没有可用地址（全部被过滤）` | 网卡上只有 ULA 或已废弃地址 | 看 `-check` 输出，必要时配 `preferred_prefix` |
| `回读校验失败` | 写入没生效，多半是权限或记录被锁 | 检查 AccessKey 权限、记录是否被锁定 |
| 通知没收到 | 邮件或 webhook 未配置 | 看日志里的「未配置任何通知渠道」 |

## 安全建议

`config.json` 里有 AccessKey 和邮箱授权码：

```bash
chmod 600 config.json
```

也可以改用环境变量，覆盖配置文件里的值：

```bash
export DDNS_ALIYUN_AK=xxx
export DDNS_ALIYUN_SK=xxx
```

`.gitignore` 建议包含：

```text
config.json
ip.txt
state.json
logs/
ddns
.ddns.lock
```
