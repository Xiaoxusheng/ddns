# DDNS动态解析脚本

### 1.支持阿里云ipv6解析
配置aliyun.json
```json
{
  "accessKeyId": "", //阿里云accessKeyId
  "accessKeySecret": "", //阿里云accessKeySecret
  "username": "邮箱",
  "password": "授权码",
  "to": "接收者邮箱"
}
```



### 2.运行
```go
nohup  go run ddns.go &
```


### 3.建议开机启动脚本
```txt
脚本为已经有过解析记录的使用
脚本为一天解析一次，运行时会发送邮件告知今天的ipv4，ipv6地址
```


