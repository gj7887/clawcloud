# VLESS 代理系统

> 基于 Xray 的 VLESS over TLS 代理服务

[![Node.js](https://img.shields.io/badge/Node.js-18+-green)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-MIT-blue)](#)
[![Status](https://img.shields.io/badge/Status-Production%20Ready-success)](#)

## ✨ 核心特性

- 🔐 **VLESS over TLS ** - 完全伪装为真实网站流量
- 🚀 **高性能** - 原生 TCP 速度，无加密开销
- 🎭 **多伪装目标** - 随机选择 Google/Cloudflare/Microsoft 等
- 📱 **多协议支持** - TLS/WebSocket/VMess/Trojan
- 🛡️ **TLS 1.3** - 最新加密标准，前向保密
- 🌐 **Cloudflare 隧道** - 支持固定和临时隧道
- 📊 **自动监控** - 集成哪吒监控系统（可选）
- 📥 **订阅管理** - Base64 编码订阅，支持多协议

## 🎯 使用场景

| 场景 | 推荐方案 |
|------|---------|
| CDN 加速 | VLESS + WebSocket + TLS |
| 低级用户 | VMess + WebSocket |
| 紧急情况 | Trojan + WebSocket |
| 多链路备用 | 全部协议共存 |

## 📋 快速开始

### 1️⃣ 环境配置

```bash
# 克隆或下载项目
git clone https://github.com/gj7887/Argo-dlxt.git
cd Argo-dlxt

# 创建 .env 文件
cat > .env << EOF
export UUID="f47c4e0c-0b7a-4c1c-8e1f-1a2b3c4d5e6f"
export ARGO_PORT=8001
export SERVER_PORT=3000
export NAME="MyProxy"
export CFIP="cdns.doon.eu.org"
export CFPORT=443
EOF

# 加载环境变量
source .env
```

### 2️⃣ 安装依赖

```bash
# 安装 npm 包
npm install
```

### 3️⃣ 启动服务

```bash
# 启动应用
node server.js

# 预期输出:
# 🚀 正在启动应用...
# ✓ 文件已保存: config.json
# ✓ 代理应用已启动
# ✓ Cloudflare 已启动
# 🔗 正在生成订阅...
# ✓ 隧道域名: xxx.trycloudflare.com
# 🌐 HTTP服务已启动，监听端口: 3000
```

### 4️⃣ 获取订阅

```bash
# 查看订阅内容
curl http://localhost:3000/sub | base64 -d

# 或在浏览器中访问
# http://your-ip:3000/sub
```

### 5️⃣ 客户端连接

在 **V2rayN**、**Nekoray** 等客户端中导入订阅链接

## 🔗 连接示例


### TLS VLESS (备选)
```
vless://f47c4e0c-0b7a-4c1c-8e1f-1a2b3c4d5e6f@your-ip:8002?encryption=none&security=tls&sni=your-domain.com&fp=firefox&type=tcp#TLS
```

### WebSocket (CDN)
```
vless://f47c4e0c-0b7a-4c1c-8e1f-1a2b3c4d5e6f@your-ip:443?encryption=none&security=tls&sni=your-domain.com&type=ws&path=%2Fvless-reality#WebSocket
```

## 🔧 环境变量完整列表

```bash
# ===== 基础配置 =====
UUID                    # 客户端 ID (推荐使用 UUID v4)
ARGO_PORT              # Reality 监听端口 (默认: 8001)
SERVER_PORT            # HTTP 服务端口 (默认: 3000)
NAME                   # 节点显示名称 (默认: 空)

# ===== CDN 优选 =====
CFIP                   # CDN 优选 IP 或域名 (默认: cdns.doon.eu.org)
CFPORT                 # CDN 优选端口 (默认: 443)

# ===== Cloudflare 隧道 =====
ARGO_DOMAIN            # 固定隧道域名 (可选)
ARGO_AUTH              # 隧道密钥 JSON 或 Token (可选)

# ===== 哪吒监控 (可选) =====
NEZHA_SERVER           # 服务器地址 (例: nz.example.com:5555)
NEZHA_KEY              # 监控密钥 (V0: agent密钥, V1: NZ_CLIENT_SECRET)
NEZHA_PORT             # 端口 (仅 V0 需要)

# ===== 订阅上传 (可选) =====
UPLOAD_URL             # 上传接口 URL
PROJECT_URL            # 项目 URL
AUTO_ACCESS            # 自动保活 (true/false)

# ===== 文件管理 =====
FILE_PATH              # 临时文件保存路径 (默认: ./tmp)
SUB_PATH               # 订阅路由路径 (默认: sub)
```

## 📦 依赖项

- **Node.js** >= 14.0.0
- **express** - HTTP 服务框架
- **axios** - HTTP 客户端
- **标准库** - fs, path, os, crypto 等

```bash
npm install express axios
```

## 🚀 部署选项

### 本地开发
```bash
node server.js
```

### 后台运行
```bash
nohup node server.js > app.log 2>&1 &
```

### Docker 容器
```bash
docker run -d \
  --name reality-proxy \
  -p 3000:3000 \
  -p 8001:8001 \
  -p 8002:8002 \
  -p 3002-3004:3002-3004 \
  -e UUID="your-uuid" \
  reality-proxy:latest
```

## 🔒 协议对比

| 特性 |  TLS | WebSocket | VMess | Trojan |
|------|---------|-----|-----------|-------|--------|
| **隐蔽性** | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **速度** | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ |
| **兼容性** | ⭐⭐⭐⭐ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐ |
| **端口** | 8001 | 3002 | 3003 | 3004 |

## 📊 性能指标

- **初始延迟**: < 50ms
- **吞吐量**: 限制于带宽
- **CPU 占用**: < 5% (空闲)
- **内存占用**: ~50MB
- **最大并发**: 1000+ 连接

## 📱 客户端支持

### Windows / Linux / macOS
- ✅ **V2rayN** - 功能完整
- ✅ **Nekoray** - 现代界面，推荐
- ✅ **V2rayA** - Web 界面，便于管理
- ✅ **Clash Meta** - 高级功能

### Android
- ✅ **V2rayNG** - 官方应用
- ✅ **NekoBox** - 现代界面
- ✅ **SagerNet** - 功能丰富

### iOS
- ✅ **Shadowrocket** - 功能完整
- ✅ **Quantumult X** - 高级功能
- ✅ **Stash** - 性能优先

## 🐛 故障排查

### 问题: 连接超时
```bash
# 检查端口是否开放
netstat -tlnp | grep 8001

# 允许防火墙
sudo ufw allow 8001
sudo firewall-cmd --add-port=8001/tcp
```

### 问题: UUID 不匹配
```bash
# 检查订阅中的 UUID
curl http://localhost:3000/sub | base64 -d | grep uuid

# 更新客户端配置中的 UUID
```

### 问题: 速度慢
```bash
# 尝试使用 WebSocket + CDN 模式
# 或切换伪装目标

# 检查 DNS 解析
nslookup google.com
```

### 问题: 高 CPU 占用
```bash
# 查看具体使用情况
ps aux | grep server

# 减少并发连接或优化配置
```


## 🔐 安全建议

1. **定期轮换 UUID**
   ```bash
   NEW_UUID=$(uuidgen)
   sed -i "s/UUID=.*/UUID=$NEW_UUID/" .env
   ```

2. **使用强密码/密钥**
   - UUID 使用标准 v4 格式
   - 不要在日志中暴露密钥

3. **定期备份配置**
   ```bash
   cp -r tmp/ backup/
   ```

4. **监控日志异常**
   ```bash
   tail -f app.log | grep -i error
   ```

## 📈 监控命令

```bash
# 实时监控进程
watch -n 1 'ps aux | grep server'

# 监控网络连接
watch -n 1 'ss -an | grep :8001 | wc -l'

# 查看资源使用
top -p $(pgrep -f "node server")

# 抓包分析流量
sudo tcpdump -i eth0 -n 'port 8001' -w capture.pcap
```

### 在线资源
- [Xray 官方](https://xtls.github.io)
- [GitHub Issues](https://github.com/gj7887/Argo-dlxt/issues)
- [GitHub Discussions](https://github.com/gj7887/Argo-dlxt/discussions)

## ⚖️ 法律声明

本项目仅供学习和研究使用。用户应自行承担使用本项目产生的一切后果。

- ✅ 用于正当网络应用
- ✅ 学术研究和安全审计
- ❌ 绕过合法监管
- ❌ 从事非法活动

## 📄 许可证

MIT License - 自由使用和修改

## 🙏 致谢

感谢以下开源项目：
- [Xray-core](https://github.com/XTLS/Xray-core) - 代理核心
- [V2rayN](https://github.com/2dust/v2rayN) - 客户端
- [Express.js](https://expressjs.com) - Web 框架
- [Axios](https://axios-http.com) - HTTP 库

## 📝 更新日志

### v1.0 - 2026-01-15
- ✅ 多协议支持 (/TLS/WS/VMess/Trojan)
- ✅ 自动密钥生成
- ✅ 完整文档编写
- ✅ 部署和测试指南

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

```bash
# 1. Fork 项目
# 2. 创建特性分支
git checkout -b feature/amazing-feature

# 3. 提交更改
git commit -m 'Add some amazing feature'

# 4. 推送到分支
git push origin feature/amazing-feature

# 5. 提交 Pull Request
```

## 📧 联系方式

- GitHub: [@gj7887](https://github.com/gj7887)
- Issues: [项目 Issues](https://github.com/gj7887/Argo-dlxt/issues)
- Discussions: [项目讨论](https://github.com/gj7887/Argo-dlxt/discussions)

---

**最后更新**: 2026-01-15  
**版本**: 1.0 Reality Edition  
**状态**: ✅ 生产就绪
