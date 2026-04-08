# WebRTC NAT 类型检测工具

基于 Twin-Server 架构的 NAT 类型深度检测工具，可检测：
- ✅ 公网/直连 (Open Internet)
- ✅ 全锥形 NAT (Full Cone)
- ✅ 地址受限锥形 NAT (Address-Restricted)
- ✅ 端口受限锥形 NAT (Port-Restricted)
- ✅ 对称型 NAT (Symmetric)
- ✅ UDP 被屏蔽 (UDP Blocked)

---

## 快速开始 (Docker Compose)

### 1. Fork 并克隆项目

```bash
git clone https://github.com/<你的用户名>/webrtc_check_nat.git
cd webrtc_check_nat
```

### 2. 启动服务

```bash
docker-compose up -d
```

### 3. 访问服务

打开浏览器访问 http://localhost:8080

---

## 配置说明

### 修改端口映射

编辑 [docker-compose.yml](docker-compose.yml) 文件：

```yaml
services:
  primary:
    ports:
      - "8080:8080"      # HTTP 端口，可修改为 "80:8080"
      - "3478:3478/udp"  # STUN 端口 1
      - "3479:3479/udp"  # STUN 端口 2
  secondary:
    ports:
      - "8081:8081"      # 辅助节点 HTTP 端口
      - "3478:3478/udp"  # STUN 端口
```

### 仅使用主节点 (基础检测)

如果不需要检测 Full Cone NAT，可以只启动主节点：

```yaml
version: '3.8'

services:
  primary:
    build: .
    ports:
      - "8080:8080"
      - "3478:3478/udp"
      - "3479:3479/udp"
    command: ["--mode", "primary", "--port", "8080"]
```

> 注意：无 secondary 节点时，只能区分 Symmetric vs Cone，无法检测 Full/Restricted 子类型。

### 双服务器部署 (生产环境)

如需在不同公网 IP 的服务器上部署，修改 `SECONDARY_HOST` 环境变量：

```yaml
services:
  primary:
    environment:
      - SECONDARY_HOST=secondary.yourdomain.com
```

---

## 手动运行 (不使用 Docker)

### 依赖

```bash
pip install aiohttp
```

### 主节点（同时托管 HTML）

```bash
python natcheck.py --mode primary --port 8080 --secondary-url http://<辅助节点IP>:8081
```

### 辅助节点（必须！）

```bash
python natcheck.py --mode secondary --port 8081
```

---

## 停止服务

```bash
docker-compose down
```

查看日志：

```bash
docker-compose logs -f
```

---

## 技术原理

详见 [nat_detector_explanation.md](nat_detector_explanation.md)