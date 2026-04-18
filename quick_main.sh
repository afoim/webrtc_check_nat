echo 更新APT
apt update && apt upgrade
echo 安装 curl, git
apt install -y curl git
echo 安装UV
curl -LsSf https://astral.sh/uv/install.sh | sh
echo 创建虚拟环境
uv venv
echo 安装 aiohttp pip包
uv pip install aiohttp
echo 已完成，手动运行以下命令以启动主节点
echo uv run natcheck.py --mode primary --port 8080 --secondary-url http://{sip}:8081
