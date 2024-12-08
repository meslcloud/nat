#!/bin/bash

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# 安装依赖
echo "Installing dependencies..."
apt-get update
apt-get install -y nftables python3-dnspython python3-netifaces curl 

# 创建必要的目录
mkdir -p /etc/nft-forward
mkdir -p /opt/nft-forward

# 下载Python脚本
echo "Downloading nft-forward.py..."
curl -o /opt/nft-forward/nft-forward.py https://raw.githubusercontent.com/meslcloud/nat/refs/heads/main/nft-forward.py

# 设置执行权限
chmod +x /opt/nft-forward/nft-forward.py

# 创建默认配置文件（如果不存在）
if [ ! -f /etc/nft-forward/forward.conf ]; then
    echo "Creating default config file..."
    cat > /etc/nft-forward/forward.conf << 'EOF'
# Format: SINGLE,local_port,remote_port,remote_host[,source_ip]
# Example with auto source IP: SINGLE,80,8080,192.168.1.100
# Example with manual source IP: SINGLE,80,8080,192.168.1.100,172.16.1.10
EOF
fi

# 创建日志文件
touch /var/log/nft-forward.log
chmod 644 /var/log/nft-forward.log

# 创建systemd服务文件
echo "Creating systemd service..."
cat > /etc/systemd/system/nft-forward.service << 'EOF'
[Unit]
Description=NFTables Port Forward Manager
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/nft-forward/nft-forward.py
Restart=always
RestartSec=30
User=root
StandardOutput=append:/var/log/nft-forward.log
StandardError=append:/var/log/nft-forward.log

[Install]
WantedBy=multi-user.target
EOF

# 重新加载systemd配置
systemctl daemon-reload

# 启用并启动服务
echo "Enabling and starting service..."
systemctl enable nft-forward
systemctl start nft-forward

echo "Installation completed successfully!"
echo "Please edit /etc/nft-forward/forward.conf to add your port forwarding rules"
echo ""
echo "Management commands:"
echo "  systemctl start nft-forward    - Start the service"
echo "  systemctl stop nft-forward     - Stop the service"
echo "  systemctl restart nft-forward  - Restart the service"
echo "  systemctl status nft-forward   - Check service status"
echo "  tail -f /var/log/nft-forward.log  - View logs"
