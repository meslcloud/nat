#!/bin/bash
# install.sh - 安装 nft-forward 服务

# 检查是否为root用户
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# 创建程序目录
INSTALL_DIR="/opt/nft-forward"
mkdir -p "$INSTALL_DIR"
mkdir -p "/etc/nft-forward"

# 复制主程序
cat > "$INSTALL_DIR/nft-forward.py" << 'EOF'
#!/usr/bin/env python3
import os
import sys
import signal
import socket
import time
import threading
import subprocess
import logging
import dns.resolver
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("/var/log/nft-forward.log"),
        logging.StreamHandler()
    ]
)

@dataclass
class ForwardRule:
    local_port: int
    remote_port: int
    remote_host: str
    last_ipv4: str = ""
    last_ipv6: str = ""
    
class PortForwardManager:
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.rules: List[ForwardRule] = []
        self.running = True
        self.nft_table_name = "port_forward"
        self.table_initialized = False
        
    def init_nftables(self):
        """初始化 nftables 表和链"""
        if self.table_initialized:
            return

        try:
            # 检查并删除现有的表
            for family in ['ip', 'ip6']:
                try:
                    subprocess.run(f"nft list table {family} {self.nft_table_name}".split(), 
                                 check=True, capture_output=True)
                    subprocess.run(f"nft delete table {family} {self.nft_table_name}".split(),
                                 check=True)
                except subprocess.CalledProcessError:
                    pass

            # 创建新的表和链
            commands = []
            
            # IPv4 表和链
            commands.extend([
                f"nft add table ip {self.nft_table_name}",
                f"nft add chain ip {self.nft_table_name} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}",
                f"nft add chain ip {self.nft_table_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}"
            ])
            
            # IPv6 表和链
            commands.extend([
                f"nft add table ip6 {self.nft_table_name}",
                f"nft add chain ip6 {self.nft_table_name} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}",
                f"nft add chain ip6 {self.nft_table_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}"
            ])

            for cmd in commands:
                try:
                    subprocess.run(cmd.split(), check=True)
                    logging.info(f"Successfully executed: {cmd}")
                except subprocess.CalledProcessError as e:
                    logging.error(f"Failed to initialize nftables: {e}")
                    raise
            
            self.table_initialized = True
            
        except Exception as e:
            logging.error(f"Failed to initialize nftables: {e}")
            raise
                
    def clear_rules(self):
        """清除所有转发规则"""
        if not self.table_initialized:
            return

        try:
            # 清除 IPv4 和 IPv6 规则
            for family in ['ip', 'ip6']:
                try:
                    subprocess.run(f"nft flush table {family} {self.nft_table_name}".split(), check=True)
                    subprocess.run(f"nft delete table {family} {self.nft_table_name}".split(), check=True)
                except subprocess.CalledProcessError:
                    pass
            logging.info("Successfully cleared all rules and removed tables")
            self.table_initialized = False
        except Exception as e:
            logging.error(f"Failed to clear rules: {e}")
            
    def resolve_dns(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """解析域名为IPv4和IPv6地址"""
        ipv4 = None
        ipv6 = None
        
        try:
            # 创建解析器
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # 尝试解析 IPv4 地址
            try:
                answers = resolver.resolve(hostname, 'A')
                ipv4 = str(answers[0])
                logging.debug(f"Resolved IPv4 for {hostname}: {ipv4}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
                logging.debug(f"No IPv4 address found for {hostname}: {e}")
                
            # 尝试解析 IPv6 地址
            try:
                answers = resolver.resolve(hostname, 'AAAA')
                ipv6 = str(answers[0])
                logging.debug(f"Resolved IPv6 for {hostname}: {ipv6}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout) as e:
                logging.debug(f"No IPv6 address found for {hostname}: {e}")
                
        except Exception as e:
            logging.error(f"DNS resolution failed for {hostname}: {e}")
            
        return ipv4, ipv6
            
    def add_forward_rules(self, rules_to_update: List[ForwardRule]):
        """批量添加转发规则"""
        if not self.table_initialized or not rules_to_update:
            return
            
        with open('/tmp/nft_rules.txt', 'w') as f:
            # 清除现有规则但保持表和链
            f.write(f'flush table ip {self.nft_table_name}\n')
            f.write(f'flush table ip6 {self.nft_table_name}\n')
            
            # 重新创建链
            f.write(f'add chain ip {self.nft_table_name} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}\n')
            f.write(f'add chain ip {self.nft_table_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n')
            f.write(f'add chain ip6 {self.nft_table_name} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}\n')
            f.write(f'add chain ip6 {self.nft_table_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}\n')
            
            # 添加所有规则
            for rule in rules_to_update:
                # IPv4 规则
                if rule.last_ipv4:
                    f.write(f'add rule ip {self.nft_table_name} prerouting tcp dport {rule.local_port} dnat to {rule.last_ipv4}:{rule.remote_port}\n')
                    f.write(f'add rule ip {self.nft_table_name} prerouting udp dport {rule.local_port} dnat to {rule.last_ipv4}:{rule.remote_port}\n')
                    f.write(f'add rule ip {self.nft_table_name} postrouting ip daddr {rule.last_ipv4} masquerade\n')
                    logging.info(f"Prepared IPv4 rule: {rule.local_port} -> {rule.last_ipv4}:{rule.remote_port}")
                
                # IPv6 规则
                if rule.last_ipv6:
                    f.write(f'add rule ip6 {self.nft_table_name} prerouting tcp dport {rule.local_port} dnat to [{rule.last_ipv6}]:{rule.remote_port}\n')
                    f.write(f'add rule ip6 {self.nft_table_name} prerouting udp dport {rule.local_port} dnat to [{rule.last_ipv6}]:{rule.remote_port}\n')
                    f.write(f'add rule ip6 {self.nft_table_name} postrouting ip6 daddr {rule.last_ipv6} masquerade\n')
                    logging.info(f"Prepared IPv6 rule: {rule.local_port} -> [{rule.last_ipv6}]:{rule.remote_port}")
                
        try:
            subprocess.run(['nft', '-f', '/tmp/nft_rules.txt'], check=True)
            logging.info("Successfully applied all rules")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to apply rules: {e}")
        finally:
            os.remove('/tmp/nft_rules.txt')
            
    def load_config(self):
        """加载配置文件"""
        self.rules.clear()
        
        try:
            with open(self.config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    parts = line.split(',')
                    if len(parts) == 4 and parts[0] == 'SINGLE':
                        local_port = int(parts[1])
                        remote_port = int(parts[2])
                        remote_host = parts[3]
                        
                        self.rules.append(ForwardRule(
                            local_port=local_port,
                            remote_port=remote_port,
                            remote_host=remote_host
                        ))
                    else:
                        logging.warning(f"Invalid config line: {line}")
                        
            logging.info(f"Loaded {len(self.rules)} rules from config")
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            raise
            
    def update_rules(self):
        """更新所有转发规则"""
        try:
            self.init_nftables()
            
            rules_updated = False
            for rule in self.rules:
                ipv4, ipv6 = self.resolve_dns(rule.remote_host)
                
                if (ipv4 and ipv4 != rule.last_ipv4) or (ipv6 and ipv6 != rule.last_ipv6):
                    if ipv4:
                        rule.last_ipv4 = ipv4
                    if ipv6:
                        rule.last_ipv6 = ipv6
                    rules_updated = True
                    logging.info(f"Detected IP change for {rule.remote_host} -> IPv4: {ipv4}, IPv6: {ipv6}")
                    
            if rules_updated:
                self.add_forward_rules(self.rules)
                
        except Exception as e:
            logging.error(f"Error updating rules: {e}")
                
    def dns_monitor(self):
        """DNS监控线程"""
        while self.running:
            try:
                self.update_rules()
            except Exception as e:
                logging.error(f"Error in DNS monitor: {e}")
                
            time.sleep(300)  # 每5分钟检查一次DNS变化
            
    def signal_handler(self, signum, frame):
        """处理信号"""
        logging.info(f"Received signal {signum}")
        self.stop()
        sys.exit(0)
            
    def start(self):
        """启动端口转发管理器"""
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        try:
            self.load_config()
            self.update_rules()
            
            monitor_thread = threading.Thread(target=self.dns_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            logging.info("Port forward manager started")
            
            while self.running:
                time.sleep(1)
                    
        except Exception as e:
            logging.error(f"Fatal error: {e}")
            self.stop()
            
    def stop(self):
        """停止端口转发管理器"""
        if not self.running:
            return
            
        self.running = False
        self.clear_rules()
        logging.info("Port forward manager stopped")
        
def main():
    if os.geteuid() != 0:
        print("This program must be run as root!")
        sys.exit(1)
        
    config_file = "/etc/nft-forward/forward.conf"
    manager = PortForwardManager(config_file)
    manager.start()
    
if __name__ == "__main__":
    main()
EOF

# 创建默认配置文件
cat > "/etc/nft-forward/forward.conf" << 'EOF'
# Format: SINGLE,local_port,remote_port,remote_host
# Example: SINGLE,10025,10026,example.com
EOF

# 创建systemd服务文件
cat > "/etc/systemd/system/nft-forward.service" << 'EOF'
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

# 设置权限
chmod +x "$INSTALL_DIR/nft-forward.py"
chmod 644 "/etc/systemd/system/nft-forward.service"
chmod 644 "/etc/nft-forward/forward.conf"
touch "/var/log/nft-forward.log"
chmod 644 "/var/log/nft-forward.log"

# 重新加载systemd配置
systemctl daemon-reload

# 启用并启动服务
systemctl enable nft-forward
systemctl start nft-forward

echo "Installation completed successfully!"
echo "You can now edit /etc/nft-forward/forward.conf to add your port forwarding rules"
echo "Use the following commands to manage the service:"
echo "  systemctl start nft-forward    - Start the service"
echo "  systemctl stop nft-forward     - Stop the service"
echo "  systemctl restart nft-forward  - Restart the service"
echo "  systemctl status nft-forward   - Check service status"
echo "  tail -f /var/log/nft-forward.log  - View logs"
