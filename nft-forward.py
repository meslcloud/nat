#!/usr/bin/env python3
import os
import sys
import signal
import socket
import time
import threading
import subprocess
import logging
import ipaddress
import netifaces
from dataclasses import dataclass
from typing import List, Dict, Optional, Set, Tuple

def run_cmd(cmd: str, check: bool = True) -> Tuple[bool, str]:
    """执行shell命令并返回结果"""
    try:
        result = subprocess.run(cmd.split(), capture_output=True, text=True, check=check)
        return True, result.stdout
    except subprocess.CalledProcessError as e:
        return False, e.stderr

@dataclass
class ForwardRule:
    local_port: int
    remote_port: int
    remote_host: str
    source_ip: str = ""
    last_ipv4: str = ""
    last_ipv6: str = ""
    is_ip: bool = False
    
    def __str__(self):
        src_ip = self.source_ip if self.source_ip else "auto"
        return f"Rule: {self.local_port} -> {self.remote_host}:{self.remote_port} (Source IP: {src_ip})"

class PortForwardManager:
    def __init__(self, config_file: str):
        self.config_file = config_file
        self.rules: List[ForwardRule] = []
        self.running = True
        self.nft_table_name = "port_forward"
        
        # 配置日志
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler("/var/log/nft-forward.log")
            ]
        )
        
        self.default_source_ips = self.get_default_ips()
        logging.info(f"Detected default source IPs: {self.default_source_ips}")

    def get_default_ips(self) -> Dict[str, str]:
        """获取默认的源IP地址"""
        default_ips = {'ipv4': None, 'ipv6': None}
        try:
            interfaces = netifaces.interfaces()
            for iface in interfaces:
                if iface == 'lo':
                    continue
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs and not default_ips['ipv4']:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('169.254.'):
                            default_ips['ipv4'] = ip
                            break
                if netifaces.AF_INET6 in addrs and not default_ips['ipv6']:
                    for addr in addrs[netifaces.AF_INET6]:
                        ip = addr['addr']
                        if not ip.startswith('fe80:'):
                            ip = ip.split('%')[0]
                            default_ips['ipv6'] = ip
                            break
        except Exception as e:
            logging.error(f"Error getting default IPs: {e}")
        return default_ips

    def is_valid_ip(self, addr: str) -> Tuple[bool, str]:
        """检查是否为有效的IP地址"""
        try:
            ip = ipaddress.ip_address(addr)
            return True, 'ipv4' if isinstance(ip, ipaddress.IPv4Address) else 'ipv6'
        except ValueError:
            return False, ''

    def resolve_dns(self, hostname: str) -> Tuple[Optional[str], Optional[str]]:
        """解析域名为IPv4和IPv6地址"""
        ipv4, ipv6 = None, None
        try:
            addrinfo = socket.getaddrinfo(hostname, None)
            for info in addrinfo:
                family, _, _, _, addr = info
                ip = addr[0]
                if family == socket.AF_INET:
                    ipv4 = ip
                elif family == socket.AF_INET6:
                    ipv6 = ip
        except Exception as e:
            logging.error(f"Error resolving DNS for {hostname}: {e}")
        return ipv4, ipv6

    def delete_tables(self):
        """删除现有的表"""
        for family in ['ip', 'ip6']:
            cmd = f'nft delete table {family} {self.nft_table_name}'
            run_cmd(cmd, check=False)

    def create_tables(self) -> bool:
        """创建表和基本链"""
        nft_rules = f'''
add table ip {self.nft_table_name}
add chain ip {self.nft_table_name} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}
add chain ip {self.nft_table_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}

add table ip6 {self.nft_table_name}
add chain ip6 {self.nft_table_name} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}
add chain ip6 {self.nft_table_name} postrouting {{ type nat hook postrouting priority srcnat; policy accept; }}
'''
        rules_file = '/tmp/nft_rules.txt'
        try:
            with open(rules_file, 'w') as f:
                f.write(nft_rules)
            success, output = run_cmd(f'nft -f {rules_file}')
            if not success:
                logging.error(f"Failed to create tables: {output}")
            return success
        finally:
            if os.path.exists(rules_file):
                os.remove(rules_file)

    def update_forward_rules(self) -> bool:
        """更新所有转发规则"""
        logging.info("Updating forwarding rules...")
        
        # 解析所有域名
        for rule in self.rules:
            if not rule.is_ip:
                ipv4, ipv6 = self.resolve_dns(rule.remote_host)
                if ipv4:
                    rule.last_ipv4 = ipv4
                if ipv6:
                    rule.last_ipv6 = ipv6
        
        # 删除现有表
        self.delete_tables()
        
        # 创建新表和链
        if not self.create_tables():
            return False
            
        # 添加端口转发规则
        return self.add_port_rules()

    def add_port_rules(self) -> bool:
        """添加端口转发规则"""
        if not self.rules:
            return True

        nft_rules = []
        for rule in self.rules:
            if rule.last_ipv4:
                source_ip = self.get_source_ip(rule, 'ipv4')
                if source_ip:
                    nft_rules.extend([
                        f'add rule ip {self.nft_table_name} prerouting tcp dport {rule.local_port} dnat to {rule.last_ipv4}:{rule.remote_port}',
                        f'add rule ip {self.nft_table_name} prerouting udp dport {rule.local_port} dnat to {rule.last_ipv4}:{rule.remote_port}',
                        f'add rule ip {self.nft_table_name} postrouting ip daddr {rule.last_ipv4} tcp dport {rule.remote_port} snat to {source_ip}',
                        f'add rule ip {self.nft_table_name} postrouting ip daddr {rule.last_ipv4} udp dport {rule.remote_port} snat to {source_ip}'
                    ])

            if rule.last_ipv6:
                source_ip = self.get_source_ip(rule, 'ipv6')
                if source_ip:
                    nft_rules.extend([
                        f'add rule ip6 {self.nft_table_name} prerouting tcp dport {rule.local_port} dnat to [{rule.last_ipv6}]:{rule.remote_port}',
                        f'add rule ip6 {self.nft_table_name} prerouting udp dport {rule.local_port} dnat to [{rule.last_ipv6}]:{rule.remote_port}',
                        f'add rule ip6 {self.nft_table_name} postrouting ip6 daddr {rule.last_ipv6} tcp dport {rule.remote_port} snat to {source_ip}',
                        f'add rule ip6 {self.nft_table_name} postrouting ip6 daddr {rule.last_ipv6} udp dport {rule.remote_port} snat to {source_ip}'
                    ])

        if not nft_rules:
            return True

        rules_file = '/tmp/nft_port_rules.txt'
        try:
            with open(rules_file, 'w') as f:
                f.write('\n'.join(nft_rules) + '\n')
            success, output = run_cmd(f'nft -f {rules_file}')
            if not success:
                logging.error(f"Failed to add port rules: {output}")
            return success
        finally:
            if os.path.exists(rules_file):
                os.remove(rules_file)

    def get_source_ip(self, rule: ForwardRule, ip_version: str) -> str:
        """获取源IP地址"""
        if rule.source_ip:
            return rule.source_ip
        return self.default_source_ips.get(ip_version)
        
    def load_config(self):
        """加载配置文件"""
        self.rules.clear()
        
        if not os.path.exists(self.config_file):
            logging.error(f"Config file not found: {self.config_file}")
            return
            
        try:
            with open(self.config_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                        
                    parts = line.split(',')
                    if len(parts) >= 4 and parts[0] == 'SINGLE':  # 支持4或5个字段
                        try:
                            local_port = int(parts[1])
                            remote_port = int(parts[2])
                            remote_host = parts[3].strip()
                            source_ip = parts[4].strip() if len(parts) > 4 else ""  # 可选的源IP
                            
                            # 如果指定了源IP，验证其有效性
                            if source_ip:
                                is_valid_source_ip, _ = self.is_valid_ip(source_ip)
                                if not is_valid_source_ip:
                                    logging.error(f"Invalid source IP address: {source_ip}")
                                    continue
                            
                            # 检查是否是IP地址
                            is_ip, ip_version = self.is_valid_ip(remote_host)
                            
                            rule = ForwardRule(
                                local_port=local_port,
                                remote_port=remote_port,
                                remote_host=remote_host,
                                source_ip=source_ip,
                                is_ip=is_ip
                            )
                            
                            # 如果是IP地址，直接设置
                            if is_ip:
                                if ip_version == 'ipv4':
                                    rule.last_ipv4 = remote_host
                                else:
                                    rule.last_ipv6 = remote_host
                                logging.info(f"Loaded IP rule: {rule}")
                            else:
                                logging.info(f"Loaded domain rule: {rule}")
                            
                            self.rules.append(rule)
                            
                        except ValueError as e:
                            logging.error(f"Invalid port number in line: {line}")
                    else:
                        logging.warning(f"Skipped invalid config line: {line}")
                        
            logging.info(f"Successfully loaded {len(self.rules)} rules from {self.config_file}")
            
        except Exception as e:
            logging.error(f"Failed to load config: {e}")
            raise

    def update_rules(self):
        """更新所有转发规则"""
        try:
            if not self.update_forward_rules():
                logging.error("Failed to update forward rules")
        except Exception as e:
            logging.error(f"Error updating rules: {e}")

    def dns_monitor(self):
        """DNS监控线程"""
        while self.running:
            try:
                update_needed = False
                
                # 检查所有域名规则
                for rule in self.rules:
                    if not rule.is_ip:  # 只检查域名规则
                        ipv4, ipv6 = self.resolve_dns(rule.remote_host)
                        if ipv4 != rule.last_ipv4 or ipv6 != rule.last_ipv6:
                            update_needed = True
                            if ipv4:
                                logging.info(f"IP changed for {rule.remote_host}: {rule.last_ipv4} -> {ipv4}")
                                rule.last_ipv4 = ipv4
                            if ipv6:
                                logging.info(f"IPv6 changed for {rule.remote_host}: {rule.last_ipv6} -> {ipv6}")
                                rule.last_ipv6 = ipv6
                
                # 如果有IP变化，更新规则
                if update_needed:
                    self.update_rules()
                    
            except Exception as e:
                logging.error(f"Error in DNS monitor: {e}")
                
            time.sleep(60)  # 每1分钟检查一次
            
    def signal_handler(self, signum, frame):
        """处理信号"""
        logging.info(f"Received signal {signum}")
        self.stop()
        sys.exit(0)
            
    def start(self):
        """启动端口转发管理器"""
        logging.info("Starting port forward manager...")
        
        signal.signal(signal.SIGTERM, self.signal_handler)
        signal.signal(signal.SIGINT, self.signal_handler)

        try:
            self.load_config()
            if not self.rules:
                logging.error("No valid rules loaded, exiting")
                return
                
            self.update_forward_rules()
            
            # 启动DNS监控线程
            monitor_thread = threading.Thread(target=self.dns_monitor)
            monitor_thread.daemon = True
            monitor_thread.start()
            
            logging.info("Port forward manager is running")
            
            while self.running:
                time.sleep(1)
                    
        except Exception as e:
            logging.error(f"Fatal error: {e}")
            self.stop()
            
    def stop(self):
        """停止端口转发管理器"""
        if not self.running:
            return
            
        logging.info("Stopping port forward manager...")
        self.running = False
        self.delete_tables()
        logging.info("Port forward manager stopped")

def main():
    if os.geteuid() != 0:
        print("This program must be run as root!")
        sys.exit(1)
        
    config_file = "/etc/nft-forward/forward.conf"
    
    if not os.path.exists(config_file):
        print(f"Config file not found: {config_file}")
        sys.exit(1)
        
    manager = PortForwardManager(config_file)
    manager.start()
    
if __name__ == "__main__":
    main()
