## 基于Python3和Nftables的TCP+UDP端口转发
> 支持DDNS域名，IPV6，自定义源站IP
* 安装依赖：
```shell
apt update
apt install nftables python3-dnspython python3-netifaces
```

* 拉取nft-forward.sh：
```shell
wget https://raw.githubusercontent.com/meslcloud/nat/refs/heads/main/nft-forward.sh
```

* 赋权执行：
```shell
chmod +x nft-forward.sh
./nft-forward.sh
```

* 编辑配置文件：
```shell
nano /etc/nft-forward/forward.conf
# 自动选择源IP
SINGLE,local_port,remote_port,remote_host
# 手动指定源IP
SINGLE,local_port,remote_port,remote_host,source_ip
```

* 启用：
```shell
systemctl restart nft-forward
systemctl status nft-forward
```

* 查看规则和日志：
```shell
tail -f /var/log/nft-forward.log
nft list ruleset
```

> 程序 /opt/nft-forward/ <br />
> 配置 /etc/nft-forward/ <br />
> 日志 /var/log/nft-forward.log <br />
