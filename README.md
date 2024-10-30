## 基于Nftables的TCP+UDP端口转发
> 支持DDNS和IPV6
* 安装python3-dnspython+Nftables：
```shell
apt update
apt install python3-dnspython nftables
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
#SINGLE,10025,10026,abc.com
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
