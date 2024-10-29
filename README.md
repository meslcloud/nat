# Python3+Nftables

```shell
apt update
apt install python3-dnspython nftables
wget https://raw.githubusercontent.com/meslcloud/nat/refs/heads/main/nft-forward.sh
chmod +x nft-forward.sh
./nft-forward.sh
nano /etc/nft-forward/forward.conf
systemctl restart nft-forward
systemctl status nft-forward
tail -f /var/log/nft-forward.log
nft list ruleset
```

