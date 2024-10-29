# Python3+Nftables端口转发


```shell
apt install python3-dnspython nftables
chmod +x nft-forward.sh
./nft-forward.sh
nano /etc/nft-forward/forward.conf
systemctl restart nft-forward
systemctl status nft-forward
tail -f /var/log/nft-forward.log
nft list ruleset
```

