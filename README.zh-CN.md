# DNS Hint Filter

[English](README.md) | 简体中文

一个 Python 3.9+ UDP DNS 转发服务，适合 Debian / Fedora 上的本机 Firefox 或受信任局域网使用。

```text
Firefox（关闭 DoH）→ 系统 DNS → 本服务 → 上游 UDP DNS
                             ← 移除 HTTPS 记录中的 ipv4hint / ipv6hint
```

## 行为

- 按来源 IPv4 / IPv6 CIDR 放行；未放行的请求直接丢弃，不访问上游。
- 转发普通 DNS 查询，只改写类型 65（HTTPS）记录；检查 Answer、Authority、Additional 三个区域。
- 保留 TTL、优先级、目标域名、`alpn`、`port`、`ech` 以及未知参数；A、AAAA 和类型 64（SVCB）不做内容改写。
- 同步删除 `mandatory` 中的 hint 引用；列表变空时删除整个 `mandatory` 参数。
- 为每次查询使用独立 UDP socket 和随机上游查询 ID，校验响应来源和请求匹配关系。
- 上游超时返回 SERVFAIL；设置共享并发上限，过载请求直接丢弃。默认不记录查询域名。

## 获取项目

```bash
git clone https://github.com/maigougou/dns-hint-filter.git
cd dns-hint-filter
```

也可从 [Releases](https://github.com/maigougou/dns-hint-filter/releases) 下载版本压缩包。

## Debian 上安装依赖

Debian 13 可以使用系统软件包：

```bash
sudo apt update
sudo apt install python3 python3-dnspython bind9-dnsutils
```

Debian 12 的仓库版本 dnspython 2.3.0 低于项目要求。使用独立虚拟环境：

```bash
sudo apt update
sudo apt install python3 python3-venv bind9-dnsutils
sudo python3 -m venv /opt/dns-hint-filter/venv
sudo /opt/dns-hint-filter/venv/bin/python -m pip install -r requirements.txt
```

随后将下文运行命令中的 `python3` 换成 `/opt/dns-hint-filter/venv/bin/python`，安装服务前将 `dns-hint-filter.service` 的 `ExecStart` 换为：

```ini
ExecStart=/opt/dns-hint-filter/venv/bin/python /usr/local/lib/dns-hint-filter/dns_hint_filter.py --config /etc/dns-hint-filter.json
```

这也适用于希望隔离 Python 依赖的 Debian 13。不要将服务虚拟环境放在用户 home 目录，因为服务启用了 `ProtectHome=yes`。

## Fedora 上安装依赖

在项目目录中执行：

```bash
sudo dnf install python3 python3-dns bind-utils
```

Fedora 的 dnspython 包名随版本有差别。如果仓库没有 `python3-dns`，使用 `python3-dnspython`。需要 dnspython 2.6.1 或更新的 2.x 版本；可运行 `python3 -c 'import dns; print(dns.__version__)'` 查看。

## 前台试用

安装依赖后执行：

```bash
cp config.example.json config.json
python3 dns_hint_filter.py --config config.json --check-config
python3 dns_hint_filter.py --config config.json --verbose
```

示例配置监听 `127.0.0.1:5300` 和 `[::1]:5300`，仅放行本机，上游为 `1.1.1.1:53`。可直接编辑 JSON 更换上游，必须填写 IP 地址；IPv6 地址直接写 `2001:db8::53` 这样的形式，不加方括号。上游不能通过本服务再次解析，避免转发环路。

另开终端对比（域名可换成你要测试的站点）：

```bash
dig @1.1.1.1 cloudflare.com TYPE65 +ignore
dig @127.0.0.1 -p 5300 cloudflare.com TYPE65 +ignore
dig @127.0.0.1 -p 5300 example.com A +ignore
```

如果上游响应含有 hints，第二条输出应不再含有 `ipv4hint` / `ipv6hint`，其余 HTTPS 参数仍在。若上游本身没有 hints，这次查询不能证明过滤效果；下方自动测试使用固定的模拟上游覆盖此情况。`+ignore` 避免 dig 遇到 TC 后自动改用 TCP。

## 安装为 systemd 服务

确认前台试用正常后停止前台进程，将 `config.json` 的 `port` 改为 **53**。系统 DNS 通常不能直接指定 5300 这样的端口。

先检查端口占用：

```bash
sudo ss -lunp 'sport = :53'
```

如果 systemd-resolved 仅监听 `127.0.0.53:53`，可以保留它，让本服务监听 `127.0.0.1:53`。如果已有服务占用 `0.0.0.0:53` 或同一具体地址，先调整监听地址；不要让上游指向稍后又会转发回本服务的 systemd-resolved。

```bash
sudo install -d -m 0755 /usr/local/lib/dns-hint-filter
sudo install -m 0644 dns_hint_filter.py /usr/local/lib/dns-hint-filter/dns_hint_filter.py
sudo install -m 0644 config.json /etc/dns-hint-filter.json
sudo install -m 0644 dns-hint-filter.service /etc/systemd/system/dns-hint-filter.service
if command -v restorecon >/dev/null 2>&1; then
  sudo restorecon -RF /usr/local/lib/dns-hint-filter /etc/dns-hint-filter.json /etc/systemd/system/dns-hint-filter.service
fi
sudo systemctl daemon-reload
sudo systemctl enable --now dns-hint-filter
sudo systemctl status dns-hint-filter --no-pager
dig @127.0.0.1 cloudflare.com TYPE65 +ignore
```

服务使用动态非 root 用户，仅授予绑定低端口所需能力，并限制文件系统写入。配置读取后保存在内存中，修改 `/etc/dns-hint-filter.json` 后执行 `sudo systemctl restart dns-hint-filter`。日志：

```bash
journalctl -u dns-hint-filter -f
```

## 让 Firefox 使用它

1. Firefox → 设置 → 隐私与安全 → DNS over HTTPS → 选择 **关闭 / Off**。也可在 `about:config` 将 `network.trr.mode` 设置为 `5`。开启 DoH 时 Firefox 可能绕过系统 DNS，本程序不提供 DoH 接口。
2. 把当前连接的 DNS 指向 `127.0.0.1`，并关闭该连接通过 DHCP / IPv6 RA 自动获得 DNS 的设置。
3. 清除系统和 Firefox 的 DNS 缓存：`sudo resolvectl flush-caches`（使用 systemd-resolved 时），以及 `about:networking#dns` 中的 Clear DNS Cache；必要时重启 Firefox。

以下命令仅适用于 NetworkManager。Debian 如果使用 ifupdown、systemd-networkd 或其他管理工具，应通过实际的管理工具配置 DNS，不要直接覆盖受管理的 `/etc/resolv.conf`。仅在安装并使用 systemd-resolved 时运行 `resolvectl`。

NetworkManager 的命令示例，先用 `nmcli connection show --active` 找到实际连接名：

```bash
CONNECTION='替换为你的连接名'
nmcli -f ipv4.dns,ipv4.ignore-auto-dns,ipv4.dns-priority,ipv4.dns-search,ipv6.dns,ipv6.ignore-auto-dns,ipv6.dns-priority connection show "$CONNECTION" > dns-settings-before.txt
sudo nmcli connection modify "$CONNECTION" \
  ipv4.dns '127.0.0.1' ipv4.ignore-auto-dns yes \
  ipv4.dns-priority -100 ipv4.dns-search '~.' \
  ipv6.dns '' ipv6.ignore-auto-dns yes ipv6.dns-priority -100
sudo nmcli connection up "$CONNECTION"
resolvectl status
```

重新激活连接可能短暂断网。`~.` 将默认 DNS 路由交给这个连接；负优先级有助于排除其他连接的 DNS。VPN、其他活动连接或已有全局 DNS 配置仍需根据 `resolvectl status` 核对，尤其不要让备用 DNS 绕过过滤。上例会替换此连接原有搜索域，如需企业内网解析，应保留相应域并按实际网络配置分流。

系统 DNS 变化影响该连接上的其他应用。此程序只过滤实际经过它的类型 65 记录，不会强制 Firefox 发起 HTTPS 查询，也不会移除网站的 A / AAAA 地址或禁止 IPv6 连接。

## 允许局域网客户端

例如服务器的固定 LAN 地址为 `192.168.1.10`，允许 `192.168.1.0/24`：

```json
{
  "listen": ["127.0.0.1", "192.168.1.10"],
  "port": 53,
  "allow": ["127.0.0.0/8", "192.168.1.0/24"],
  "upstream": "1.1.1.1",
  "upstream_port": 53,
  "timeout": 3.0,
  "max_inflight": 256
}
```

替换地址和网段后重启服务，让客户端 DNS 指向 `192.168.1.10`。IPv6 同理，将主机的 IPv6 地址加入 `listen`，将允许的 IPv6 CIDR 加入 `allow`。`listen` 也支持 `0.0.0.0` / `::`，但只绑定实际需要的地址更便于管理。

若使用 firewalld，查看接口所属 zone，并只允许目标网段访问 UDP 53；例如接口位于 `public`。Debian 若使用 nftables / UFW，应在相应防火墙中配置，无需为了本项目更换防火墙：

```bash
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --permanent --zone=public --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="53" protocol="udp" accept'
sudo firewall-cmd --reload
```

ACL 检查的是服务实际看到的来源 IP。若客户端经过 NAT 或另一个 DNS 转发器，应按其出口地址配置；CIDR 放行不是身份认证。

## 协议边界

- **UDP only**：客户端到本服务、服务到上游均只使用 UDP。上游 TC 标志保留；超过客户端限制的响应会重新截断。EDNS 最大广告尺寸为 1232 字节，无 EDNS 时为 512 字节。需要 TCP 才能取回的完整响应无法由此版本提供，因此不等同于完整通用 DNS 服务器。
- **DNSSEC**：修改 HTTPS RRset 后原签名失效，因此清除响应 AD 标志并删除该 RRset 对应的 RRSIG。其他记录及签名保留。本服务不做 DNSSEC 验证；需要保留上游验证时，应将验证解析器放在过滤器之前。自行验证 DNSSEC 的下游（包括配置了强制验证的 systemd-resolved）会拒绝改写记录；清除 AD 不能解决这种不兼容。
- **查询范围**：普通单问题 QUERY；不支持 UPDATE、区域传送、TSIG / SIG(0) 签名代理。畸形报文丢弃，失败的上游查询返回 SERVFAIL。
- **无缓存、无上游故障切换**：缓存可由系统 stub 或上游提供；修改配置后注意清理旧缓存。

## 测试

在已安装 dnspython 的环境中：

```bash
python3 -m unittest discover -s tests -v
```

测试不依赖公网 DNS，使用随机本机 UDP 端口，覆盖多区域 / 多条 HTTPS 记录、mandatory、其他参数保留、DNSSEC 签名清理、ACL、UDP 超时、错误响应过滤、TC、响应尺寸和同 ID 并发请求。

自动测试使用本机模拟上游，不依赖公网 DNS。GitHub Actions 配置覆盖多个 Python 版本及 Debian / Fedora 容器，结果见仓库 Actions 页面；systemd 开机运行、SELinux、firewalld 和 Firefox 接入仍需在目标机器验证。

## 停用与恢复

先按 `dns-settings-before.txt` 恢复 NetworkManager 原始 DNS 设置并重新激活连接，确认系统解析恢复，再执行 `sudo systemctl disable --now dns-hint-filter`。如果加过 firewalld rich rule，用相同规则配合 `--remove-rich-rule` 删除并 reload。需要时恢复 Firefox 原来的 DoH 设置。

## 参考

- [RFC 9460：HTTPS / SVCB、地址 hints 和 mandatory](https://www.rfc-editor.org/rfc/rfc9460.html)
- [dnspython：DNS 消息与截断](https://dnspython.readthedocs.io/en/stable/message-class.html)
- [Fedora python3-dns 软件包](https://packages.fedoraproject.org/pkgs/python-dns/python3-dns/)
- [Firefox DoH 设置](https://support.mozilla.org/en-US/kb/dns-over-https)
- [Mozilla：DNSOverHTTPS 策略与 network.trr.mode](https://firefox-admin-docs.mozilla.org/reference/policies/dnsoverhttps/)
- [NetworkManager IPv4 DNS 配置](https://networkmanager.dev/docs/api/latest/settings-ipv4.html)
