# FAQ

**问:** 自从我安装 OpenVPN 以来，脚本已经更新了。我如何更新？

**答:** 你无法直接更新。管理脚本的更新和新功能需要太多工作。你唯一的解决方案是卸载 OpenVPN 并使用更新后的脚本重新安装。

当然，你可以（甚至推荐）使用你的包管理器更新 `openvpn` 包。

---

**问:** 我如何在证书过期前续订它们？

**答:** 使用 CLI 命令续订证书：

```bash
# 续订客户端证书
./openvpn-install.sh client renew alice

# 使用自定义有效期续订（365 天）
./openvpn-install.sh client renew alice --cert-days 365

# 续订服务器证书
./openvpn-install.sh server renew
```

对于客户端续订，将生成一个新的 `.ovpn` 文件，你需要将其分发给客户端。对于服务器续订，需要重启 OpenVPN 服务（脚本会提示你）。

---

**问:** 我如何检查 DNS 泄漏？

**答:** 使用浏览器访问 [browserleaks.com](https://browserleaks.com/dns) 或 [ipleak.net](https://ipleak.net/)（两者都执行 IPv4 和 IPv6 检查）。你的 IP 不应该显示出来（使用和不使用 VPN 测试）。DNS 服务器应该是你在设置过程中选择的服务器，而不是你的 IP 地址或 ISP 的 DNS 服务器地址。

---

**问:** 我如何修复 DNS 泄漏？

**答:** 在 Windows 10 上，默认使用 `block-outside-dns` 选项阻止 DNS 泄漏。
在 Linux 上，你需要根据你的发行版将这些行添加到你的 `.ovpn` 文件中。

Debian 9, 10 和 Ubuntu 16.04, 18.04

```
script-security 2
up /etc/openvpn/update-resolv-conf
down /etc/openvpn/update-resolv-conf
```

CentOS 6, 7

```
script-security 2
up /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.up
down /usr/share/doc/openvpn-2.4.8/contrib/pull-resolv-conf/client.down
```

CentOS 8, Fedora 30, 31

```
script-security 2
up /usr/share/doc/openvpn/contrib/pull-resolv-conf/client.up
down /usr/share/doc/openvpn/contrib/pull-resolv-conf/client.down
```

Arch Linux

```
script-security 2
up /usr/share/openvpn/contrib/pull-resolv-conf/client.up
down /usr/share/openvpn/contrib/pull-resolv-conf/client.down
```

---

**问:** IPv6 在我的 Hetzner VM 上不工作

**答:** 这是他们那边的问题。请参阅 <https://angristan.xyz/fix-ipv6-hetzner-cloud/>

---

**问:** DNS 在我的 Linux 客户端上不工作

**答:** 请参阅 "我如何修复 DNS 泄漏？" 问题

---

**问:** 脚本会做出哪些 sysctl 和防火墙更改？

**答:** 如果 firewalld 处于活动状态，脚本使用 `firewall-cmd --permanent` 来配置端口、伪装和富规则。否则，iptables 规则保存在 `/etc/iptables/add-openvpn-rules.sh` 和 `/etc/iptables/rm-openvpn-rules.sh`，由 `/etc/systemd/system/iptables-openvpn.service` 管理。

Sysctl 选项位于 `/etc/sysctl.d/99-openvpn.conf`

---

**问:** 我如何访问连接到同一 OpenVPN 服务器的其他客户端？

**答:** 在你的 `server.conf` 中添加 `client-to-client`

---

**问:** 我的路由器无法连接

**答:**

- `Options error: No closing quotation (") in config.ovpn:46` :

  在被问及是否自定义加密设置时输入 `yes` 并选择 `tls-auth`

---

**问:** 我如何访问 OpenVPN 服务器所在局域网中的计算机？

**答:** 需要两个步骤：

1. **向客户端推送路由** - 将局域网子网添加到 `/etc/openvpn/server/server.conf`：

   ```
   push "route 192.168.1.0 255.255.255.0"
   ```

   将 `192.168.1.0/24` 替换为你实际的局域网子网。

2. **启用路由回到 VPN 客户端** - 选择以下选项之一：
   - **选项 A：在路由器上添加静态路由**（当你可以配置路由器时推荐）

     在你的局域网路由器上，为 VPN 子网（默认 `10.8.0.0/24`）添加一条指向 OpenVPN 服务器局域网 IP 的路由。这允许局域网设备在没有 NAT 的情况下回复 VPN 客户端。

   - **选项 B：将 VPN 流量伪装到局域网**

     如果你无法修改路由器，添加一个伪装规则，使 VPN 流量看起来来自服务器：

     ```bash
     # iptables
     iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -d 192.168.1.0/24 -j MASQUERADE

     # 或 nftables
     nft add rule ip nat postrouting ip saddr 10.8.0.0/24 ip daddr 192.168.1.0/24 masquerade
     ```

     通过将其添加到你的防火墙脚本中使其持久化。

修改后重启 OpenVPN：`systemctl restart openvpn-server@server`

---

**问:** 我如何一次性添加多个用户？

**答:** 以下是一个实现此目的的示例 Bash 脚本：

```bash
#!/bin/bash
userlist=(user1 user2 user3)

for user in "${userlist[@]}"; do
  ./openvpn-install.sh client add "$user"
done
```

从文本文件中的列表：

```bash
#!/bin/bash
while read -r user; do
  ./openvpn-install.sh client add "$user"
done < users.txt
```

添加受密码保护的客户端：

```bash
#!/bin/bash
./openvpn-install.sh client add alice --password "secretpass123"
```

---

**问:** 我如何更改为未来客户端创建的默认 `.ovpn` 文件？

**答:** 你可以通过编辑 `/etc/openvpn/server/client-template.txt` 来修改创建 `.ovpn` 文件的模板

---

**问:** 对于我的客户端 - 我想设置我的内部网络通过 VPN 访问，其余部分通过我的互联网访问？

**答:** 你需要编辑 `.ovpn` 文件。你可以通过编辑 `/etc/openvpn/server/client-template.txt` 文件来修改创建这些文件的模板，并添加

```sh
route-nopull
route 10.0.0.0 255.0.0.0
```

例如 - 这里会将所有 `10.0.0.0/8` 流量路由到 VPN，其余通过互联网。

---

**问:** 我如何在服务器上配置拆分隧道模式（只为所有客户端通过 VPN 路由特定网络）？

**答:** 默认情况下，脚本配置全隧道模式，所有客户端流量都通过 VPN。要配置拆分隧道（仅特定网络通过 VPN 路由），编辑 `/etc/openvpn/server/server.conf`：

1. 删除或注释掉 redirect-gateway 行：

   ```
   #push "redirect-gateway def1 bypass-dhcp"
   ```

2. 为你想要隧道的网络添加路由：

   ```
   push "route 10.0.0.0 255.0.0.0"
   push "route 192.168.1.0 255.255.255.0"
   ```

3. 如果你不想要 VPN DNS，可选删除 DNS 推送指令：

   ```
   #push "dhcp-option DNS 1.1.1.1"
   ```

4. 对于 IPv6，删除或注释掉：

   ```
   #push "route-ipv6 2000::/3"
   #push "redirect-gateway ipv6"
   ```

   或添加特定的 IPv6 路由：

   ```
   push "route-ipv6 2001:db8::/32"
   ```

5. 重启 OpenVPN：`systemctl restart openvpn-server@server`

---

**问:** 我已经启用了 IPv6，我的 VPN 客户端获得了 IPv6 地址。为什么我只能通过 IPv4 访问网站或其他双栈目的地？

**答:** 这是因为在隧道内你没有获得可公开路由的 IPv6 地址，而是获得了一个 ULA（唯一本地地址）地址。操作系统并不总是优先使用它。你可以在操作系统策略中修复此问题，因为这与 VPN 本身无关：

Windows（命令需要以管理员身份运行 cmd.exe）：

```
netsh interface ipv6 add prefixpolicy fd00::/8 3 1
```

Linux：

编辑 `/etc/gai.conf` 并取消注释以下行，并将其值更改为 `1`：

```
label fc00::/7      1
```

除非你在 VPN 服务器 `server.conf` 中添加一或两行来推送至少 1 个 IPv6 DNS 服务器，否则这将无法正常工作。大多数提供商也有 IPv6 服务器，添加两行 `push "dhcp-option DNS <IPv6>"`

---

**问:** 我如何在端口 443 上与 Web 服务器一起运行 OpenVPN？

**答:** 使用 OpenVPN 的 `port-share` 功能在同一端口上复用两个服务。当 OpenVPN 收到非 VPN 流量时，它会将其转发到你的 Web 服务器。

1. 安装过程中，选择 **TCP** 和端口 **443**
2. 配置你的 Web 服务器监听不同的端口（例如 8443）
3. 添加到 `/etc/openvpn/server/server.conf`：

   ```
   port-share 127.0.0.1 8443
   ```

4. 重启 OpenVPN：`systemctl restart openvpn-server@server`

这在你的网络只允许端口 443 上的出站连接时很有用。请注意，由于队头阻塞，TCP 对于 VPN 流量的性能比 UDP 差，因此仅在必要时使用。
