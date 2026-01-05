# CCNA-commands
https://visualsubnetcalc.com/
https://www.exampointers.com/ipv4/
Part 1
2. 基础设备设置 (Basic Setup)
设置设备名称和登录横幅。

! 进入全局配置模式
Router# configure terminal

! 设置主机名 (例如将 Router 改名为 R1)
Router(config)# hostname R1

! 设置每日消息 (Banner Message of the Day)
! 消息内容必须包含在两个相同的符号之间 (这里使用的是 #)
R1(config)# banner motd #Access Denied! Authorized Personnel Only#
3. 端口与远程登录密码 (Line Passwords)
保护物理控制台接口 (Console) 和虚拟远程接口 (VTY)。

! --- 配置 Console 接口 (物理线缆连接) ---
R1(config)# line console 0               ! 进入控制台接口配置
R1(config-line)# password cisco          ! 设置密码为 "cisco"
R1(config-line)# login                   ! 启用登录检查 (必须输入，否则密码不生效)
R1(config-line)# exit                    ! 退出该接口

! --- 配置 VTY 接口 (Telnet/SSH 远程连接) ---
! 路由器通常有 5 个端口 (0-4)，交换机通常有 16 个端口 (0-15)
R1(config)# line vty 0 4                 ! 进入 VTY 0 到 4 线路
R1(config-line)# password cisco          ! 设置远程登录密码
R1(config-line)# login                   ! 启用登录检查
R1(config-line)# exec-timeout 10 0       ! 设置空闲超时: 10分钟 0秒无操作自动登出
R1(config-line)# exit

! --- 密码加密 ---
R1(config)# service password-encryption  ! 将配置文件中所有的明文密码加密显示
4. 管理员权限密码 (Enable Password)
保护从用户模式 (>) 进入特权模式 (#) 的权限。

! 选项 A: Enable Secret (推荐)
! 密码使用 MD5 哈希加密存储，非常安全
R1(config)# enable secret mysecurepass

! 选项 B: Enable Password (不推荐)
! 密码以明文存储，极易被破解
! R1(config)# enable password myweakpass
5. IP 地址与网关配置 (IP & Gateway)
通常用于交换机管理接口 (SVI - Switch Virtual Interface)。

! 进入 VLAN 1 接口 (默认管理接口)
S1(config)# interface vlan 1

! 配置 IP 地址和子网掩码 (格式: IP Subnet)
S1(config-if)# ip address 192.168.1.10 255.255.255.0

! 激活接口 (非常重要：默认状态是关闭的/Shutdown)
S1(config-if)# no shutdown
S1(config-if)# exit

! --- 配置默认网关 ---
! 允许交换机与不同网段的设备通信
S1(config)# ip default-gateway 192.168.1.1
6. SSH 安全登录配置 (SSH Configuration)
使用加密的 SSH 替代明文的 Telnet，这是网络管理的最佳实践。

前置条件： 必须先配置好 hostname 和 ip domain-name。

! 1. 设置域名 (生成密钥必须)
R1(config)# ip domain-name example.com

! 2. 创建本地管理员用户
! 使用 secret 关键字确保密码在配置中加密
R1(config)# username admin secret strongpassword123

! 3. 生成 RSA 加密密钥
! 建议密钥长度至少为 1024 或 2048 位
R1(config)# crypto key generate rsa general-keys modulus 1024

! 4. SSH 参数优化
R1(config)# ip ssh version 2                 ! 强制使用 SSH 版本 2 (更安全)
R1(config)# ip ssh authentication-retries 2  ! 限制密码重试次数 (防暴力破解)
R1(config)# ip ssh time-out 60               ! 设置连接建立超时时间 (秒)

! 5. 应用设置到 VTY 线路
R1(config)# line vty 0 4
R1(config-line)# transport input ssh         ! 仅允许 SSH 协议 (禁用 Telnet)
R1(config-line)# login local                 ! 强制使用步骤2中创建的本地账号认证
R1(config-line)# exit
7. 常用杂项命令 (Misc)
防止错误和提高安全性的实用命令。
! 禁用 DNS 域名解析
! 防止输入错误命令时，设备尝试将其解析为域名而卡顿
R1(config)# no ip domain-lookup

! 设置最小密码长度策略
! 强制要求所有新设置的密码至少为 10 位
R1(config)# security passwords min-length 10

! 快捷键说明:
! Ctrl + Shift + 6  -> 强制中断当前操作 (如 Ping 或 DNS 查询卡住时)
! Ctrl + Z          -> 快速回到特权模式 (#)
___________________________________________________________________________________________________________
Part 2
1. VLAN 与 Trunk 配置 (VLANs & Trunking)
创建虚拟局域网并配置端口连接模式。
! --- 创建 VLAN ---
S1(config)# vlan 10                        ! 创建 VLAN ID 10
S1(config-vlan)# name Sales                ! 给 VLAN 命名

! --- 配置 Access 端口 (连接终端设备) ---
S1(config)# interface range f0/1-10        ! 批量选择接口
S1(config-if-range)# switchport mode access! 设置为接入模式
S1(config-if-range)# switchport access vlan 10 ! 将端口划分到 VLAN 10

! --- 配置 Voice VLAN (连接 IP 电话) ---
S1(config-if)# mls qos trust cos           ! 信任数据帧的 CoS 优先级标记
S1(config-if)# switchport voice vlan 20    ! 设定语音 VLAN 为 20

! --- 配置 Trunk 端口 (连接交换机/路由器) ---
S1(config)# interface g0/1
S1(config-if)# switchport mode trunk       ! 强制设置为 Trunk 模式
S1(config-if)# switchport trunk native vlan 99 ! 修改 Native VLAN (默认为1，两端必须一致)
S1(config-if)# switchport trunk allowed vlan 10,20,99 ! 仅允许特定 VLAN 通过
S1(config-if)# switchport nonegotiate      ! 关闭 DTP 协商 (防止自动协商)
2. 生成树协议 (Spanning Tree Protocol)
防止二层环路并优化网络路径。

! --- 全局 STP 设置 ---
S1(config)# spanning-tree mode pvst        ! 使用 PVST+ 模式 (Cisco 默认)

! --- 根桥选举 (Root Bridge) ---
! 方法 A: 直接指定优先级 (必须是 4096 的倍数)
S1(config)# spanning-tree vlan 1 priority 24576
! 方法 B: 让系统自动计算 (Primary 减去 8192, Secondary 减去 4096)
S1(config)# spanning-tree vlan 10 root primary   ! 设为主根桥
S1(config)# spanning-tree vlan 10 root secondary ! 设为备份根桥

! --- PortFast & BPDUGuard (用于边缘端口) ---
! PortFast: 让连接终端的端口跳过侦听/学习状态，立即转发
! BPDUGuard: 如果 PortFast 端口收到 BPDU (交换机报文)，自动关闭端口
S1(config-if)# spanning-tree portfast      ! 接口级开启 PortFast
S1(config-if)# spanning-tree bpduguard enable ! 接口级开启 BPDU 防护
3. EtherChannel (链路聚合)
将多个物理接口捆绑为一个逻辑接口，增加带宽和冗余。


! --- LACP 配置 (通用标准, 推荐) ---
S1(config)# interface range f0/21-22
S1(config-if-range)# shutdown              ! 配置前建议先关闭接口
S1(config-if-range)# channel-group 1 mode active ! Active: 主动发送协商 / Passive: 被动等待
S1(config-if-range)# no shutdown

! --- PAgP 配置 (Cisco 私有) ---
S1(config-if-range)# channel-group 2 mode desirable ! Desirable: 主动 / Auto: 被动

! --- 配置逻辑接口 (Port-Channel) ---
S1(config)# interface port-channel 1       ! 进入聚合口
S1(config-if)# switchport mode trunk       ! 将聚合口设为 Trunk
S1(config-if)# switchport trunk native vlan 99
4. VLAN 间路由 (Inter-VLAN Routing)
让不同 VLAN 之间可以通信。

方式 A: 单臂路由 (Router-on-a-Stick) - 只有路由器

! 物理接口必须开启，但不配置 IP
R1(config)# interface g0/0
R1(config-if)# no shutdown

! 配置子接口
R1(config)# interface g0/0.10              ! 创建对应 VLAN 10 的子接口
R1(config-subif)# encapsulation dot1q 10   ! 封装 802.1Q 标签，对应 VLAN 10
R1(config-subif)# ip address 192.168.10.1 255.255.255.0
方式 B: 三层交换机 (SVI) - 推荐

! 必须先在交换机上开启路由功能
S1(config)# ip routing

! 配置 SVI 接口
S1(config)# interface vlan 10
S1(config-if)# ip address 192.168.10.1 255.255.255.0
S1(config-if)# no shutdown
5. 网关冗余协议 (HSRP)
Hot Standby Router Protocol - 提供网关热备。

! --- R1 (主路由器) ---
R1(config)# interface g0/1
R1(config-if)# standby version 2           ! 使用 HSRP 版本 2
R1(config-if)# standby 1 ip 192.168.1.254  ! 设置虚拟网关 IP (Virtual IP)
R1(config-if)# standby 1 priority 150      ! 设置优先级 (默认100，越高越优先)
R1(config-if)# standby 1 preempt           ! 开启抢占 (故障恢复后重新夺回主权)

! --- R2 (备路由器) ---
R2(config)# interface g0/1
R2(config-if)# standby version 2
R2(config-if)# standby 1 ip 192.168.1.254  ! 虚拟 IP 必须与 R1 一致
! R2 优先级保持默认 100，作为备份
6. DHCPv4 配置与中继

! --- 配置 DHCP 服务器 ---
R1(config)# ip dhcp excluded-address 192.168.1.1 192.168.1.10 ! 排除不分配的 IP 范围
R1(config)# ip dhcp pool LAN-POOL          ! 创建地址池
R1(dhcp-config)# network 192.168.1.0 255.255.255.0 ! 定义网段
R1(dhcp-config)# default-router 192.168.1.1! 设置默认网关
R1(dhcp-config)# dns-server 8.8.8.8        ! 设置 DNS
R1(dhcp-config)# domain-name example.com   ! 设置域名

! --- 配置 DHCP 中继 (Relay Agent) ---
! 如果 DHCP 服务器在不同网段，需在网关接口配置
R2(config)# interface g0/1
R2(config-if)# ip helper-address 10.1.1.2  ! 指向 DHCP 服务器的真实 IP
7. IPv6 地址分配 (SLAAC & DHCPv6)
IPv6 的地址分配方式较为灵活，主要依靠 RA (Router Advertisement) 消息。

! 全局开启 IPv6 路由 (必须开启，否则无法发送 RA 消息)
R1(config)# ipv6 unicast-routing

! --- 方式 1: SLAAC (无状态自动配置) ---
! 客户端根据 RA 消息自动生成 IP，无需 DHCP 服务器
R1(config-if)# ipv6 address 2001:db8:acad:1::1/64
R1(config-if)# no ipv6 nd managed-config-flag ! 确保 M 位关闭
R1(config-if)# no ipv6 nd other-config-flag   ! 确保 O 位关闭

! --- 方式 2: Stateless DHCPv6 (SLAAC + DNS) ---
! IP 由 SLAAC 生成，DNS 等信息由 DHCPv6 提供
R1(config-if)# ipv6 nd other-config-flag      ! 开启 O 位 (Tell client: ask DHCP for other info)
R1(config)# ipv6 dhcp pool DNS-ONLY
R1(config-dhcp)# dns-server 2001:4860:4860::8888
R1(config-if)# ipv6 dhcp server DNS-ONLY      ! 绑定到接口

! --- 方式 3: Stateful DHCPv6 (完全类似 DHCPv4) ---
! IP 和 DNS 都由 DHCPv6 服务器分配
R1(config-if)# ipv6 nd managed-config-flag    ! 开启 M 位 (Tell client: ask DHCP for IP)
R1(config-if)# ipv6 nd prefix default no-autoconfig ! 禁止客户端使用 SLAAC 生成地址
8. 交换机安全 (Switch Security)
端口安全 (Port Security)
限制端口连接的 MAC 地址数量，防止非法接入。

S1(config-if)# switchport port-security                  ! 开启端口安全
S1(config-if)# switchport port-security maximum 2        ! 最多允许 2 个 MAC 地址
S1(config-if)# switchport port-security mac-address sticky ! 自动学习并记住当前 MAC (粘性)
S1(config-if)# switchport port-security violation restrict ! 违规策略: 丢包并记录日志 (protect/restrict/shutdown)
DHCP Snooping (防流氓 DHCP)
防止非法的 DHCP 服务器接入网络。

S1(config)# ip dhcp snooping                       ! 全局开启
S1(config)# ip dhcp snooping vlan 10               ! 在特定 VLAN 开启
S1(config)# interface g0/1                         ! 连接合法 DHCP 服务器的上行接口
S1(config-if)# ip dhcp snooping trust              ! 设置为"信任"接口 (允许发送 DHCP Offer)
! 其他连接用户的接口默认为"非信任"，会拦截 DHCP Offer
DAI (动态 ARP 检测)
防止 ARP 欺骗 (中间人攻击)，依赖于 DHCP Snooping 数据库。

S1(config)# ip arp inspection vlan 10              ! 在 VLAN 10 开启 ARP 检查
S1(config)# interface g0/1                         ! 上行接口
S1(config-if)# ip arp inspection trust             ! 设置为信任接口
S1(config)# ip arp inspection validate src-mac ip  ! 额外验证源 MAC 和 IP 的一致性
___________________________________________________________________________________________________________
Part 3
1. OSPF 动态路由配置 (OSPF Routing)
配置开放式最短路径优先协议 (OSPFv2)。
基础 OSPF 启用

! --- 方法 A: 使用 Network 命令宣告 (传统方式) ---
R1(config)# router ospf 10                 ! 启用 OSPF 进程 10 (本地有效)
R1(config-router)# network 10.0.0.0 0.0.0.3 area 0  ! 精确宣告网段 (使用反掩码)
R1(config-router)# network 10.1.0.0 0.0.0.255 area 0

! --- 方法 B: 直接在接口下启用 (新方式) ---
R1(config)# interface g0/0
R1(config-if)# ip ospf 10 area 0           ! 将此接口加入 OSPF 进程 10 区域 0
OSPF 优化与调整
Cisco CLI

! --- 被动接口 (Passive Interface) ---
! 禁止向 LAN 侧发送 OSPF Hello 包，提高安全性并减少广播
R1(config-router)# passive-interface g0/1  
R1(config-router)# passive-interface default ! (可选) 默认全部被动，需手动 no passive 开启特定接口

! --- 调整 DR/BDR 选举 ---
! 优先级越高越容易成为 DR (Designated Router)
R1(config)# interface g0/0
R1(config-if)# ip ospf priority 255        ! 设置为最高优先级 (确保成为 DR)
R3(config-if)# ip ospf priority 0          ! 设置为 0 表示永远不参与选举 (DROTHER)

! --- 修改网络类型 ---
! 在点对点链路 (如串口) 上消除 DR/BDR 选举过程，加快收敛
R1(config-if)# ip ospf network point-to-point

! --- 下发默认路由 ---
! 将 R2 上的默认路由广播给 OSPF 网络中的其他路由器
R2(config)# ip route 0.0.0.0 0.0.0.0 203.0.113.1  ! 必须先有一条静态默认路由
R2(config)# router ospf 10
R2(config-router)# default-information originate
2. 访问控制列表 (ACLs)
用于过滤流量。注意： ACL 默认最后都有一条隐含的 "Deny All" (拒绝所有)。

标准 ACL (Standard ACL)
仅基于源 IP 地址进行过滤 (编号 1-99)。推荐应用在离目标最近的地方。

! --- 编号式标准 ACL ---
R1(config)# access-list 1 deny 192.168.11.0 0.0.0.255  ! 拒绝源网段 11.0
R1(config)# access-list 1 permit any                   ! 允许其他所有流量
! 应用到接口
R1(config)# interface g0/0
R1(config-if)# ip access-group 1 out                   ! 出站方向应用

! --- 命名式标准 ACL ---
R1(config)# ip access-list standard BLOCK_HOST
R1(config-std-nacl)# deny host 192.168.20.4            ! 拒绝特定主机
R1(config-std-nacl)# permit any
扩展 ACL (Extended ACL)
基于源 IP、目标 IP、协议 (TCP/UDP/ICMP) 和端口号过滤 (编号 100-199)。推荐应用在离源最近的地方。

! --- 编号式扩展 ACL ---
! 允许特定主机访问 FTP (端口 21)
R1(config)# access-list 100 permit tcp host 172.22.1.1 host 172.22.34.62 eq ftp
! 允许 Ping (ICMP)
R1(config)# access-list 100 permit icmp 172.22.1.0 0.0.0.255 host 172.22.34.62
! (隐式拒绝其他所有)

! --- 命名式扩展 ACL ---
R1(config)# ip access-list extended HTTP_ONLY
R1(config-ext-nacl)# permit tcp 172.22.34.0 0.0.0.255 host 172.22.34.62 eq www
3. 网络地址转换 (NAT & PAT)
将私有 IP 转换为公网 IP 以便上网。

静态 NAT (Static NAT)
一对一映射，通常用于让外网访问内网服务器。

R2(config)# ip nat inside source static 172.16.16.1 64.100.50.1
端口复用 PAT (NAT Overload)
多对一映射，家庭和企业最常用。允许多个内网设备共用一个公网 IP。

! 1. 定义允许转换的内网地址范围 (使用 ACL)
R2(config)# access-list 1 permit 192.168.0.0 0.0.0.255

! 2. 配置 NAT Overload (绑定到外网接口)
R2(config)# ip nat inside source list 1 interface serial0/1/1 overload

! 3. 定义接口方向 (关键步骤!)
R2(config)# interface g0/0
R2(config-if)# ip nat inside       ! 内网接口
R2(config)# interface serial0/1/1
R2(config-if)# ip nat outside      ! 外网接口
4. WAN 协议与隧道 (PPP & GRE)
PPP 封装与 CHAP 认证
用于串行链路的安全连接。

! R1 配置 (验证 R2)
R1(config)# username R2 password MySecretPassword  ! 创建对端用户的数据库
R1(config)# interface s0/1/0
R1(config-if)# encapsulation ppp                   ! 封装改为 PPP
R1(config-if)# ppp authentication chap             ! 开启 CHAP 认证
GRE 隧道 (GRE Tunnel)
在互联网上建立未加密的虚拟点对点连接。

! --- R1 配置 ---
R1(config)# interface tunnel 0
R1(config-if)# ip address 10.0.0.1 255.255.255.0   ! 隧道内部的私有 IP
R1(config-if)# tunnel source 1.2.3.4               ! 本地公网 IP (或接口名)
R1(config-if)# tunnel destination 6.7.8.9          ! 对端公网 IP

! --- 配置路由 ---
! 让去往 R2 内网的流量走隧道
R1(config)# ip route 192.168.100.0 255.255.255.0 10.0.0.2
5. IPsec VPN 安全配置 (IPsec over GRE)
GRE 本身不加密，通常结合 IPsec 使用。以下是配置 IPsec 保护 GRE 隧道的步骤：

第一阶段: ISAKMP 策略 (管理连接)
R1(config)# crypto isakmp policy 1
R1(config-isakmp)# hash sha                ! 哈希算法
R1(config-isakmp)# authentication pre-share! 认证方式: 预共享密钥
R1(config-isakmp)# group 5                 ! Diffie-Hellman 组
R1(config-isakmp)# encryption aes          ! 加密算法
R1(config-isakmp)# exit

! 配置预共享密钥 (对端 IP 和密钥必须匹配)
R1(config)# crypto isakmp key CISCO123 address 6.7.8.9
第二阶段: IPsec 变换集 (数据加密)

! 定义如何加密实际数据流量
R1(config)# crypto ipsec transform-set MY_SET esp-aes esp-sha-hmac
第三阶段: Crypto Map 与 ACL

! 1. 定义要加密的流量 (这里指 GRE 流量)
R1(config)# ip access-list extended VPN_ACL
R1(config-ext-nacl)# permit gre host 1.2.3.4 host 6.7.8.9

! 2. 创建加密映射图 (Map)
R1(config)# crypto map MY_MAP 1 ipsec-isakmp
R1(config-crypto-map)# set peer 6.7.8.9            ! 对端公网 IP
R1(config-crypto-map)# set transform-set MY_SET    ! 关联变换集
R1(config-crypto-map)# match address VPN_ACL       ! 关联 ACL
第四阶段: 应用到物理接口

! 注意：是应用在物理外网接口，而不是 Tunnel 接口
R1(config)# interface s0/1/0
R1(config-if)# crypto map MY_MAP
