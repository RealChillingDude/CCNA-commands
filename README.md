# CCNA-commands
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
