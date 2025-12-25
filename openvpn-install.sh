#!/bin/bash
# shellcheck disable=SC1091,SC2034
# SC1091: 不遵循 /etc/os-release（动态来源）
# SC2034: 变量间接使用或导出给子进程

# 适用于 Debian, Ubuntu, CentOS, Amazon Linux 2023, Fedora, Oracle Linux, Arch Linux, Rocky Linux 和 AlmaLinux 的安全 OpenVPN 服务器安装脚本。
# https://github.com/plutobe/openvpn-install-zh

# 配置常量
readonly DEFAULT_CERT_VALIDITY_DURATION_DAYS=3650 # 10 年
readonly DEFAULT_CRL_VALIDITY_DURATION_DAYS=5475  # 15 年
readonly EASYRSA_VERSION="3.2.5"
readonly EASYRSA_SHA256="662ee3b453155aeb1dff7096ec052cd83176c460cfa82ac130ef8568ec4df490"

# =============================================================================
# 日志配置
# =============================================================================
# 设置 VERBOSE=1 查看命令输出，VERBOSE=0（默认）为静默模式
# 设置 LOG_FILE 自定义日志位置（默认：当前目录下的 openvpn-install.log）
# 设置 LOG_FILE="" 禁用文件日志
VERBOSE=${VERBOSE:-0}
LOG_FILE=${LOG_FILE:-openvpn-install.log}
OUTPUT_FORMAT=${OUTPUT_FORMAT:-table} # table 或 json - json 会抑制日志输出

# 颜色定义（如果不是终端则禁用，除非 FORCE_COLOR=1）
if [[ -t 1 ]] || [[ $FORCE_COLOR == "1" ]]; then
	readonly COLOR_RESET='\033[0m'
	readonly COLOR_RED='\033[0;31m'
	readonly COLOR_GREEN='\033[0;32m'
	readonly COLOR_YELLOW='\033[0;33m'
	readonly COLOR_BLUE='\033[0;34m'
	readonly COLOR_CYAN='\033[0;36m'
	readonly COLOR_DIM='\033[0;90m'
	readonly COLOR_BOLD='\033[1m'
else
	readonly COLOR_RESET=''
	readonly COLOR_RED=''
	readonly COLOR_GREEN=''
	readonly COLOR_YELLOW=''
	readonly COLOR_BLUE=''
	readonly COLOR_CYAN=''
	readonly COLOR_DIM=''
	readonly COLOR_BOLD=''
fi

# 写入日志文件（无颜色，带时间戳）
_log_to_file() {
	if [[ -n "$LOG_FILE" ]]; then
		echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >>"$LOG_FILE"
	fi
}

# 日志函数
log_info() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_BLUE}[INFO]${COLOR_RESET} $*"
	_log_to_file "[INFO] $*"
}

log_warn() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_YELLOW}[WARN]${COLOR_RESET} $*"
	_log_to_file "[WARN] $*"
}

log_error() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[ERROR] $*"
	if [[ -n "$LOG_FILE" ]]; then
		echo -e "${COLOR_YELLOW}        请查看日志文件获取详细信息：${LOG_FILE}${COLOR_RESET}" >&2
	fi
}

log_fatal() {
	echo -e "${COLOR_RED}[ERROR]${COLOR_RESET} $*" >&2
	_log_to_file "[FATAL] $*"
	if [[ -n "$LOG_FILE" ]]; then
		echo -e "${COLOR_YELLOW}        请查看日志文件获取详细信息：${LOG_FILE}${COLOR_RESET}" >&2
		_log_to_file "脚本错误退出"
	fi
	exit 1
}

log_success() {
	[[ $OUTPUT_FORMAT == "json" ]] && return
	echo -e "${COLOR_GREEN}[OK]${COLOR_RESET} $*"
	_log_to_file "[OK] $*"
}

log_debug() {
	if [[ $VERBOSE -eq 1 && $OUTPUT_FORMAT != "json" ]]; then
		echo -e "${COLOR_DIM}[DEBUG]${COLOR_RESET} $*"
	fi
	_log_to_file "[DEBUG] $*"
}

log_prompt() {
	# 用于面向用户的提示/问题（无前缀，仅青色）
	# 在非交互模式下跳过显示
	if [[ $NON_INTERACTIVE_INSTALL != "y" ]]; then
		echo -e "${COLOR_CYAN}$*${COLOR_RESET}"
	fi
	_log_to_file "[PROMPT] $*"
}

log_header() {
	# 用于章节标题
	# 在非交互模式下跳过显示
	if [[ $NON_INTERACTIVE_INSTALL != "y" ]]; then
		echo ""
		echo -e "${COLOR_BOLD}${COLOR_BLUE}=== $* ===${COLOR_RESET}"
		echo ""
	fi
	_log_to_file "=== $* ==="
}

log_menu() {
	# 用于菜单选项 - 仅在交互模式下显示
	if [[ $NON_INTERACTIVE_INSTALL != "y" ]]; then
		echo "$@"
	fi
}

# 运行命令，可选抑制输出
# 用法：run_cmd "描述" 命令 [参数...]
run_cmd() {
	local desc="$1"
	shift
	# 显示正在运行的命令
	echo -e "${COLOR_DIM}> $*${COLOR_RESET}"
	_log_to_file "[CMD] $*"
	if [[ $VERBOSE -eq 1 ]]; then
		if [[ -n "$LOG_FILE" ]]; then
			"$@" 2>&1 | tee -a "$LOG_FILE"
		else
			"$@"
		fi
	else
		if [[ -n "$LOG_FILE" ]]; then
			"$@" >>"$LOG_FILE" 2>&1
		else
			"$@" >/dev/null 2>&1
		fi
	fi
	local ret=$?
	if [[ $ret -eq 0 ]]; then
		log_debug "$desc 执行成功"
	else
		log_error "$desc 执行失败，退出码 $ret"
	fi
	return $ret
}

# 运行必须成功的命令，失败则退出
# 用法：run_cmd_fatal "描述" 命令 [参数...]
run_cmd_fatal() {
	local desc="$1"
	shift
	if ! run_cmd "$desc" "$@"; then
		log_fatal "$desc 执行失败"
	fi
}

# =============================================================================
# CLI 配置
# =============================================================================
readonly SCRIPT_NAME="openvpn-install"

# =============================================================================
# 帮助文本函数
# =============================================================================
show_help() {
	cat <<-EOF
		OpenVPN 安装器和管理器

		用法：$SCRIPT_NAME <命令> [选项]

		命令：
			install       安装并配置 OpenVPN 服务器
			uninstall     移除 OpenVPN 服务器
			client        管理客户端证书
			server        服务器管理
			interactive   启动交互式菜单

		全局选项：
			--verbose     显示详细输出
			--log <路径>  日志文件路径（默认：openvpn-install.log）
			--no-log      禁用文件日志记录
			--no-color    禁用彩色输出
			-h, --help    显示帮助

		运行 '$SCRIPT_NAME <命令> --help' 获取命令特定的帮助。
	EOF
}

show_install_help() {
	cat <<-EOF
		安装并配置 OpenVPN 服务器

		用法：$SCRIPT_NAME install [选项]

		选项：
			-i, --interactive     运行交互式安装向导

		网络选项：
			--endpoint <host>     客户端的公共 IP 或主机名（自动检测）
			--endpoint-type <4|6> 端点 IP 版本：4 或 6（默认：4）
			--ip <addr>           服务器监听 IP（自动检测）
			--client-ipv4         为 VPN 客户端启用 IPv4（默认：启用）
			--no-client-ipv4      为 VPN 客户端禁用 IPv4
			--client-ipv6         为 VPN 客户端启用 IPv6
			--no-client-ipv6      为 VPN 客户端禁用 IPv6（默认）
			--subnet-ipv4 <x.x.x.0>  IPv4 VPN 子网（默认：10.8.0.0）
			--subnet-ipv6 <prefix>   IPv6 VPN 子网（默认：fd42:42:42:42::）
			--port <num>          OpenVPN 端口（默认：1194）
			--port-random         使用随机端口（49152-65535）
			--protocol <proto>    协议：udp 或 tcp（默认：udp）
			--mtu <size>          隧道 MTU（默认：1500）

		DNS 选项：
			--dns <provider>      DNS 提供商（默认：cloudflare）
				提供商：system, unbound, cloudflare, quad9, quad9-uncensored,
				fdn, dnswatch, opendns, google, yandex, adguard, nextdns, custom
			--dns-primary <ip>    自定义主要 DNS（需要 --dns custom）
			--dns-secondary <ip>  自定义次要 DNS（可选）

		安全选项：
			--cipher <cipher>     数据通道密码（默认：AES-128-GCM）
				密码：AES-128-GCM, AES-192-GCM, AES-256-GCM, AES-128-CBC,
				AES-192-CBC, AES-256-CBC, CHACHA20-POLY1305
			--cert-type <type>    证书类型：ecdsa 或 rsa（默认：ecdsa）
			--cert-curve <curve>  ECDSA 曲线（默认：prime256v1）
				曲线：prime256v1, secp384r1, secp521r1
			--rsa-bits <size>     RSA 密钥大小：2048, 3072, 4096（默认：2048）
			--cc-cipher <cipher>  控制通道密码（自动选择）
			--tls-version-min <ver>  最小 TLS 版本：1.2 或 1.3（默认：1.2）
			--tls-ciphersuites <list>  TLS 1.3 密码套件，以冒号分隔
			--tls-groups <list>   密钥交换组，以冒号分隔
				（默认：X25519:prime256v1:secp384r1:secp521r1）
			--hmac <alg>          HMAC 算法：SHA256, SHA384, SHA512（默认：SHA256）
			--tls-sig <mode>      TLS 模式：crypt-v2, crypt, auth（默认：crypt-v2）
			--auth-mode <mode>    认证模式：pki, fingerprint（默认：pki）
				fingerprint 需要 OpenVPN 2.6+
			--server-cert-days <n>  服务器证书有效期（天）（默认：3650）

		其他选项：
			--multi-client        允许在多个设备上使用相同证书

		初始客户端选项：
			--client <name>       初始客户端名称（默认：client）
			--client-password [p] 密码保护客户端（如果未提供值则提示）
			--client-cert-days <n>  客户端证书有效期（天）（默认：3650）
			--no-client           跳过初始客户端创建

		示例：
			$SCRIPT_NAME install
			$SCRIPT_NAME install --port 443 --protocol tcp
			$SCRIPT_NAME install --dns quad9 --cipher AES-256-GCM
			$SCRIPT_NAME install -i
	EOF
}

show_uninstall_help() {
	cat <<-EOF
		移除 OpenVPN 服务器

		用法：$SCRIPT_NAME uninstall [选项]

		选项：
			-f, --force   跳过确认提示

		示例：
			$SCRIPT_NAME uninstall
			$SCRIPT_NAME uninstall --force
	EOF
}

show_client_help() {
	cat <<-EOF
		管理客户端证书

		用法：$SCRIPT_NAME client <子命令> [选项]

		子命令：
			add <名称>     添加新客户端
			list           列出所有客户端
			revoke <名称>  吊销客户端证书
			renew <名称>   续订客户端证书

		运行 '$SCRIPT_NAME client <子命令> --help' 获取更多信息。
	EOF
}

show_client_add_help() {
	cat <<-EOF
		添加新的 VPN 客户端

		用法：$SCRIPT_NAME client add <名称> [选项]

		选项：
			--password [pass]   密码保护客户端（如果未提供值则提示）
			--cert-days <n>     证书有效期（天）（默认：3650）
			--output <路径>     .ovpn 文件的输出路径（默认：~/<名称>.ovpn）

		示例：
			$SCRIPT_NAME client add alice
			$SCRIPT_NAME client add bob --password
			$SCRIPT_NAME client add charlie --cert-days 365 --output /tmp/charlie.ovpn
	EOF
}

show_client_list_help() {
	cat <<-EOF
		列出所有客户端证书

		用法：$SCRIPT_NAME client list [选项]

		选项：
			--format <格式>  输出格式：table 或 json（默认：table）

		示例：
			$SCRIPT_NAME client list
			$SCRIPT_NAME client list --format json
	EOF
}

show_client_revoke_help() {
	cat <<-EOF
		吊销客户端证书

		用法：$SCRIPT_NAME client revoke <名称> [选项]

		选项：
			-f, --force   跳过确认提示

		示例：
			$SCRIPT_NAME client revoke alice
			$SCRIPT_NAME client revoke bob --force
	EOF
}

show_client_renew_help() {
	cat <<-EOF
		续订客户端证书

		用法：$SCRIPT_NAME client renew <名称> [选项]

		选项：
			--cert-days <n>   新证书有效期（天）（默认：3650）

		示例：
			$SCRIPT_NAME client renew alice
			$SCRIPT_NAME client renew bob --cert-days 365
	EOF
}

show_server_help() {
	cat <<-EOF
		服务器管理

		用法：$SCRIPT_NAME server <子命令> [选项]

		子命令：
			status   列出当前连接的客户端
			renew    续订服务器证书

		运行 '$SCRIPT_NAME server <子命令> --help' 获取更多信息。
	EOF
}

show_server_status_help() {
	cat <<-EOF
		列出当前连接的客户端

		注意：OpenVPN 每 60 秒更新一次客户端数据。

		用法：$SCRIPT_NAME server status [选项]

		选项：
			--format <格式>  输出格式：table 或 json（默认：table）

		示例：
			$SCRIPT_NAME server status
			$SCRIPT_NAME server status --format json
	EOF
}

show_server_renew_help() {
	cat <<-EOF
		续订服务器证书

		用法：$SCRIPT_NAME server renew [选项]

		选项：
			--cert-days <n>   新证书有效期（天）（默认：3650）
			-f, --force       跳过确认/警告

		示例：
			$SCRIPT_NAME server renew
			$SCRIPT_NAME server renew --cert-days 1825
	EOF
}

# =============================================================================
# CLI 命令处理程序
# =============================================================================

# 检查 OpenVPN 是否已安装
isOpenVPNInstalled() {
	[[ -e /etc/openvpn/server/server.conf ]]
}

# 要求 OpenVPN 已安装
requireOpenVPN() {
	if ! isOpenVPNInstalled; then
		log_fatal "OpenVPN 未安装。请先运行 '$SCRIPT_NAME install'。"
	fi
}

# 要求 OpenVPN 未安装
requireNoOpenVPN() {
	if isOpenVPNInstalled; then
		log_fatal "OpenVPN 已安装。使用 '$SCRIPT_NAME client' 管理客户端或 '$SCRIPT_NAME uninstall' 移除。"
	fi
}

# 解析 DNS 提供商字符串
parse_dns_provider() {
	case "$1" in
	system | unbound | cloudflare | quad9 | quad9-uncensored | fdn | dnswatch | opendns | google | yandex | adguard | nextdns | custom)
		DNS="$1"
		;;
	*) log_fatal "无效的 DNS 提供商: $1。请查看 '$SCRIPT_NAME install --help' 获取有效提供商。" ;;
	esac
}

# 解析密码字符串
parse_cipher() {
	case "$1" in
	AES-128-GCM | AES-192-GCM | AES-256-GCM | AES-128-CBC | AES-192-CBC | AES-256-CBC | CHACHA20-POLY1305)
		CIPHER="$1"
		;;
	*) log_fatal "无效的密码: $1。请查看 '$SCRIPT_NAME install --help' 获取有效密码。" ;;
	esac
}

# 解析曲线字符串
parse_curve() {
	case "$1" in
	prime256v1 | secp384r1 | secp521r1) echo "$1" ;;
	*)
		log_fatal "无效的曲线: $1。有效曲线: prime256v1, secp384r1, secp521r1" ;;
	esac
}

# =============================================================================
# 配置常量
# =============================================================================
# 协议选项
readonly PROTOCOLS=("udp" "tcp")

# DNS 提供商（使用字符串名称）
readonly DNS_PROVIDERS=("system" "unbound" "aliyun" "cloudflare" "quad9" "quad9-uncensored" "fdn" "dnswatch" "opendns" "google" "yandex" "adguard" "nextdns" "custom")

# 密码选项
readonly CIPHERS=("AES-128-GCM" "AES-192-GCM" "AES-256-GCM" "AES-128-CBC" "AES-192-CBC" "AES-256-CBC" "CHACHA20-POLY1305")

# 证书类型（使用字符串）
readonly CERT_TYPES=("ecdsa" "rsa")

# ECDSA 曲线
readonly CERT_CURVES=("prime256v1" "secp384r1" "secp521r1")

# RSA 密钥大小
readonly RSA_KEY_SIZES=("2048" "3072" "4096")

# TLS 版本
readonly TLS_VERSIONS=("1.2" "1.3")

# TLS 签名模式（使用字符串）
readonly TLS_SIG_MODES=("crypt-v2" "crypt" "auth")

# 认证模式：pki（基于 CA）或 fingerprint（对等指纹，OpenVPN 2.6+）
readonly AUTH_MODES=("pki" "fingerprint")

# HMAC 算法
readonly HMAC_ALGS=("SHA256" "SHA384" "SHA512")

# TLS 1.3 密码套件选项
readonly TLS13_OPTIONS=("all" "aes-256-only" "aes-128-only" "chacha20-only")

# TLS 组选项
readonly TLS_GROUPS_OPTIONS=("all" "x25519-only" "nist-only")

# =============================================================================
# 设置安装默认值
# =============================================================================
# 集中设置所有默认值的函数 - 在配置前调用
set_installation_defaults() {
	# 网络
	ENDPOINT_TYPE="${ENDPOINT_TYPE:-4}"
	CLIENT_IPV4="${CLIENT_IPV4:-y}"
	CLIENT_IPV6="${CLIENT_IPV6:-n}"
	VPN_SUBNET_IPV4="${VPN_SUBNET_IPV4:-10.8.0.0}"
	VPN_SUBNET_IPV6="${VPN_SUBNET_IPV6:-fd42:42:42:42::}"
	PORT="${PORT:-1194}"
	PROTOCOL="${PROTOCOL:-udp}"

	# DNS（使用字符串名称）
	DNS="${DNS:-aliyun}"

	# 多客户端
	MULTI_CLIENT="${MULTI_CLIENT:-n}"

	# 加密
	CIPHER="${CIPHER:-AES-128-GCM}"
	CERT_TYPE="${CERT_TYPE:-ecdsa}"
	CERT_CURVE="${CERT_CURVE:-prime256v1}"
	RSA_KEY_SIZE="${RSA_KEY_SIZE:-2048}"
	TLS_VERSION_MIN="${TLS_VERSION_MIN:-1.2}"
	TLS13_CIPHERSUITES="${TLS13_CIPHERSUITES:-TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256}"
	TLS_GROUPS="${TLS_GROUPS:-X25519:prime256v1:secp384r1:secp521r1}"
	HMAC_ALG="${HMAC_ALG:-SHA256}"
	TLS_SIG="${TLS_SIG:-crypt-v2}"
	AUTH_MODE="${AUTH_MODE:-pki}"

	# 如果未设置，则从 CERT_TYPE 派生 CC_CIPHER
	if [[ -z $CC_CIPHER ]]; then
		if [[ $CERT_TYPE == "ecdsa" ]]; then
			CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		else
			CC_CIPHER="TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256"
		fi
	fi

	# 客户端
	CLIENT="${CLIENT:-client}"
	PASS="${PASS:-1}"
	CLIENT_CERT_DURATION_DAYS="${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}"
	SERVER_CERT_DURATION_DAYS="${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}"

	# 注意：网关值（VPN_GATEWAY_IPV4, VPN_GATEWAY_IPV6）和 IPV6_SUPPORT
	# 在 validate_network_config() 中计算，该函数在验证后调用
}

# 版本比较：如果 version1 >= version2 则返回 0
version_ge() {
	local ver1="$1" ver2="$2"
	# 使用 sort -V 进行版本比较
	[[ "$(printf '%s\n%s' "$ver1" "$ver2" | sort -V | head -n1)" == "$ver2" ]]
}

# 获取已安装的 OpenVPN 版本（例如："2.6.12"）
get_openvpn_version() {
	openvpn --version 2>/dev/null | head -1 | awk '{print $2}'
}

# 验证函数
validate_port() {
	local port="$1"
	if ! [[ "$port" =~ ^[0-9]+$ ]] || [[ "$port" -lt 1 ]] || [[ "$port" -gt 65535 ]]; then
		log_fatal "无效的端口: $port。必须是 1 到 65535 之间的数字。"
	fi
}

validate_subnet_ipv4() {
	local subnet="$1"
	# 检查格式：x.x.x.0，其中 x 是 0-255
	if ! [[ "$subnet" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.0$ ]]; then
		log_fatal "无效的 IPv4 子网: $subnet。必须是 x.x.x.0 格式（例如：10.8.0.0）"
	fi
	local octet1="${BASH_REMATCH[1]}"
	local octet2="${BASH_REMATCH[2]}"
	local octet3="${BASH_REMATCH[3]}"
	# 验证每个 octet 是 0-255
	if [[ "$octet1" -gt 255 ]] || [[ "$octet2" -gt 255 ]] || [[ "$octet3" -gt 255 ]]; then
		log_fatal "无效的 IPv4 子网: $subnet。Octets 必须是 0-255。"
	fi
	# 检查 RFC1918 私有地址范围
	if ! { [[ "$octet1" -eq 10 ]] ||
		[[ "$octet1" -eq 172 && "$octet2" -ge 16 && "$octet2" -le 31 ]] ||
		[[ "$octet1" -eq 192 && "$octet2" -eq 168 ]]; }; then
		log_fatal "无效的 IPv4 子网: $subnet。必须是私有网络（10.x.x.0, 172.16-31.x.0, 或 192.168.x.0）。"
	fi
}

validate_subnet_ipv6() {
	local subnet="$1"
	# 接受格式：以 :: 结尾的 IPv6 地址（仅前缀，此处无 CIDR 表示法）
	# 我们期望的格式如：fd42:42:42:42:: 或 fdxx:xxxx:xxxx:xxxx::
	# 脚本将为服务器指令追加 /112

	# IPv6 ULA 验证（fd00::/8 范围，至少有 /48 前缀）
	# ULA 格式：fdxx:xxxx:xxxx:: 或 fdxx:xxxx:xxxx:xxxx::，其中 x 是十六进制
	if ! [[ "$subnet" =~ ^fd[0-9a-fA-F]{2}(:[0-9a-fA-F]{1,4}){2,5}::$ ]]; then
		log_fatal "无效的 IPv6 子网: $subnet。必须是至少有 /48 前缀的 ULA 地址，以 :: 结尾（例如：fd42:42:42::）"
	fi
}

# 验证正整数
validate_positive_int() {
	local value="$1"
	local name="$2"
	if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 1 ]]; then
		log_fatal "无效的 $name: $value。必须是正整数。"
	fi
}

# 验证 MTU
validate_mtu() {
	local mtu="$1"
	if ! [[ "$mtu" =~ ^[0-9]+$ ]] || [[ "$mtu" -lt 576 ]] || [[ "$mtu" -gt 65535 ]]; then
		log_fatal "无效的 MTU: $mtu。必须在 576 到 65535 之间。"
	fi
}

# 客户端名称的最大长度（OpenSSL CN 限制）
readonly MAX_CLIENT_NAME_LENGTH=64

# 检查客户端名称是否有效（非致命，返回 true/false）
is_valid_client_name() {
	local name="$1"
	[[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#name} -le $MAX_CLIENT_NAME_LENGTH ]]
}

# 验证客户端名称，如果无效则退出并显示错误
validate_client_name() {
	local name="$1"
	if [[ -z "$name" ]]; then
		log_fatal "客户端名称不能为空。"
	fi
	if ! [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]]; then
		log_fatal "无效的客户端名称: $name。只允许字母数字字符、下划线和连字符。"
	fi
	if [[ ${#name} -gt $MAX_CLIENT_NAME_LENGTH ]]; then
		log_fatal "客户端名称太长: ${#name} 个字符。最大为 $MAX_CLIENT_NAME_LENGTH 个字符（OpenSSL CN 限制）。"
	fi
}

# 验证所有配置值（在非交互模式下捕获无效的环境变量）
validate_configuration() {
	# 验证协议
	case "$PROTOCOL" in
	udp | tcp) ;;
	*) log_fatal "无效的协议: $PROTOCOL。必须是 'udp' 或 'tcp'。" ;;
	esac

	# 验证 DNS
	case "$DNS" in
	system | unbound | cloudflare | quad9 | quad9-uncensored | fdn | dnswatch | opendns | google | yandex | adguard | nextdns | custom) ;;
	*) log_fatal "无效的 DNS 提供商: $DNS。有效提供商: system, unbound, cloudflare, quad9, quad9-uncensored, fdn, dnswatch, opendns, google, yandex, adguard, nextdns, custom" ;;
	esac

	# 验证证书类型
	case "$CERT_TYPE" in
	ecdsa | rsa) ;;
	*) log_fatal "无效的证书类型: $CERT_TYPE。必须是 'ecdsa' 或 'rsa'。" ;;
	esac

	# 验证 TLS 签名模式
	case "$TLS_SIG" in
	crypt-v2 | crypt | auth) ;;
	*) log_fatal "无效的 TLS 签名模式: $TLS_SIG。必须是 'crypt-v2', 'crypt', 或 'auth'。" ;;
	esac

	# 验证认证模式
	case "$AUTH_MODE" in
	pki | fingerprint) ;;
	*) log_fatal "无效的认证模式: $AUTH_MODE。必须是 'pki' 或 'fingerprint'。" ;;
	esac

	# 指纹模式需要 OpenVPN 2.6+
	if [[ $AUTH_MODE == "fingerprint" ]]; then
		local openvpn_ver
		openvpn_ver=$(get_openvpn_version)
		if [[ -n "$openvpn_ver" ]] && ! version_ge "$openvpn_ver" "2.6.0"; then
			log_fatal "指纹模式需要 OpenVPN 2.6.0 或更高版本。已安装版本: $openvpn_ver"
		fi
	fi

	# 验证端口
	if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [[ "$PORT" -lt 1 ]] || [[ "$PORT" -gt 65535 ]]; then
		log_fatal "无效的端口: $PORT。必须是 1 到 65535 之间的数字。"
	fi

	# 验证 CLIENT_IPV4/CLIENT_IPV6
	if [[ $CLIENT_IPV4 != "y" ]] && [[ $CLIENT_IPV6 != "y" ]]; then
		log_fatal "CLIENT_IPV4 或 CLIENT_IPV6 至少有一个必须是 'y'"
	fi

	# 验证端点类型
	case "$ENDPOINT_TYPE" in
	4 | 6) ;;
	*) log_fatal "无效的端点类型: $ENDPOINT_TYPE。必须是 '4' 或 '6'。" ;;
	esac

	# 验证密码
	case "$CIPHER" in
	AES-128-GCM | AES-192-GCM | AES-256-GCM | AES-128-CBC | AES-192-CBC | AES-256-CBC | CHACHA20-POLY1305) ;;
	*) log_fatal "无效的密码: $CIPHER。有效密码: AES-128-GCM, AES-192-GCM, AES-256-GCM, AES-128-CBC, AES-192-CBC, AES-256-CBC, CHACHA20-POLY1305" ;;
	esac

	# 验证证书曲线（仅当 ECDSA 时）
	if [[ $CERT_TYPE == "ecdsa" ]]; then
		case "$CERT_CURVE" in
		prime256v1 | secp384r1 | secp521r1) ;;
		*) log_fatal "无效的证书曲线: $CERT_CURVE。必须是 'prime256v1', 'secp384r1', 或 'secp521r1'。" ;;
		esac
	fi

	# 验证 RSA 密钥大小（仅当 RSA 时）
	if [[ $CERT_TYPE == "rsa" ]]; then
		case "$RSA_KEY_SIZE" in
		2048 | 3072 | 4096) ;;
		*) log_fatal "无效的 RSA 密钥大小: $RSA_KEY_SIZE。必须是 2048, 3072, 或 4096。" ;;
		esac
	fi

	# 验证 TLS 版本
	case "$TLS_VERSION_MIN" in
	1.2 | 1.3) ;;
	*) log_fatal "无效的 TLS 版本: $TLS_VERSION_MIN。必须是 '1.2' 或 '1.3'。" ;;
	esac

	# 验证 HMAC 算法
	case "$HMAC_ALG" in
	SHA256 | SHA384 | SHA512) ;;
	*) log_fatal "无效的 HMAC 算法: $HMAC_ALG。必须是 SHA256, SHA384, 或 SHA512。" ;;
	esac

	# 如果设置了 MTU，则验证 MTU
	if [[ -n $MTU ]]; then
		if ! [[ "$MTU" =~ ^[0-9]+$ ]] || [[ "$MTU" -lt 576 ]] || [[ "$MTU" -gt 65535 ]]; then
			log_fatal "无效的 MTU: $MTU。必须是 576 到 65535 之间的数字。"
		fi
	fi

	# 如果选择了自定义 DNS，则验证自定义 DNS
	if [[ $DNS == "custom" ]] && [[ -z $DNS1 ]]; then
		log_fatal "已选择自定义 DNS，但 DNS1（主要 DNS）未设置。使用 --dns-primary 指定。"
	fi

	# 使用专用的验证函数验证 VPN 子网
	# 这些函数检查格式、octet 范围和 RFC1918/ULA 合规性
	if [[ -n $VPN_SUBNET_IPV4 ]]; then
		validate_subnet_ipv4 "$VPN_SUBNET_IPV4"
	fi

	if [[ $CLIENT_IPV6 == "y" ]] && [[ -n $VPN_SUBNET_IPV6 ]]; then
		validate_subnet_ipv6 "$VPN_SUBNET_IPV6"
	fi
}

# =============================================================================
# 交互式辅助函数
# =============================================================================
# 数组的通用菜单选择函数
# 用法：select_from_array "提示" 数组名 "默认值" 结果变量
# 注意：使用 namerefs (-n) 处理数组
select_from_array() {
	local prompt="$1"
	local -n _options_ref="$2"
	local default="$3"
	local -n _result_ref="$4"

	# 如果已设置（非交互模式），直接返回
	if [[ -n $_result_ref ]]; then
		return
	fi

	# 查找默认索引（显示为 1-based）
	local default_idx=1
	for i in "${!_options_ref[@]}"; do
		if [[ "${_options_ref[$i]}" == "$default" ]]; then
			default_idx=$((i + 1))
			break
		fi
	done

	# 显示菜单
	local count=${#_options_ref[@]}
	for i in "${!_options_ref[@]}"; do
		log_menu "   $((i + 1))) ${_options_ref[$i]}"
	done

	# 读取选择
	local choice
	until [[ $choice =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= count)); do
		read -rp "$prompt [1-$count]: " -e -i "$default_idx" choice
	done

	_result_ref="${_options_ref[$((choice - 1))]}"
}

# 使用自定义标签选择（用于需要不同显示文本的菜单项）
# 用法：select_with_labels "提示" 标签数组 值数组 "默认值" 结果变量
select_with_labels() {
	local prompt="$1"
	local -n _labels_ref="$2"
	local -n _values_ref="$3"
	local default="$4"
	local -n _result_ref="$5"

	# 如果已设置（非交互模式），直接返回
	if [[ -n $_result_ref ]]; then
		return
	fi

	# 查找默认索引
	local default_idx=1
	for i in "${!_values_ref[@]}"; do
		if [[ "${_values_ref[$i]}" == "$default" ]]; then
			default_idx=$((i + 1))
			break
		fi
	done

	# 显示菜单
	local count=${#_labels_ref[@]}
	for i in "${!_labels_ref[@]}"; do
		log_menu "   $((i + 1))) ${_labels_ref[$i]}"
	done

	# 读取选择
	local choice
	until [[ $choice =~ ^[0-9]+$ ]] && ((choice >= 1 && choice <= count)); do
		read -rp "$prompt [1-$count]: " -e -i "$default_idx" choice
	done

	_result_ref="${_values_ref[$((choice - 1))]}"
}

# 提示 yes/no 选择，带有默认值
# 用法：prompt_yes_no "提示" "默认值" 结果变量
prompt_yes_no() {
	local prompt="$1"
	local default="$2"
	local -n _result_ref="$3"

	# 如果已设置，直接返回
	if [[ $_result_ref =~ ^[yn]$ ]]; then
		return
	fi

	until [[ $_result_ref =~ ^[yn]$ ]]; do
		read -rp "$prompt [y/n]: " -e -i "$default" _result_ref
	done
}

# 使用验证函数提示输入值
# 用法：prompt_validated "提示" "验证函数" "默认值" 结果变量
# 验证函数应返回 0 表示有效，非 0 表示无效
prompt_validated() {
	local prompt="$1"
	local validator="$2"
	local default="$3"
	local -n _result_ref="$4"

	# 如果已设置且有效，直接返回
	if [[ -n $_result_ref ]] && $validator "$_result_ref" 2>/dev/null; then
		return
	fi

	_result_ref=""
	until [[ -n $_result_ref ]] && $validator "$_result_ref" 2>/dev/null; do
		read -rp "$prompt: " -e -i "$default" _result_ref
	done
}

# 非致命端口验证器（返回 0/1）
is_valid_port() {
	local port="$1"
	[[ "$port" =~ ^[0-9]+$ ]] && ((port >= 1 && port <= 65535))
}

# 非致命 MTU 验证器（返回 0/1）
is_valid_mtu() {
	local mtu="$1"
	[[ "$mtu" =~ ^[0-9]+$ ]] && ((mtu >= 576 && mtu <= 65535))
}

# 处理安装命令
cmd_install() {
	local interactive=false
	local no_client=false
	local client_password_flag=false
	local client_password_value=""

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-i | --interactive)
			interactive=true
			shift
			;;
		--endpoint)
			[[ -z "${2:-}" ]] && log_fatal "--endpoint 需要一个参数"
			ENDPOINT="$2"
			shift 2
			;;
		--ip)
			[[ -z "${2:-}" ]] && log_fatal "--ip 需要一个参数"
			IP="$2"
			APPROVE_IP=y
			shift 2
			;;
		--endpoint-type)
			[[ -z "${2:-}" ]] && log_fatal "--endpoint-type 需要一个参数"
			case "$2" in
			4) ENDPOINT_TYPE="4" ;;
			6) ENDPOINT_TYPE="6" ;;
			*)
				log_fatal "无效的端点类型: $2。使用 '4' 或 '6'。" ;;
			esac
			shift 2
			;;
		--client-ipv4)
			CLIENT_IPV4=y
			shift
			;;
		--no-client-ipv4)
			CLIENT_IPV4=n
			shift
			;;
		--client-ipv6)
			CLIENT_IPV6=y
			shift
			;;
		--no-client-ipv6)
			CLIENT_IPV6=n
			shift
			;;
		--ipv6)
			# 遗留标志：为客户端启用 IPv6（向后兼容）
			CLIENT_IPV6=y
			shift
			;;
		--subnet-ipv4)
			[[ -z "${2:-}" ]] && log_fatal "--subnet-ipv4 需要一个参数"
			validate_subnet_ipv4 "$2"
			VPN_SUBNET_IPV4="$2"
			shift 2
			;;
		--subnet-ipv6)
			[[ -z "${2:-}" ]] && log_fatal "--subnet-ipv6 需要一个参数"
			validate_subnet_ipv6 "$2"
			VPN_SUBNET_IPV6="$2"
			shift 2
			;;
		--subnet)
			# 遗留标志：--subnet 现在映射到 --subnet-ipv4
			[[ -z "${2:-}" ]] && log_fatal "--subnet 需要一个参数"
			validate_subnet_ipv4 "$2"
			VPN_SUBNET_IPV4="$2"
			shift 2
			;;
		--port)
			[[ -z "${2:-}" ]] && log_fatal "--port 需要一个参数"
			validate_port "$2"
			PORT="$2"
			shift 2
			;;
		--port-random)
			PORT="random"
			shift
			;;
		--protocol)
			[[ -z "${2:-}" ]] && log_fatal "--protocol 需要一个参数"
			case "$2" in
			udp | tcp)
				PROTOCOL="$2"
				;;
			*) log_fatal "无效的协议: $2。使用 'udp' 或 'tcp'。" ;;
			esac
			shift 2
			;;
		--mtu)
			[[ -z "${2:-}" ]] && log_fatal "--mtu 需要一个参数"
			validate_mtu "$2"
			MTU="$2"
			shift 2
			;;
		--dns)
			[[ -z "${2:-}" ]] && log_fatal "--dns 需要一个参数"
			parse_dns_provider "$2"
			shift 2
			;;
		--dns-primary)
			[[ -z "${2:-}" ]] && log_fatal "--dns-primary 需要一个参数"
			DNS1="$2"
			shift 2
			;;
		--dns-secondary)
			[[ -z "${2:-}" ]] && log_fatal "--dns-secondary 需要一个参数"
			DNS2="$2"
			shift 2
			;;
		--multi-client)
			MULTI_CLIENT=y
			shift
			;;
		--cipher)
			[[ -z "${2:-}" ]] && log_fatal "--cipher 需要一个参数"
			parse_cipher "$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--cert-type)
			[[ -z "${2:-}" ]] && log_fatal "--cert-type 需要一个参数"
			case "$2" in
			ecdsa | rsa) CERT_TYPE="$2" ;;
			*)
				log_fatal "无效的证书类型: $2。使用 'ecdsa' 或 'rsa'。" ;;
			esac
			shift 2
			;;
		--cert-curve)
			[[ -z "${2:-}" ]] && log_fatal "--cert-curve 需要一个参数"
			CERT_CURVE=$(parse_curve "$2")
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--rsa-bits)
			[[ -z "${2:-}" ]] && log_fatal "--rsa-bits 需要一个参数"
			case "$2" in
			2048 | 3072 | 4096) RSA_KEY_SIZE="$2" ;;
			*)
				log_fatal "无效的 RSA 密钥大小: $2。使用 2048, 3072, 或 4096。" ;;
			esac
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--cc-cipher)
			[[ -z "${2:-}" ]] && log_fatal "--cc-cipher 需要一个参数"
			CC_CIPHER="$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-ciphersuites)
			[[ -z "${2:-}" ]] && log_fatal "--tls-ciphersuites 需要一个参数"
			TLS13_CIPHERSUITES="$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-version-min)
			[[ -z "${2:-}" ]] && log_fatal "--tls-version-min 需要一个参数"
			case "$2" in
			1.2 | 1.3) TLS_VERSION_MIN="$2" ;;
			*)
				log_fatal "无效的 TLS 版本: $2。使用 '1.2' 或 '1.3'。" ;;
			esac
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-groups)
			[[ -z "${2:-}" ]] && log_fatal "--tls-groups 需要一个参数"
			TLS_GROUPS="$2"
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--hmac)
			[[ -z "${2:-}" ]] && log_fatal "--hmac 需要一个参数"
			case "$2" in
			SHA256 | SHA384 | SHA512) HMAC_ALG="$2" ;;
			*)
				log_fatal "无效的 HMAC 算法: $2。使用 SHA256, SHA384, 或 SHA512。" ;;
			esac
			CUSTOMIZE_ENC=y
			shift 2
			;;
		--tls-sig)
			[[ -z "${2:-}" ]] && log_fatal "--tls-sig 需要一个参数"
			case "$2" in
			crypt-v2 | crypt | auth) TLS_SIG="$2" ;;
			*)
				log_fatal "无效的 TLS 模式: $2。使用 'crypt-v2', 'crypt', 或 'auth'。" ;;
			esac
			shift 2
			;;
		--auth-mode)
			[[ -z "${2:-}" ]] && log_fatal "--auth-mode 需要一个参数"
			case "$2" in
			pki | fingerprint) AUTH_MODE="$2" ;;
			*)
				log_fatal "无效的认证模式: $2。使用 'pki' 或 'fingerprint'。" ;;
			esac
			shift 2
			;;
		--server-cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--server-cert-days 需要一个参数"
			validate_positive_int "$2" "server-cert-days"
			SERVER_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		--client)
			[[ -z "${2:-}" ]] && log_fatal "--client 需要一个参数"
			validate_client_name "$2"
			CLIENT="$2"
			shift 2
			;;
		--client-password)
			client_password_flag=true
			# 检查下一个参数是值还是另一个标志
			if [[ -n "${2:-}" ]] && [[ ! "$2" =~ ^- ]]; then
				client_password_value="$2"
				shift
			fi
			shift
			;;
		--client-cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--client-cert-days 需要一个参数"
			validate_positive_int "$2" "client-cert-days"
			CLIENT_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		--no-client)
			no_client=true
			shift
			;;
		-h | --help)
			show_install_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME install --help' 获取用法。"
			;;
		esac
	done

	# 验证自定义 DNS 设置
	if [[ -n "${DNS1:-}" || -n "${DNS2:-}" ]] && [[ "${DNS:-}" != "custom" ]]; then
		log_fatal "--dns-primary 和 --dns-secondary 需要 --dns custom"
	fi

	# 检查是否已安装
	requireNoOpenVPN

	if [[ $interactive == true ]]; then
		# 运行交互式安装程序
		installQuestions
	else
		# 非交互式模式 - 设置标志和默认值
		NON_INTERACTIVE_INSTALL=y
		APPROVE_INSTALL=y
		APPROVE_IP=${APPROVE_IP:-y}
		CONTINUE=y

		# 处理随机端口
		if [[ $PORT == "random" ]]; then
			PORT=$(shuf -i 49152-65535 -n1)
			log_info "随机端口: $PORT"
		fi

		# 客户端设置
		if [[ $no_client == true ]]; then
			NEW_CLIENT=n
		else
			NEW_CLIENT=y
			if [[ $client_password_flag == true ]]; then
				PASS=2
				if [[ -n "$client_password_value" ]]; then
					PASSPHRASE="$client_password_value"
				fi
			fi
		fi

		# 为所有未设置的值设置默认值
		set_installation_defaults

		# 验证配置值（捕获无效的环境变量）
		validate_configuration

		# 检测 IP 并设置网络配置（交互式模式在 installQuestions 中执行此操作）
		detect_server_ips
	fi

	# 准备派生的网络配置（网关等）
	prepare_network_config

	installOpenVPN
}

# 处理卸载命令
cmd_uninstall() {
	local force=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_uninstall_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME uninstall --help' 获取用法。"
			;;
		esac
	done

	requireOpenVPN

	if [[ $force == true ]]; then
		REMOVE=y
	fi

	removeOpenVPN
}

# 处理客户端命令
cmd_client() {
	local subcmd="${1:-}"
	shift || true

	case "$subcmd" in
	"" | "-h" | "--help")
		show_client_help
		exit 0
		;;
	add)
		cmd_client_add "$@"
		;;
	list)
		cmd_client_list "$@"
		;;
	revoke)
		cmd_client_revoke "$@"
		;;
	renew)
		cmd_client_renew "$@"
		;;
	*) log_fatal "未知的客户端子命令: $subcmd。请查看 '$SCRIPT_NAME client --help' 获取用法。" ;;
	esac
}

# 处理客户端添加命令
cmd_client_add() {
	local client_name=""
	local password_flag=false
	local password_value=""

	# 第一个非标志参数是客户端名称
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--password)
			password_flag=true
			# 检查下一个参数是值还是另一个标志
			if [[ -n "${2:-}" ]] && [[ ! "$2" =~ ^- ]]; then
				password_value="$2"
				shift
			fi
			shift
			;;
		--cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--cert-days 需要一个参数"
			validate_positive_int "$2" "cert-days"
			CLIENT_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		--output)
			[[ -z "${2:-}" ]] && log_fatal "--output 需要一个参数"
			CLIENT_FILEPATH="$2"
			shift 2
			;;
		-h | --help)
			show_client_add_help
			exit 0
			;;
		-*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME client add --help' 获取用法。"
			;;
		*)
			if [[ -z "$client_name" ]]; then
				client_name="$1"
			else
				log_fatal "意外参数: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z "$client_name" ]] && log_fatal "需要客户端名称。请查看 '$SCRIPT_NAME client add --help' 获取用法。"
	validate_client_name "$client_name"

	requireOpenVPN

	# 为 newClient 函数设置变量
	CLIENT="$client_name"
	CLIENT_CERT_DURATION_DAYS=${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}

	if [[ $password_flag == true ]]; then
		PASS=2
		if [[ -n "$password_value" ]]; then
			PASSPHRASE="$password_value"
		fi
	else
		PASS=1
	fi

	newClient
	exit 0
}

# 处理客户端列表命令
cmd_client_list() {
	local format="table"

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--format)
			[[ -z "${2:-}" ]] && log_fatal "--format 需要一个参数"
			case "$2" in
			table | json) format="$2" ;;
			*)
				log_fatal "无效的格式: $2。使用 'table' 或 'json'。" ;;
			esac
			shift 2
			;;
		-h | --help)
			show_client_list_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME client list --help' 获取用法。"
			;;
		esac
	done

	requireOpenVPN

	OUTPUT_FORMAT="$format" listClients
}

# 处理客户端吊销命令
cmd_client_revoke() {
	local client_name=""
	local force=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_client_revoke_help
			exit 0
			;;
		-*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME client revoke --help' 获取用法。"
			;;
		*)
			if [[ -z "$client_name" ]]; then
				client_name="$1"
			else
				log_fatal "意外参数: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z "$client_name" ]] && log_fatal "需要客户端名称。请查看 '$SCRIPT_NAME client revoke --help' 获取用法。"

	requireOpenVPN

	CLIENT="$client_name"
	if [[ $force == true ]]; then
		REVOKE_CONFIRM=y
	fi

	revokeClient
}

# 处理客户端续订命令
cmd_client_renew() {
	local client_name=""

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--cert-days 需要一个参数"
			validate_positive_int "$2" "cert-days"
			CLIENT_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		-h | --help)
			show_client_renew_help
			exit 0
			;;
		-*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME client renew --help' 获取用法。"
			;;
		*)
			if [[ -z "$client_name" ]]; then
				client_name="$1"
			else
				log_fatal "意外参数: $1"
			fi
			shift
			;;
		esac
	done

	[[ -z "$client_name" ]] && log_fatal "需要客户端名称。请查看 '$SCRIPT_NAME client renew --help' 获取用法。"

	requireOpenVPN

	CLIENT="$client_name"
	CLIENT_CERT_DURATION_DAYS=${CLIENT_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}

	renewClient
}

# 处理服务器命令
cmd_server() {
	local subcmd="${1:-}"
	shift || true

	case "$subcmd" in
	"" | "-h" | "--help")
		show_server_help
		exit 0
		;;
	status)
		cmd_server_status "$@"
		;;
	renew)
		cmd_server_renew "$@"
		;;
	*) log_fatal "未知的服务器子命令: $subcmd。请查看 '$SCRIPT_NAME server --help' 获取用法。" ;;
	esac
}

# 处理服务器状态命令
cmd_server_status() {
	local format="table"

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--format)
			[[ -z "${2:-}" ]] && log_fatal "--format 需要一个参数"
			case "$2" in
			table | json) format="$2" ;;
			*)
				log_fatal "无效的格式: $2。使用 'table' 或 'json'。" ;;
			esac
			shift 2
			;;
		-h | --help)
			show_server_status_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME server status --help' 获取用法。"
			;;
		esac
	done

	requireOpenVPN

	OUTPUT_FORMAT="$format" listConnectedClients
}

# 处理服务器续订命令
cmd_server_renew() {
	local force=false

	while [[ $# -gt 0 ]]; do
		case "$1" in
		--cert-days)
			[[ -z "${2:-}" ]] && log_fatal "--cert-days 需要一个参数"
			validate_positive_int "$2" "cert-days"
			SERVER_CERT_DURATION_DAYS="$2"
			shift 2
			;;
		-f | --force)
			force=true
			shift
			;;
		-h | --help)
			show_server_renew_help
			exit 0
			;;
		*)
			log_fatal "未知选项: $1。请查看 '$SCRIPT_NAME server renew --help' 获取用法。"
			;;
		esac
	done

	requireOpenVPN

	SERVER_CERT_DURATION_DAYS=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
	if [[ $force == true ]]; then
		CONTINUE=y
	fi

	renewServer
}

# 处理交互式命令（传统菜单）
cmd_interactive() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			echo "启动 OpenVPN 管理的交互式菜单"
			echo ""
			echo "用法: $SCRIPT_NAME interactive"
			exit 0
			;;
		*)
			log_fatal "未知选项: $1"
			;;
		esac
	done

	if isOpenVPNInstalled; then
		manageMenu
	else
		installQuestions
		installOpenVPN
	fi
}

# 主参数解析器
parse_args() {
	# 首先解析全局选项
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--verbose)
			VERBOSE=1
			shift
			;;
		--log)
			[[ -z "${2:-}" ]] && log_fatal "--log 需要一个参数"
			LOG_FILE="$2"
			shift 2
			;;
		--no-log)
			LOG_FILE=""
			shift
			;;
		--no-color)
			# 颜色已在脚本开始时设置，但我们可以取消设置
			COLOR_RESET=''
			COLOR_RED=''
			COLOR_GREEN=''
			COLOR_YELLOW=''
			COLOR_BLUE=''
			COLOR_CYAN=''
			COLOR_DIM=''
			COLOR_BOLD=''
			shift
			;;
		-h | --help)
			show_help
			exit 0
			;;
		-*)
			# 可能是命令特定的选项，让命令处理它
			break
			;;
		*)
			# 第一个非选项是命令
			break
			;;
		esac
	done

	# 获取命令
	local cmd="${1:-}"
	shift || true

	# 检查用户是否只想获取帮助（不需要 root 权限）
	# 还会提前检测 --format json 以在 initialCheck 前抑制日志输出
	local wants_help=false
	local prev_arg=""
	for arg in "$@"; do
		if [[ "$arg" == "-h" || "$arg" == "--help" ]]; then
			wants_help=true
		fi
		if [[ "$prev_arg" == "--format" && "$arg" == "json" ]]; then
			OUTPUT_FORMAT="json"
		fi
		prev_arg="$arg"
	done

	# 分发到命令处理程序
	case "$cmd" in
	"")
		show_help
		exit 0
		;;
	install)
		[[ $wants_help == false ]] && initialCheck
		cmd_install "$@"
		;;
	uninstall)
		[[ $wants_help == false ]] && initialCheck
		cmd_uninstall "$@"
		;;
	client)
		[[ $wants_help == false ]] && initialCheck
		cmd_client "$@"
		;;
	server)
		[[ $wants_help == false ]] && initialCheck
		cmd_server "$@"
		;;
	interactive)
		[[ $wants_help == false ]] && initialCheck
		cmd_interactive "$@"
		;;
	*)
		log_fatal "未知命令: $cmd。请查看 '$SCRIPT_NAME --help' 获取用法。"
		;;
	esac
}

# =============================================================================
# 系统检查函数
# =============================================================================
function isRoot() {
	if [ "$EUID" -ne 0 ]; then
		return 1
	fi
}

function tunAvailable() {
	if [ ! -e /dev/net/tun ]; then
		return 1
	fi
}

function checkOS() {
	if [[ -e /etc/debian_version ]]; then
		OS="debian"
		source /etc/os-release

		if [[ $ID == "debian" || $ID == "raspbian" ]]; then
			if [[ $VERSION_ID -lt 11 ]]; then
				log_warn "您的 Debian 版本不受支持。"
				log_info "但是，如果您使用的是 Debian >= 11 或不稳定/测试版本，您可以继续使用，但风险自负。"
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续吗？[y/n]: " -e CONTINUE
					done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		elif [[ $ID == "ubuntu" ]]; then
			OS="ubuntu"
			MAJOR_UBUNTU_VERSION=$(echo "$VERSION_ID" | cut -d '.' -f1)
			if [[ $MAJOR_UBUNTU_VERSION -lt 18 ]]; then
				log_warn "您的 Ubuntu 版本不受支持。"
				log_info "但是，如果您使用的是 Ubuntu >= 18.04 或测试版本，您可以继续使用，但风险自负。"
				until [[ $CONTINUE =~ (y|n) ]]; do
					read -rp "继续吗？[y/n]: " -e CONTINUE
					done
				if [[ $CONTINUE == "n" ]]; then
					exit 1
				fi
			fi
		fi
	elif [[ -e /etc/os-release ]]; then
		source /etc/os-release
		if [[ $ID == "fedora" || $ID_LIKE == "fedora" ]]; then
			OS="fedora"
		fi
		if [[ $ID == "opensuse-tumbleweed" ]]; then
			OS="opensuse"
		fi
		if [[ $ID == "opensuse-leap" ]]; then
			OS="opensuse"
			if [[ ${VERSION_ID%.*} -lt 16 ]]; then
				log_info "此脚本仅支持 openSUSE Leap 16+。"
				log_fatal "您的 openSUSE Leap 版本不受支持。"
			fi
		fi
		if [[ $ID == "centos" || $ID == "rocky" || $ID == "almalinux" ]]; then
			OS="centos"
		fi
		if [[ $ID == "ol" ]]; then
			OS="oracle"
		fi
		if [[ $OS =~ (centos|oracle) ]] && [[ ${VERSION_ID%.*} -lt 8 ]]; then
			log_info "此脚本仅支持 CentOS Stream / Rocky Linux / AlmaLinux / Oracle Linux 版本 8+。"
			log_fatal "您的版本不受支持。"
		fi
		if [[ $ID == "amzn" ]]; then
			if [[ "$(echo "$PRETTY_NAME" | cut -c 1-18)" == "Amazon Linux 2023." ]] && [[ "$(echo "$PRETTY_NAME" | cut -c 19)" -ge 6 ]]; then
				OS="amzn2023"
			else
				log_info "此脚本仅支持 Amazon Linux 2023.6+"
				log_info "Amazon Linux 2 已停止支持。"
				log_fatal "您的 Amazon Linux 版本不受支持。"
			fi
		fi
		if [[ $ID == "arch" ]]; then
			OS="arch"
		fi
	elif [[ -e /etc/arch-release ]]; then
		OS=arch
	else
		log_fatal "看起来您不是在 Debian、Ubuntu、Fedora、openSUSE、CentOS、Amazon Linux 2023、Oracle Linux、Arch Linux、Rocky Linux 或 AlmaLinux 系统上运行此安装程序。"
	fi
}

function checkArchPendingKernelUpgrade() {
	if [[ $OS != "arch" ]]; then
		return 0
	fi

	# 检查运行中内核的模块是否可用
	#（检测内核是否已升级但系统未重启）
	# 跳过容器中的此检查 - 它们共享主机内核但有自己的 /lib/modules
	if [[ -f /.dockerenv ]] || grep -qE '(docker|lxc|containerd)' /proc/1/cgroup 2>/dev/null; then
		log_info "在容器中运行，跳过内核模块检查"
	else
		local running_kernel
		running_kernel=$(uname -r)
		if [[ ! -d "/lib/modules/${running_kernel}" ]]; then
			log_error "未找到运行内核 ($running_kernel) 的内核模块!"
			log_info "这通常意味着内核已升级但系统未重启。"
			log_fatal "请重启系统并再次运行此脚本。"
		fi
	fi

	log_info "检查 Arch Linux 上的待处理内核升级..."

	# 同步包数据库以检查更新
	if ! pacman -Sy &>/dev/null; then
		log_warn "同步包数据库失败，跳过内核升级检查"
		return 0
	fi

	# 检查待处理的 Linux 内核升级
	local pending_kernels
	pending_kernels=$(pacman -Qu 2>/dev/null | grep -E '^linux' || true)

	if [[ -n "$pending_kernels" ]]; then
		log_warn "Linux 内核升级待处理:"
		echo "$pending_kernels" | while read -r line; do
			log_info "  $line"
		done
		echo ""
		log_info "此脚本使用 'pacman -Syu'，这将升级您的内核。"
		log_info "内核升级后，TUN 模块在重启前不可用。"
		echo ""
		log_info "请先升级系统并重启:"
		log_info "  sudo pacman -Syu"
		log_info "  sudo reboot"
		echo ""
		log_fatal "中止。升级并重启后再次运行此脚本。"
	fi

	log_success "没有待处理的内核升级"
}

function initialCheck() {
	log_debug "检查root权限..."
	if ! isRoot; then
		log_fatal "对不起，您需要以root身份运行此脚本。"
	fi
	log_debug "Root检查通过"

	log_debug "检查TUN设备可用性..."
	if ! tunAvailable; then
		log_fatal "TUN不可用。"
	fi
	log_debug "TUN设备在 /dev/net/tun 可用"

	log_debug "检测操作系统..."
	checkOS
	log_debug "检测到操作系统: $OS (${PRETTY_NAME:-unknown})"
	checkArchPendingKernelUpgrade
}

# 检查 OpenVPN 版本是否至少为指定版本
# 用法: openvpnVersionAtLeast "2.5"
# 如果版本 >= 指定版本则返回 0，否则返回 1
function openvpnVersionAtLeast() {
	local required_version="$1"
	local installed_version

	if ! command -v openvpn &>/dev/null; then
		return 1
	fi

	installed_version=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
	if [[ -z "$installed_version" ]]; then
		return 1
	fi

	# 使用 sort -V 比较版本
	if [[ "$(printf '%s\n' "$required_version" "$installed_version" | sort -V | head -n1)" == "$required_version" ]]; then
		return 0
	fi
	return 1
}

# 检查内核版本是否至少为指定版本
# 用法: kernelVersionAtLeast "6.16"
# 如果版本 >= 指定版本则返回 0，否则返回 1
function kernelVersionAtLeast() {
	local required_version="$1"
	local kernel_version

	kernel_version=$(uname -r | cut -d'-' -f1)
	if [[ -z "$kernel_version" ]]; then
		return 1
	fi

	if [[ "$(printf '%s\n' "$required_version" "$kernel_version" | sort -V | head -n1)" == "$required_version" ]]; then
		return 0
	fi
	return 1
}

# 检查数据通道卸载 (DCO) 是否可用
# DCO 要求: OpenVPN 2.6+, 内核支持 (Linux 6.16+ 或 ovpn-dco 模块)
# 如果 DCO 可用则返回 0，否则返回 1
function isDCOAvailable() {
	# DCO 需要 OpenVPN 2.6+
	if ! openvpnVersionAtLeast "2.6"; then
		return 1
	fi

	# DCO 内置于 Linux 6.16+，或可通过 ovpn-dco 模块获得
	if kernelVersionAtLeast "6.16"; then
		return 0
	elif lsmod 2>/dev/null | grep -q "^ovpn_dco" || modinfo ovpn-dco &>/dev/null; then
		return 0
	fi
	return 1
}

function installOpenVPNRepo() {
	log_info "设置官方 OpenVPN 仓库..."

	if [[ $OS =~ (debian|ubuntu) ]]; then
		run_cmd_fatal "更新包列表" apt-get update
		run_cmd_fatal "安装依赖" apt-get install -y ca-certificates curl

		# 创建 keyrings 目录
		run_cmd "创建 keyrings 目录" mkdir -p /etc/apt/keyrings

		# 下载并安装 GPG 密钥
		if ! run_cmd "下载 OpenVPN GPG 密钥" curl -fsSL https://swupdate.openvpn.net/repos/repo-public.gpg -o /etc/apt/keyrings/openvpn-repo-public.asc; then
			log_fatal "下载 OpenVPN 仓库 GPG 密钥失败"
		fi

		# 添加仓库 - 使用稳定版本
		if [[ -z "${VERSION_CODENAME}" ]]; then
			log_fatal "VERSION_CODENAME 未设置。无法配置 OpenVPN 仓库。"
		fi
		echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/openvpn-repo-public.asc] https://build.openvpn.net/debian/openvpn/stable ${VERSION_CODENAME} main" >/etc/apt/sources.list.d/openvpn-aptrepo.list

		log_info "使用新仓库更新包列表..."
		run_cmd_fatal "更新包列表" apt-get update

		log_info "OpenVPN 官方仓库已配置"

	elif [[ $OS =~ (centos|oracle) ]]; then
		# 对于 RHEL 基础系统，使用 Fedora Copr (OpenVPN 2.6 稳定版)
		# pkcs11-helper 依赖需要 EPEL
		log_info "为 RHEL 基础系统配置 OpenVPN Copr 仓库..."

		# Oracle Linux 使用 oracle-epel-release-el* 而不是 epel-release
		if [[ $OS == "oracle" ]]; then
			EPEL_PACKAGE="oracle-epel-release-el${VERSION_ID%.*}"
		else
			EPEL_PACKAGE="epel-release"
		fi

		if ! command -v dnf &>/dev/null; then
			run_cmd_fatal "安装 EPEL 仓库" yum install -y "$EPEL_PACKAGE"
			run_cmd_fatal "安装 yum-plugin-copr" yum install -y yum-plugin-copr
			run_cmd_fatal "启用 OpenVPN Copr 仓库" yum copr enable -y @OpenVPN/openvpn-release-2.6
		else
			run_cmd_fatal "安装 EPEL 仓库" dnf install -y "$EPEL_PACKAGE"
			run_cmd_fatal "安装 dnf-plugins-core" dnf install -y dnf-plugins-core
			run_cmd_fatal "启用 OpenVPN Copr 仓库" dnf copr enable -y @OpenVPN/openvpn-release-2.6
		fi

		log_info "OpenVPN Copr 仓库已配置"

	elif [[ $OS == "fedora" ]]; then
		# Fedora 已经包含了最新的 OpenVPN 2.6.x，不需要 Copr
		log_info "Fedora 已经包含了最新的 OpenVPN 包，使用发行版版本"

	else
		log_info "此操作系统没有官方 OpenVPN 仓库，使用发行版包"
	fi
}

function installUnbound() {
	log_info "安装 Unbound DNS 解析器..."

	# 如果未安装 Unbound，则安装
	if [[ ! -e /etc/unbound/unbound.conf ]]; then
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd_fatal "安装 Unbound" apt-get install -y unbound
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd_fatal "安装 Unbound" yum install -y unbound
		elif [[ $OS =~ (fedora|amzn2023) ]]; then
			run_cmd_fatal "安装 Unbound" dnf install -y unbound
		elif [[ $OS == "opensuse" ]]; then
			run_cmd_fatal "安装 Unbound" zypper install -y unbound
		elif [[ $OS == "arch" ]]; then
			run_cmd_fatal "安装 Unbound" pacman -Syu --noconfirm unbound
		fi
	fi

	# 为 OpenVPN 配置 Unbound（无论是否新安装）
	# 创建 conf.d 目录（适用于所有发行版）
	run_cmd "创建 Unbound 配置目录" mkdir -p /etc/unbound/unbound.conf.d

	# 确保主配置包含 conf.d 目录
	# 现代 Debian/Ubuntu 使用 include-toplevel，其他系统需要 include 指令
	if ! grep -qE "include(-toplevel)?:\s*.*/etc/unbound/unbound.conf.d" /etc/unbound/unbound.conf 2>/dev/null; then
		# 如果不存在，添加 conf.d 的 include 指令
		echo 'include: "/etc/unbound/unbound.conf.d/*.conf"' >>/etc/unbound/unbound.conf
	fi

	# 生成 OpenVPN 特定的 Unbound 配置
	# 在所有发行版上使用一致的最佳实践设置
	{
		echo 'server:'
		echo '    # OpenVPN DNS resolver configuration'

		# IPv4 VPN 接口（仅当客户端获得 IPv4 时）
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "    interface: $VPN_GATEWAY_IPV4"
			echo "    access-control: $VPN_SUBNET_IPV4/24 allow"
		fi

		# IPv6 VPN 接口（仅当客户端获得 IPv6 时）
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "    interface: $VPN_GATEWAY_IPV6"
			echo "    access-control: ${VPN_SUBNET_IPV6}/112 allow"
		fi

		echo ''
		echo '    # Security hardening'
		echo '    hide-identity: yes'
		echo '    hide-version: yes'
		echo '    harden-glue: yes'
		echo '    harden-dnssec-stripped: yes'
		echo ''
		echo '    # Performance optimizations'
		echo '    prefetch: yes'
		echo '    use-caps-for-id: yes'
		echo '    qname-minimisation: yes'
		echo ''
		echo '    # Allow binding before tun interface exists'
		echo '    ip-freebind: yes'
		echo ''
		echo '    # DNS rebinding protection'
		echo '    private-address: 10.0.0.0/8'
		echo '    private-address: 172.16.0.0/12'
		echo '    private-address: 192.168.0.0/16'
		echo '    private-address: 169.254.0.0/16'
		echo '    private-address: 127.0.0.0/8'
		echo '    private-address: fd00::/8'
		echo '    private-address: fe80::/10'
		echo '    private-address: ::ffff:0:0/96'

		# 如果启用了 IPv6，将 VPN 子网添加到私有地址
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "    private-address: ${VPN_SUBNET_IPV6}/112"
		fi

		# 禁用远程控制（openSUSE 需要 SSL 证书）
		if [[ $OS == "opensuse" ]]; then
			echo ''
			echo 'remote-control:'
			echo '    control-enable: no'
		fi
	} >/etc/unbound/unbound.conf.d/openvpn.conf

	run_cmd "Enabling Unbound service" systemctl enable unbound
	run_cmd "Starting Unbound service" systemctl restart unbound

	# 验证 Unbound 是否正在运行
	for i in {1..10}; do
		if pgrep -x unbound >/dev/null; then
			return 0
		fi
		sleep 1
	done
	log_fatal "Unbound failed to start. Check 'journalctl -u unbound' for details."
}

function resolvePublicIPv4() {
	local public_ip=""

	# 尝试解析公共 IPv4，使用：https://api.seeip.org
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://api.seeip.org 2>/dev/null)
	fi

	# 尝试使用：https://ifconfig.me 解析
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://ifconfig.me 2>/dev/null)
	fi

	# 尝试使用：https://api.ipify.org 解析
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -4 https://api.ipify.org 2>/dev/null)
	fi

	# 尝试使用：ns1.google.com 解析
	if [[ -z $public_ip ]]; then
		public_ip=$(dig -4 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi
	echo "$public_ip"
}

function resolvePublicIPv6() {
	local public_ip=""

	# 尝试解析公共 IPv6，使用：https://api6.seeip.org
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://api6.seeip.org 2>/dev/null)
	fi

	# 尝试使用：https://ifconfig.me (IPv6) 解析
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://ifconfig.me 2>/dev/null)
	fi

	# 尝试使用：https://api64.ipify.org (双栈，优先 IPv6) 解析
	if [[ -z $public_ip ]]; then
		public_ip=$(curl -f -m 5 -sS --retry 2 --retry-connrefused -6 https://api64.ipify.org 2>/dev/null)
	fi

	# 尝试使用：ns1.google.com 解析
	if [[ -z $public_ip ]]; then
		public_ip=$(dig -6 TXT +short o-o.myaddr.l.google.com @ns1.google.com | tr -d '"')
	fi

	echo "$public_ip"
}

# 向后兼容的遗留包装器
function resolvePublicIP() {
	if [[ $ENDPOINT_TYPE == "6" ]]; then
		resolvePublicIPv6
	else
		resolvePublicIPv4
	fi
}

# 检测服务器的 IPv4 和 IPv6 地址
function detect_server_ips() {
	IP_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	IP_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	# 根据 ENDPOINT_TYPE 设置 IP
	if [[ $ENDPOINT_TYPE == "6" ]]; then
		IP="$IP_IPV6"
	else
		IP="$IP_IPV4"
	fi
}

# 计算派生的网络配置值
function prepare_network_config() {
	# 计算 IPv4 网关（始终需要，防止泄漏）
	VPN_GATEWAY_IPV4="${VPN_SUBNET_IPV4%.*}.1"

	# 如果启用了 IPv6，则计算 IPv6 网关
	if [[ $CLIENT_IPV6 == "y" ]]; then
		VPN_GATEWAY_IPV6="${VPN_SUBNET_IPV6}1"
	fi

	# Set legacy variable for backward compatibility
	IPV6_SUPPORT="$CLIENT_IPV6"
}

function installQuestions() {
	log_header "OpenVPN 安装器"
	log_prompt "Git 仓库地址: https://github.com/plutobe/openvpn-install-zh"

	log_prompt "在开始设置之前，我需要问你几个问题。"
	log_prompt "如果你对默认选项没有意见，可以直接按回车键。"

	# ==========================================================================
	# 步骤 1：检测服务器 IP 地址
	# ==========================================================================
	log_menu ""
	log_prompt "正在检测服务器IP地址..."

	# 检测IPv4地址
	IP_IPV4=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | head -1)
	# 检测IPv6地址
	IP_IPV6=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)

	if [[ -n $IP_IPV4 ]]; then
		log_prompt "  检测到IPv4地址: $IP_IPV4"
	else
		log_prompt "  未检测到IPv4地址"
	fi
	if [[ -n $IP_IPV6 ]]; then
		log_prompt "  检测到IPv6地址: $IP_IPV6"
	else
		log_prompt "  未检测到IPv6地址"
	fi

	# ==========================================================================
	# 步骤 2：端点类型选择
	# ==========================================================================
	log_menu ""
	log_prompt "客户端应该使用什么IP版本连接到这个服务器？"

	# 根据可用地址确定默认选项
	if [[ -n $IP_IPV4 ]]; then
		ENDPOINT_TYPE_DEFAULT=1
	elif [[ -n $IP_IPV6 ]]; then
		ENDPOINT_TYPE_DEFAULT=2
	else
		log_fatal "此服务器上未检测到IPv4或IPv6地址。"
	fi

	log_menu "   1) IPv4"
	log_menu "   2) IPv6"
	until [[ $ENDPOINT_TYPE_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "端点类型 [1-2]: " -e -i $ENDPOINT_TYPE_DEFAULT ENDPOINT_TYPE_CHOICE
	done
	case $ENDPOINT_TYPE_CHOICE in
	1)
		ENDPOINT_TYPE="4"
		IP="$IP_IPV4"
		;;
	2)
		ENDPOINT_TYPE="6"
		IP="$IP_IPV6"
		;;
	esac

	# ==========================================================================
	# 步骤 3：端点地址（IPv4处理NAT，IPv6直接连接）
	# ==========================================================================
	APPROVE_IP=${APPROVE_IP:-n}
	if [[ $APPROVE_IP =~ n ]]; then
		log_menu ""
		if [[ $ENDPOINT_TYPE == "4" ]]; then
			log_prompt "服务器监听IPv4地址:"
			read -rp "IPv4地址: " -e -i "$IP" IP
		else
			log_prompt "服务器监听IPv6地址:"
			read -rp "IPv6地址: " -e -i "$IP" IP
		fi
	fi

	# 如果是IPv4且为私有IP，服务器在NAT后面
	if [[ $ENDPOINT_TYPE == "4" ]] && echo "$IP" | grep -qE '^(10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.|192\.168)'; then
		log_menu ""
		log_prompt "看起来此服务器在NAT后面。它的公共IPv4地址或主机名是什么？"
		log_prompt "我们需要它让客户端连接到服务器。"

		if [[ -z $ENDPOINT ]]; then
			DEFAULT_ENDPOINT=$(resolvePublicIPv4)
		fi

		until [[ $ENDPOINT != "" ]]; do
			read -rp "公共IPv4地址或主机名: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
		done
	elif [[ $ENDPOINT_TYPE == "6" ]]; then
		# 对于IPv6，检查是否为链路本地地址（以fe80开头）
		if echo "$IP" | grep -qiE '^fe80'; then
			log_menu ""
			log_prompt "检测到的IPv6地址是链路本地地址。公共IPv6地址或主机名是什么？"
			log_prompt "我们需要它让客户端连接到服务器。"

			if [[ -z $ENDPOINT ]]; then
				DEFAULT_ENDPOINT=$(resolvePublicIPv6)
			fi

			until [[ $ENDPOINT != "" ]]; do
				read -rp "公共IPv6地址或主机名: " -e -i "$DEFAULT_ENDPOINT" ENDPOINT
			done
		fi
	fi

	# ==========================================================================
	# 步骤4: 客户端IP版本
	# ==========================================================================
	log_menu ""
	log_prompt "VPN客户端应该使用什么IP版本？"
	log_prompt "这决定了它们的VPN地址和通过隧道的互联网访问。"

	# 检查IPv6连接性以提供建议
	if type ping6 >/dev/null 2>&1; then
		PING6="ping6 -c1 -W2 ipv6.google.com > /dev/null 2>&1"
	else
		PING6="ping -6 -c1 -W2 ipv6.google.com > /dev/null 2>&1"
	fi
	HAS_IPV6_CONNECTIVITY="n"
	if eval "$PING6"; then
		HAS_IPV6_CONNECTIVITY="y"
	fi

	# 根据连接性提供默认建议
	if [[ $HAS_IPV6_CONNECTIVITY == "y" ]]; then
		CLIENT_IP_DEFAULT=3 # 如果IPv6可用，使用双栈
	else
		CLIENT_IP_DEFAULT=1 # 否则仅使用IPv4
	fi

	log_menu "   1) 仅IPv4"
	log_menu "   2) 仅IPv6"
	log_menu "   3) 双栈 (IPv4 + IPv6)"
	until [[ $CLIENT_IP_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "客户端IP版本 [1-3]: " -e -i $CLIENT_IP_DEFAULT CLIENT_IP_CHOICE
	done
	case $CLIENT_IP_CHOICE in
	1)
		CLIENT_IPV4="y"
		CLIENT_IPV6="n"
		;;
	2)
		CLIENT_IPV4="n"
		CLIENT_IPV6="y"
		;;
	3)
		CLIENT_IPV4="y"
		CLIENT_IPV6="y"
		;;
	esac

	# ==========================================================================
	# 步骤 5：IPv4 子网（仅在启用 IPv4 时提示，但始终设置以防止泄漏）
	# ==========================================================================
	if [[ $CLIENT_IPV4 == "y" ]]; then
		log_menu ""
		log_prompt "IPv4 VPN 子网:"
		log_menu "   1) 默认: 10.8.0.0/24"
		log_menu "   2) 自定义"
		until [[ $SUBNET_IPV4_CHOICE =~ ^[1-2]$ ]]; do
			read -rp "IPv4 子网选择 [1-2]: " -e -i 1 SUBNET_IPV4_CHOICE
		done
		case $SUBNET_IPV4_CHOICE in
		1)
			VPN_SUBNET_IPV4="10.8.0.0"
			;;
		2)
			# 如果 VPN_SUBNET_IPV4 已设置（例如通过环境变量），则跳过提示
			if [[ -z $VPN_SUBNET_IPV4 ]]; then
				until [[ $VPN_SUBNET_IPV4 =~ ^(10\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|172\.(1[6-9]|2[0-9]|3[0-1])\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])|192\.168\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9]))\.0$ ]]; do
					read -rp "自定义 IPv4 子网（例如：10.9.0.0）: " VPN_SUBNET_IPV4
				done
			fi
			;;
		esac
	else
		# 仅 IPv6 模式：仍需 IPv4 子网以防止泄漏（redirect-gateway def1）
		VPN_SUBNET_IPV4="10.8.0.0"
	fi

	# ==========================================================================
	# 步骤 6：IPv6 子网（如果为客户端启用了 IPv6）
	# ==========================================================================
	if [[ $CLIENT_IPV6 == "y" ]]; then
		log_menu ""
		log_prompt "IPv6 VPN 子网:"
		log_menu "   1) 默认: fd42:42:42:42::/112"
		log_menu "   2) 自定义"
		until [[ $SUBNET_IPV6_CHOICE =~ ^[1-2]$ ]]; do
			read -rp "IPv6 子网选择 [1-2]: " -e -i 1 SUBNET_IPV6_CHOICE
		done
		case $SUBNET_IPV6_CHOICE in
		1)
			VPN_SUBNET_IPV6="fd42:42:42:42::"
			;;
		2)
			# 如果 VPN_SUBNET_IPV6 已设置（例如通过环境变量），则跳过提示
			if [[ -z $VPN_SUBNET_IPV6 ]]; then
				until [[ $VPN_SUBNET_IPV6 =~ ^fd[0-9a-fA-F]{0,2}(:[0-9a-fA-F]{0,4}){0,6}::$ ]]; do
					read -rp "自定义 IPv6 子网（例如：fd12:3456:789a::）: " VPN_SUBNET_IPV6
				done
			fi
			;;
		esac
	fi

	log_menu ""
log_prompt "您希望 OpenVPN 监听哪个端口？"
log_menu "   1) 默认: 1194"
log_menu "   2) 自定义"
log_menu "   3) 随机 [49152-65535]"
until [[ $PORT_CHOICE =~ ^[1-3]$ ]]; do
	read -rp "端口选择 [1-3]: " -e -i 1 PORT_CHOICE
done
case $PORT_CHOICE in
1)
	PORT="1194"
	;;
2)
	until [[ $PORT =~ ^[0-9]+$ ]] && [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ]; do
		read -rp "自定义端口 [1-65535]: " -e -i 1194 PORT
	done
	;;
3)
	# 在私有端口范围内生成随机数
	PORT=$(shuf -i 49152-65535 -n1)
	log_info "随机端口: $PORT"
	;;
esac
log_menu ""
log_prompt "您希望 OpenVPN 使用什么协议？"
log_prompt "UDP 更快。除非不可用，否则不应使用 TCP。"
log_menu "   1) UDP"
log_menu "   2) TCP"
until [[ $PROTOCOL_CHOICE =~ ^[1-2]$ ]]; do
	read -rp "协议 [1-2]: " -e -i 1 PROTOCOL_CHOICE
done
	case $PROTOCOL_CHOICE in
	1)
		PROTOCOL="udp"
		;;
	2)
		PROTOCOL="tcp"
		;;
	esac
	log_menu ""
	log_prompt "您希望 VPN 使用什么 DNS 解析器？"
	local dns_labels=("当前系统解析器（来自 /etc/resolv.conf）" "自托管 DNS 解析器（Unbound）" "阿里云 (Anycast: 中国)" "Cloudflare (Anycast: 全球)" "Quad9 (Anycast: 全球)" "Quad9 uncensored (Anycast: 全球)" "FDN (法国)" "DNS.WATCH (德国)" "OpenDNS (Anycast: 全球)" "Google (Anycast: 全球)" "Yandex Basic (俄罗斯)" "AdGuard DNS (Anycast: 全球)" "NextDNS (Anycast: 全球)" "自定义")
	local dns_valid=false
	until [[ $dns_valid == true ]]; do
			select_with_labels "DNS" dns_labels DNS_PROVIDERS "aliyun" DNS
			if [[ $DNS == "unbound" ]] && [[ -e /etc/unbound/unbound.conf ]]; then
			log_menu ""
			log_prompt "Unbound已经安装。"
	log_prompt "您可以允许脚本配置它，以便从您的OpenVPN客户端使用它"
	log_prompt "我们将简单地向/etc/unbound/unbound.conf添加第二个服务器，用于OpenVPN子网。"
			log_prompt "未对当前配置进行任何更改。"
			log_menu ""

			local unbound_continue
		until [[ $unbound_continue =~ ^[yn]$ ]]; do
			read -rp "是否将配置更改应用到 Unbound？[y/n]: " -e unbound_continue
		done
			if [[ $unbound_continue == "n" ]]; then
				unset DNS
			else
				dns_valid=true
			fi
		elif [[ $DNS == "custom" ]]; then
			until [[ $DNS1 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
			read -rp "主要 DNS: " -e DNS1
		done
		until [[ $DNS2 =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
			read -rp "次要 DNS (可选): " -e DNS2
			if [[ $DNS2 == "" ]]; then
				break
			fi
		done
			dns_valid=true
		else
			dns_valid=true
		fi
	done
	log_menu ""
	log_prompt "您是否允许单个.ovpn配置文件同时在多个设备上使用？"
	log_prompt "注意：启用此选项将禁用客户端的持久IP地址。"
	until [[ $MULTI_CLIENT =~ (y|n) ]]; do
		read -rp "允许每个客户端使用多个设备吗？[y/n]: " -e -i n MULTI_CLIENT
	done
	log_menu ""
	log_prompt "您想要自定义隧道MTU吗？"
	log_menu "   MTU控制最大数据包大小。较低的值可以帮助解决"
	log_menu "   某些网络上的连接问题（例如，PPPoE，移动网络）。"
	log_menu "   1) 默认值 (1500) - 适用于大多数网络"
	log_menu "   2) 自定义"
	until [[ $MTU_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "MTU选择 [1-2]: " -e -i 1 MTU_CHOICE
	done
	if [[ $MTU_CHOICE == "2" ]]; then
		until [[ $MTU =~ ^[0-9]+$ ]] && [[ $MTU -ge 576 ]] && [[ $MTU -le 65535 ]]; do
			read -rp "MTU [576-65535]: " -e -i 1500 MTU
		done
	fi
	log_menu ""
	log_prompt "请选择认证模式："
	log_menu "   1) PKI (证书颁发机构) - 传统的基于CA的认证（推荐用于大型设置）"
	log_menu "   2) 对等指纹 - 使用证书指纹的简化类WireGuard认证"
	log_menu "      注意：指纹模式需要OpenVPN 2.6+，适合小型/家庭设置"
	local auth_mode_choice
	until [[ $auth_mode_choice =~ ^[1-2]$ ]]; do
		read -rp "认证模式 [1-2]: " -e -i 1 auth_mode_choice
	done
	case $auth_mode_choice in
	1)
		AUTH_MODE="pki"
		;;
	2)
		AUTH_MODE="fingerprint"
		# Verify OpenVPN 2.6+ is available for fingerprint mode
		local openvpn_ver
		openvpn_ver=$(get_openvpn_version)
		if [[ -n "$openvpn_ver" ]] && ! version_ge "$openvpn_ver" "2.6.0"; then
			log_warn "检测到 OpenVPN $openvpn_ver。指纹模式需要 2.6.0+ 版本。"
			log_warn "设置过程中将安装 OpenVPN 2.6+。"
		fi
		;;
	esac
	log_menu ""
	log_prompt "您是否要自定义加密设置？"
	log_prompt "除非您知道自己在做什么，否则请使用脚本提供的默认参数。"
	log_prompt "请注意，无论您选择什么，脚本中提供的所有选项都是安全的（与OpenVPN的默认设置不同）。"
	log_prompt "了解更多信息，请访问 https://github.com/plutobe/openvpn-install-zh#安全性和加密。"
	log_menu ""
	until [[ $CUSTOMIZE_ENC =~ (y|n) ]]; do
		read -rp "是否自定义加密设置？[y/n]: " -e -i n CUSTOMIZE_ENC
	done
	if [[ $CUSTOMIZE_ENC == "n" ]]; then
		# Use default, sane and fast parameters
		CIPHER="AES-128-GCM"
		CERT_TYPE="ecdsa"
		CERT_CURVE="prime256v1"
		CC_CIPHER="TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
		TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
		TLS_VERSION_MIN="1.2"
		TLS_GROUPS="X25519:prime256v1:secp384r1:secp521r1"
		HMAC_ALG="SHA256"
		TLS_SIG="crypt-v2"
	else
		log_menu ""
	log_prompt "请选择要用于数据通道的加密算法："
	log_menu "   1) AES-128-GCM (推荐)"
	log_menu "   2) AES-192-GCM"
	log_menu "   3) AES-256-GCM"
	log_menu "   4) AES-128-CBC"
	log_menu "   5) AES-192-CBC"
	log_menu "   6) AES-256-CBC"
	log_menu "   7) CHACHA20-POLY1305 (需要 OpenVPN 2.5+，适合没有 AES-NI 的设备)"
	until [[ $CIPHER_CHOICE =~ ^[1-7]$ ]]; do
		read -rp "加密算法 [1-7]: " -e -i 1 CIPHER_CHOICE
	done
		case $CIPHER_CHOICE in
		1)
			CIPHER="AES-128-GCM"
			;;
		2)
			CIPHER="AES-192-GCM"
			;;
		3)
			CIPHER="AES-256-GCM"
			;;
		4)
			CIPHER="AES-128-CBC"
			;;
		5)
			CIPHER="AES-192-CBC"
			;;
		6)
			CIPHER="AES-256-CBC"
			;;
		7)
			CIPHER="CHACHA20-POLY1305"
			;;
		esac
		log_menu ""
	log_prompt "请选择要使用的证书类型："
	log_menu "   1) ECDSA (推荐)"
	log_menu "   2) RSA"
	local cert_type_choice
	until [[ $cert_type_choice =~ ^[1-2]$ ]]; do
		read -rp "证书密钥类型 [1-2]: " -e -i 1 cert_type_choice
	done
		case $cert_type_choice in
		1)
			CERT_TYPE="ecdsa"
			log_menu ""
	log_prompt "请选择要用于证书密钥的曲线："
	select_from_array "曲线" CERT_CURVES "prime256v1" CERT_CURVE
	;;
	2)
		CERT_TYPE="rsa"
		log_menu ""
		log_prompt "请选择要用于证书RSA密钥的大小："
		select_from_array "RSA密钥大小" RSA_KEY_SIZES "2048" RSA_KEY_SIZE
		;;
		esac
		log_menu ""
	log_prompt "请选择要用于控制通道的加密算法："
	local cc_labels cc_values
		if [[ $CERT_TYPE == "ecdsa" ]]; then
			cc_labels=("ECDHE-ECDSA-AES-128-GCM-SHA256 (推荐)" "ECDHE-ECDSA-AES-256-GCM-SHA384" "ECDHE-ECDSA-CHACHA20-POLY1305 (OpenVPN 2.5+)")
			cc_values=("TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256" "TLS-ECDHE-ECDSA-WITH-AES-256-GCM-SHA384" "TLS-ECDHE-ECDSA-WITH-CHACHA20-POLY1305-SHA256")
		else
			cc_labels=("ECDHE-RSA-AES-128-GCM-SHA256 (推荐)" "ECDHE-RSA-AES-256-GCM-SHA384" "ECDHE-RSA-CHACHA20-POLY1305 (OpenVPN 2.5+)")
			cc_values=("TLS-ECDHE-RSA-WITH-AES-128-GCM-SHA256" "TLS-ECDHE-RSA-WITH-AES-256-GCM-SHA384" "TLS-ECDHE-RSA-WITH-CHACHA20-POLY1305-SHA256")
		fi
		select_with_labels "控制通道加密算法" cc_labels cc_values "${cc_values[0]}" CC_CIPHER
		log_menu ""
	log_prompt "请选择最低TLS版本："
	log_menu "   1) TLS 1.2 (推荐，兼容所有客户端)"
	log_menu "   2) TLS 1.3 (更安全，需要 OpenVPN 2.5+ 客户端)"
	until [[ $TLS_VERSION_MIN_CHOICE =~ ^[1-2]$ ]]; do
		read -rp "最低TLS版本 [1-2]: " -e -i 1 TLS_VERSION_MIN_CHOICE
	done
		case $TLS_VERSION_MIN_CHOICE in
		1)
			TLS_VERSION_MIN="1.2"
			;;
		2)
			TLS_VERSION_MIN="1.3"
			;;
		esac
		log_menu ""
	log_prompt "请选择TLS 1.3密码套件（当协商TLS 1.3时使用）："
	log_menu "   1) 所有安全密码套件 (推荐)"
	log_menu "   2) 仅AES-256-GCM"
	log_menu "   3) 仅AES-128-GCM"
	log_menu "   4) 仅ChaCha20-Poly1305"
	until [[ $TLS13_CIPHER_CHOICE =~ ^[1-4]$ ]]; do
		read -rp "TLS 1.3密码套件 [1-4]: " -e -i 1 TLS13_CIPHER_CHOICE
	done
		case $TLS13_CIPHER_CHOICE in
		1)
			TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256"
			;;
		2)
			TLS13_CIPHERSUITES="TLS_AES_256_GCM_SHA384"
			;;
		3)
			TLS13_CIPHERSUITES="TLS_AES_128_GCM_SHA256"
			;;
		4)
			TLS13_CIPHERSUITES="TLS_CHACHA20_POLY1305_SHA256"
			;;
		esac
		log_menu ""
	log_prompt "请选择TLS密钥交换组（用于ECDH密钥交换）："
	log_menu "   1) 所有现代曲线 (推荐)"
	log_menu "   2) 仅X25519 (最安全，可能存在兼容性问题)"
	log_menu "   3) 仅NIST曲线 (prime256v1, secp384r1, secp521r1)"
	until [[ $TLS_GROUPS_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "TLS密钥交换组 [1-3]: " -e -i 1 TLS_GROUPS_CHOICE
	done
		case $TLS_GROUPS_CHOICE in
		1)
			TLS_GROUPS="X25519:prime256v1:secp384r1:secp521r1"
			;;
		2)
			TLS_GROUPS="X25519"
			;;
		3)
			TLS_GROUPS="prime256v1:secp384r1:secp521r1"
			;;
		esac
		log_menu ""
	# "auth"选项在AEAD密码算法（GCM, ChaCha20-Poly1305）中的行为不同
	if [[ $CIPHER =~ CBC$ ]]; then
		log_prompt "摘要算法用于验证数据通道数据包和控制通道的tls-auth数据包。"
	elif [[ $CIPHER =~ GCM$ ]] || [[ $CIPHER == "CHACHA20-POLY1305" ]]; then
		log_prompt "摘要算法用于验证控制通道的tls-auth数据包。"
	fi
	log_prompt "您想为HMAC使用哪种摘要算法？"
	log_menu "   1) SHA-256 (推荐)"
	log_menu "   2) SHA-384"
	log_menu "   3) SHA-512"
	until [[ $HMAC_ALG_CHOICE =~ ^[1-3]$ ]]; do
		read -rp "摘要算法 [1-3]: " -e -i 1 HMAC_ALG_CHOICE
	done
		case $HMAC_ALG_CHOICE in
		1)
			HMAC_ALG="SHA256"
			;;
		2)
			HMAC_ALG="SHA384"
			;;
		3)
			HMAC_ALG="SHA512"
			;;
		esac
		log_menu ""
	log_prompt "您可以为控制通道添加额外的安全层。"
	local tls_sig_labels=("tls-crypt-v2 (推荐): 加密控制通道，每个客户端使用唯一密钥" "tls-crypt: 加密控制通道，所有客户端共享密钥" "tls-auth: 验证控制通道，不加密")
	select_with_labels "控制通道安全" tls_sig_labels TLS_SIG_MODES "crypt-v2" TLS_SIG
	fi
	log_menu ""
	log_prompt "好的，我已经收集了所有必要的信息。现在我们准备好设置您的OpenVPN服务器了。"
	log_prompt "安装完成后，您将能够生成客户端证书。"
	APPROVE_INSTALL=${APPROVE_INSTALL:-n}
	if [[ $APPROVE_INSTALL =~ n ]]; then
		read -n1 -r -p "按任意键继续..."
	fi
}

function installOpenVPN() {
	if [[ $NON_INTERACTIVE_INSTALL == "y" ]]; then
		# 如果未设置 ENDPOINT，则解析公共 IP
		if [[ -z $ENDPOINT ]]; then
			ENDPOINT=$(resolvePublicIP)
		fi

		# 记录非交互式模式和参数
		log_info "=== OpenVPN 非交互式安装 ==="
		log_info "正在以非交互式模式运行，使用以下设置："
		log_info "  ENDPOINT=$ENDPOINT"
		log_info "  ENDPOINT_TYPE=$ENDPOINT_TYPE"
		log_info "  CLIENT_IPV4=$CLIENT_IPV4"
		log_info "  CLIENT_IPV6=$CLIENT_IPV6"
		log_info "  VPN_SUBNET_IPV4=$VPN_SUBNET_IPV4"
		log_info "  VPN_SUBNET_IPV6=$VPN_SUBNET_IPV6"
		log_info "  PORT=$PORT"
		log_info "  PROTOCOL=$PROTOCOL"
		log_info "  DNS=$DNS"
		[[ -n $MTU ]] && log_info "  MTU=$MTU"
		log_info "  MULTI_CLIENT=$MULTI_CLIENT"
		log_info "  AUTH_MODE=$AUTH_MODE"
		log_info "  CLIENT=$CLIENT"
		log_info "  CLIENT_CERT_DURATION_DAYS=$CLIENT_CERT_DURATION_DAYS"
		log_info "  SERVER_CERT_DURATION_DAYS=$SERVER_CERT_DURATION_DAYS"
	fi

	# 从默认路由获取 "公共" 接口
	NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
	if [[ -z $NIC ]] && [[ $CLIENT_IPV6 == 'y' ]]; then
		NIC=$(ip -6 route show default | sed -ne 's/^default .* dev \([^ ]*\) .*$/\1/p')
	fi

	# $NIC 不能为空，否则脚本 rm-openvpn-rules.sh 无法正常工作
	if [[ -z $NIC ]]; then
		log_warn "无法检测到公共接口。"
		log_info "这需要设置 MASQUERADE。"
		until [[ $CONTINUE =~ (y|n) ]]; do
			read -rp "继续吗？[y/n]: " -e CONTINUE
		done
		if [[ $CONTINUE == "n" ]]; then
			exit 1
		fi
	fi

	# 如果 OpenVPN 尚未安装，则安装它。此脚本在多次运行时基本是幂等的，
	# 但只会在第一次运行时从上游安装 OpenVPN。
	if [[ ! -e /etc/openvpn/server/server.conf ]]; then
		log_header "安装 OpenVPN"

		# 设置官方 OpenVPN 仓库以获取最新版本
		installOpenVPNRepo

		log_info "正在安装 OpenVPN 和依赖项..."
		# socat 用于与 OpenVPN 管理接口通信（吊销时客户端断开连接）
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd_fatal "正在安装 OpenVPN" apt-get install -y openvpn iptables openssl curl ca-certificates tar dnsutils socat
		elif [[ $OS == 'centos' ]]; then
			run_cmd_fatal "正在安装 OpenVPN" yum install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat 'policycoreutils-python*'
		elif [[ $OS == 'oracle' ]]; then
			run_cmd_fatal "正在安装 OpenVPN" yum install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat policycoreutils-python-utils
		elif [[ $OS == 'amzn2023' ]]; then
			run_cmd_fatal "正在安装 OpenVPN" dnf install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat
		elif [[ $OS == 'fedora' ]]; then
			run_cmd_fatal "正在安装 OpenVPN" dnf install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat policycoreutils-python-utils
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd_fatal "正在安装 OpenVPN" zypper install -y openvpn iptables openssl ca-certificates curl tar bind-utils socat
		elif [[ $OS == 'arch' ]]; then
			run_cmd_fatal "正在安装 OpenVPN" pacman --needed --noconfirm -Syu openvpn iptables openssl ca-certificates curl tar bind socat
		fi

		# 如果选择了 ChaCha20-Poly1305，则验证其兼容性
		if [[ $CIPHER == "CHACHA20-POLY1305" ]] || [[ $CC_CIPHER =~ CHACHA20 ]]; then
			local installed_version
			installed_version=$(openvpn --version 2>/dev/null | head -1 | awk '{print $2}')
			if ! openvpnVersionAtLeast "2.5"; then
				log_fatal "ChaCha20-Poly1305 需要 OpenVPN 2.5 或更高版本。已安装版本: $installed_version"
			fi
			log_info "OpenVPN 版本支持 ChaCha20-Poly1305"
		fi

		# 检查数据通道卸载 (DCO) 可用性
		if isDCOAvailable; then
			# 检查配置是否与 DCO 兼容（udp 或 udp6）
			if [[ $PROTOCOL =~ ^udp ]] && [[ $CIPHER =~ (GCM|CHACHA20-POLY1305) ]]; then
				log_info "数据通道卸载 (DCO) 可用，将用于提高性能"
			else
				log_info "数据通道卸载 (DCO) 可用但未启用（需要 UDP、AEAD 加密算法）"
			fi
		else
			log_info "数据通道卸载 (DCO) 不可用（需要 OpenVPN 2.6+ 和内核支持）"
		fi

		# 创建服务器目录（OpenVPN 2.4+ 目录结构）
		run_cmd_fatal "创建服务器目录" mkdir -p /etc/openvpn/server
	fi

	# 确定 OpenVPN 应该以哪个用户/组运行
	# - Fedora/RHEL/Amazon 创建 'openvpn' 用户，所属组为 'openvpn'
	# - Arch 创建 'openvpn' 用户，所属组为 'network'
	# - Debian/Ubuntu/openSUSE 不创建专用用户，使用 'nobody'
	#
	# 同时检查 systemd 服务文件是否已经处理用户/组切换。
	# 如果是，则不应在配置中添加用户/组（否则会导致双重权限下降）。
	SYSTEMD_HANDLES_USER=false
	for service_file in /usr/lib/systemd/system/openvpn-server@.service /lib/systemd/system/openvpn-server@.service; do
		if [[ -f "$service_file" ]] && grep -q "^User=" "$service_file"; then
			SYSTEMD_HANDLES_USER=true
			break
		fi
	done

	if id openvpn &>/dev/null; then
		OPENVPN_USER=openvpn
		# 获取 openvpn 用户的主要组（例如，Fedora 上为 'openvpn'，Arch 上为 'network'）
		OPENVPN_GROUP=$(id -gn openvpn 2>/dev/null || echo openvpn)
	else
		OPENVPN_USER=nobody
		if grep -qs "^nogroup:" /etc/group; then
			OPENVPN_GROUP=nogroup
		else
			OPENVPN_GROUP=nobody
		fi
	fi

	# 如果尚未安装，从源代码安装最新版本的 easy-rsa
	if [[ ! -d /etc/openvpn/server/easy-rsa/ ]]; then
		run_cmd_fatal "下载 Easy-RSA v${EASYRSA_VERSION}" curl -fL --retry 5 -o ~/easy-rsa.tgz "https://github.com/OpenVPN/easy-rsa/releases/download/v${EASYRSA_VERSION}/EasyRSA-${EASYRSA_VERSION}.tgz"
		log_info "验证 Easy-RSA 校验和..."
		CHECKSUM_OUTPUT=$(echo "${EASYRSA_SHA256}  $HOME/easy-rsa.tgz" | sha256sum -c 2>&1) || {
			_log_to_file "[CHECKSUM] $CHECKSUM_OUTPUT"
			run_cmd "清理失败的下载" rm -f ~/easy-rsa.tgz
			log_fatal "Easy-RSA 下载的 SHA256 校验和验证失败！"
		}
		_log_to_file "[CHECKSUM] $CHECKSUM_OUTPUT"
		run_cmd_fatal "创建 Easy-RSA 目录" mkdir -p /etc/openvpn/server/easy-rsa
		run_cmd_fatal "解压 Easy-RSA" tar xzf ~/easy-rsa.tgz --strip-components=1 --no-same-owner --directory /etc/openvpn/server/easy-rsa
		run_cmd "清理归档文件" rm -f ~/easy-rsa.tgz

		cd /etc/openvpn/server/easy-rsa/ || return
		case $CERT_TYPE in
		ecdsa)
			echo "set_var EASYRSA_ALGO ec" >vars
			echo "set_var EASYRSA_CURVE $CERT_CURVE" >>vars
			;;
		rsa)
			echo "set_var EASYRSA_KEY_SIZE $RSA_KEY_SIZE" >vars
			;;
		esac

		# 生成一个 16 字符的随机字母数字标识符作为 CN 和服务器名称
		# 注意：2>/dev/null 抑制 fold 命令在 head 提前退出时产生的 "Broken pipe" 错误
		SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 2>/dev/null | head -n 1)"
		echo "$SERVER_CN" >SERVER_CN_GENERATED
		SERVER_NAME="server_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 2>/dev/null | head -n 1)"
		echo "$SERVER_NAME" >SERVER_NAME_GENERATED

		# 创建 PKI，设置 CA，生成 DH 参数和服务器证书
		log_info "初始化 PKI..."
		run_cmd_fatal "初始化 PKI" ./easyrsa init-pki

		if [[ $AUTH_MODE == "pki" ]]; then
			# 带有 CA 的传统 PKI 模式
			export EASYRSA_CA_EXPIRE=$DEFAULT_CERT_VALIDITY_DURATION_DAYS
			log_info "构建 CA..."
			run_cmd_fatal "构建 CA" ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass

			export EASYRSA_CERT_EXPIRE=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
			log_info "构建服务器证书..."
			run_cmd_fatal "构建服务器证书" ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
			export EASYRSA_CRL_DAYS=$DEFAULT_CRL_VALIDITY_DURATION_DAYS
			run_cmd_fatal "生成 CRL" ./easyrsa gen-crl
		else
			# 带有自签名证书的指纹模式（OpenVPN 2.6+）
			log_info "为指纹模式构建自签名服务器证书..."
			export EASYRSA_CERT_EXPIRE=${SERVER_CERT_DURATION_DAYS:-$DEFAULT_CERT_VALIDITY_DURATION_DAYS}
			run_cmd_fatal "构建自签名服务器证书" ./easyrsa --batch self-sign-server "$SERVER_NAME" nopass

			# 提取并存储服务器指纹
			SERVER_FINGERPRINT=$(openssl x509 -in "pki/issued/$SERVER_NAME.crt" -fingerprint -sha256 -noout | cut -d'=' -f2)
			if [[ -z $SERVER_FINGERPRINT ]]; then
				log_error "无法提取服务器证书指纹"
				exit 1
			fi
			mkdir -p /etc/openvpn/server
			echo "$SERVER_FINGERPRINT" >/etc/openvpn/server/server-fingerprint
			log_info "服务器指纹: $SERVER_FINGERPRINT"
		fi

		log_info "生成 TLS 密钥..."
		case $TLS_SIG in
		crypt-v2)
			# 生成 tls-crypt-v2 服务器密钥
			run_cmd_fatal "生成 tls-crypt-v2 服务器密钥" openvpn --genkey tls-crypt-v2-server /etc/openvpn/server/tls-crypt-v2.key
			;;
		crypt)
			# 生成 tls-crypt 密钥
			run_cmd_fatal "生成 tls-crypt 密钥" openvpn --genkey secret /etc/openvpn/server/tls-crypt.key
			;;
		auth)
			# 生成 tls-auth 密钥
			run_cmd_fatal "生成 tls-auth 密钥" openvpn --genkey secret /etc/openvpn/server/tls-auth.key
			;;
		esac
		# 存储认证模式供以后使用
		echo "$AUTH_MODE" >AUTH_MODE_GENERATED
	else
		# 如果 easy-rsa 已经安装，获取生成的 SERVER_NAME 用于客户端配置
		cd /etc/openvpn/server/easy-rsa/ || return
		SERVER_NAME=$(cat SERVER_NAME_GENERATED)
		# 读取存储的认证模式
		if [[ -f AUTH_MODE_GENERATED ]]; then
			AUTH_MODE=$(cat AUTH_MODE_GENERATED)
		else
			# 对于现有安装，默认使用 pki
			AUTH_MODE="pki"
		fi
	fi

	# 移动所有生成的文件
	log_info "复制证书..."
	if [[ $AUTH_MODE == "pki" ]]; then
		run_cmd_fatal "将证书复制到 /etc/openvpn/server" cp pki/ca.crt pki/private/ca.key "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server
		# 使证书吊销列表对非 root 用户可读
		run_cmd "设置 CRL 权限" chmod 644 /etc/openvpn/server/crl.pem
	else
		# 指纹模式：仅复制服务器证书和密钥（不包括 CA 或 CRL）
	run_cmd_fatal "将证书复制到 /etc/openvpn/server" cp "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" /etc/openvpn/server
	fi

	# 生成 server.conf
	log_info "生成服务器配置..."
	echo "port $PORT" >/etc/openvpn/server/server.conf

	# 协议选择：如果端点是 IPv6，则使用 proto6 变体
	if [[ $ENDPOINT_TYPE == "6" ]]; then
		echo "proto ${PROTOCOL}6" >>/etc/openvpn/server/server.conf
	else
		echo "proto $PROTOCOL" >>/etc/openvpn/server/server.conf
	fi

	if [[ $MULTI_CLIENT == "y" ]]; then
		echo "duplicate-cn" >>/etc/openvpn/server/server.conf
	fi

	echo "dev tun" >>/etc/openvpn/server/server.conf
	# 仅当 systemd 不处理用户/组时才添加（避免双重权限下降）
	if [[ $SYSTEMD_HANDLES_USER == "false" ]]; then
		echo "user $OPENVPN_USER
group $OPENVPN_GROUP" >>/etc/openvpn/server/server.conf
	fi
	echo "persist-key
persist-tun
keepalive 10 120
topology subnet" >>/etc/openvpn/server/server.conf

	# IPv4 服务器指令 - 始终为客户端分配 IPv4 以确保正确路由
	# 即使在仅 IPv6 模式下，我们也需要 IPv4 地址，以便 redirect-gateway def1 可以阻止 IPv4 泄漏
	echo "server $VPN_SUBNET_IPV4 255.255.255.0" >>/etc/openvpn/server/server.conf

	# IPv6 服务器指令（仅当客户端获得 IPv6 时）
	if [[ $CLIENT_IPV6 == "y" ]]; then
		{
			echo "server-ipv6 ${VPN_SUBNET_IPV6}/112"
			echo "tun-ipv6"
			echo "push tun-ipv6"
		} >>/etc/openvpn/server/server.conf
	fi

	# ifconfig-pool-persist 与 duplicate-cn 不兼容
	if [[ $MULTI_CLIENT != "y" ]]; then
		echo "ifconfig-pool-persist ipp.txt" >>/etc/openvpn/server/server.conf
	fi

	# DNS 解析器
	case $DNS in
	system)
		# 定位正确的 resolv.conf
		# 对于运行 systemd-resolved 的系统是必需的
		if grep -q "127.0.0.53" "/etc/resolv.conf"; then
			RESOLVCONF='/run/systemd/resolve/resolv.conf'
		else
			RESOLVCONF='/etc/resolv.conf'
		fi
		# 从 resolv.conf 获取解析器并用于 OpenVPN
		sed -ne 's/^nameserver[[:space:]]\+\([^[:space:]]\+\).*$/\1/p' $RESOLVCONF | while read -r line; do
			# 如果客户端有 IPv4，则复制 IPv4 解析器；如果客户端有 IPv6，则复制 IPv6 解析器
			if [[ $line =~ ^[0-9.]*$ ]] && [[ $CLIENT_IPV4 == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server/server.conf
			elif [[ $line =~ : ]] && [[ $CLIENT_IPV6 == 'y' ]]; then
				echo "push \"dhcp-option DNS $line\"" >>/etc/openvpn/server/server.conf
			fi
		done
		;;
	unbound)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "push \"dhcp-option DNS $VPN_GATEWAY_IPV4\"" >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "push \"dhcp-option DNS $VPN_GATEWAY_IPV6\"" >>/etc/openvpn/server/server.conf
		fi
		;;
	cloudflare)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 1.0.0.1"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 1.1.1.1"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2606:4700:4700::1001"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2606:4700:4700::1111"' >>/etc/openvpn/server/server.conf
		fi
		;;
	quad9)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 9.9.9.9"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.112"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2620:fe::fe"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2620:fe::9"' >>/etc/openvpn/server/server.conf
		fi
		;;
	aliyun)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 223.5.5.5"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 223.6.6.6"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2400:3200::1"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2400:3200:baba::1"' >>/etc/openvpn/server/server.conf
		fi
		;;
	quad9-uncensored)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 9.9.9.10"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 149.112.112.10"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2620:fe::10"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2620:fe::fe:10"' >>/etc/openvpn/server/server.conf
		fi
		;;
	fdn)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 80.67.169.40"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 80.67.169.12"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2001:910:800::40"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2001:910:800::12"' >>/etc/openvpn/server/server.conf
		fi
		;;
	dnswatch)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 84.200.69.80"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 84.200.70.40"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2001:1608:10:25::1c04:b12f"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2001:1608:10:25::9249:d69b"' >>/etc/openvpn/server/server.conf
		fi
		;;
	opendns)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 208.67.222.222"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 208.67.220.220"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2620:119:35::35"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2620:119:53::53"' >>/etc/openvpn/server/server.conf
		fi
		;;
	google)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 8.8.8.8"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 8.8.4.4"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2001:4860:4860::8888"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2001:4860:4860::8844"' >>/etc/openvpn/server/server.conf
		fi
		;;
	yandex)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 77.88.8.8"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 77.88.8.1"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2a02:6b8::feed:0ff"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2a02:6b8:0:1::feed:0ff"' >>/etc/openvpn/server/server.conf
		fi
		;;
	adguard)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 94.140.14.14"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 94.140.15.15"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2a10:50c0::ad1:ff"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2a10:50c0::ad2:ff"' >>/etc/openvpn/server/server.conf
		fi
		;;
	nextdns)
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo 'push "dhcp-option DNS 45.90.28.167"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 45.90.30.167"' >>/etc/openvpn/server/server.conf
		fi
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo 'push "dhcp-option DNS 2a07:a8c0::"' >>/etc/openvpn/server/server.conf
			echo 'push "dhcp-option DNS 2a07:a8c1::"' >>/etc/openvpn/server/server.conf
		fi
		;;
	custom)
		echo "push \"dhcp-option DNS $DNS1\"" >>/etc/openvpn/server/server.conf
		if [[ $DNS2 != "" ]]; then
			echo "push \"dhcp-option DNS $DNS2\"" >>/etc/openvpn/server/server.conf
		fi
		;;
	esac

	# 重定向网关设置 - 始终重定向 IPv4 和 IPv6 以防止泄漏
	# 对于 IPv4：redirect-gateway def1 将所有 IPv4 路由通过 VPN（如果未配置 IPv4 则丢弃）
	# 对于 IPv6：route-ipv6 + redirect-gateway ipv6 将所有 IPv6 路由通过 VPN，或 block-ipv6 丢弃它
	echo 'push "redirect-gateway def1 bypass-dhcp"' >>/etc/openvpn/server/server.conf
	if [[ $CLIENT_IPV6 == "y" ]]; then
		echo 'push "route-ipv6 2000::/3"' >>/etc/openvpn/server/server.conf
		echo 'push "redirect-gateway ipv6"' >>/etc/openvpn/server/server.conf
	else
		# 阻止客户端上的 IPv6，防止 VPN 仅处理 IPv4 时出现 IPv6 泄漏
		echo 'push "block-ipv6"' >>/etc/openvpn/server/server.conf
	fi

	if [[ -n $MTU ]]; then
		echo "tun-mtu $MTU" >>/etc/openvpn/server/server.conf
	fi

	# 使用 ECDH 密钥交换（dh none）和 tls-groups 进行曲线协商
	echo "dh none" >>/etc/openvpn/server/server.conf
	echo "tls-groups $TLS_GROUPS" >>/etc/openvpn/server/server.conf

	case $TLS_SIG in
	crypt-v2)
		echo "tls-crypt-v2 tls-crypt-v2.key" >>/etc/openvpn/server/server.conf
		;;
	crypt)
		echo "tls-crypt tls-crypt.key" >>/etc/openvpn/server/server.conf
		;;
	auth)
		echo "tls-auth tls-auth.key 0" >>/etc/openvpn/server/server.conf
		;;
	esac

	# 通用服务器配置选项
	# PKI 模式添加 crl-verify、ca 和 remote-cert-tls
	# 指纹模式：首次创建客户端时添加 <peer-fingerprint> 块
	{
		[[ $AUTH_MODE == "pki" ]] && echo "crl-verify crl.pem
ca ca.crt"
		echo "cert $SERVER_NAME.crt
key $SERVER_NAME.key
auth $HMAC_ALG
cipher $CIPHER
ignore-unknown-option data-ciphers
data-ciphers $CIPHER
ncp-ciphers $CIPHER
tls-server
tls-version-min $TLS_VERSION_MIN"
		[[ $AUTH_MODE == "pki" ]] && echo "remote-cert-tls client"
		echo "tls-cipher $CC_CIPHER
tls-ciphersuites $TLS13_CIPHERSUITES
client-config-dir ccd
status /var/log/openvpn/status.log
management /var/run/openvpn/server.sock unix
verb 3"
	} >>/etc/openvpn/server/server.conf

	# 创建管理套接字目录
	run_cmd_fatal "创建管理套接字目录" mkdir -p /var/run/openvpn

	# 创建客户端配置目录
	run_cmd_fatal "创建客户端配置目录" mkdir -p /etc/openvpn/server/ccd
	# 创建日志目录
	run_cmd_fatal "创建日志目录" mkdir -p /var/log/openvpn

	# 在使用专用 OpenVPN 用户（不是 "nobody"）的发行版上，例如 Fedora、RHEL、Arch，
	# 设置所有权，使 OpenVPN 可以读取配置/证书并写入日志目录
	if [[ $OPENVPN_USER != "nobody" ]]; then
		log_info "为 OpenVPN 用户设置所有权..."
		chown -R "$OPENVPN_USER:$OPENVPN_GROUP" /etc/openvpn/server
		chown "$OPENVPN_USER:$OPENVPN_GROUP" /var/log/openvpn
	fi

	# 启用路由
	log_info "启用 IP 转发..."
	run_cmd_fatal "创建 sysctl.d 目录" mkdir -p /etc/sysctl.d

	# 如果客户端获得 IPv4，则启用 IPv4 转发
	if [[ $CLIENT_IPV4 == 'y' ]]; then
		echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/99-openvpn.conf
	else
		echo '# IPv4 转发不需要（没有 IPv4 客户端）' >/etc/sysctl.d/99-openvpn.conf
	fi
	# 如果客户端获得 IPv6，则启用 IPv6 转发
	if [[ $CLIENT_IPV6 == 'y' ]]; then
		echo 'net.ipv6.conf.all.forwarding=1' >>/etc/sysctl.d/99-openvpn.conf
	fi
	# 应用 sysctl 规则
	run_cmd "应用 sysctl 规则" sysctl --system

	# 如果 SELinux 已启用并选择了自定义端口，我们需要这个
	if hash sestatus 2>/dev/null; then
		if sestatus | grep "Current mode" | grep -qs "enforcing"; then
			if [[ $PORT != '1194' ]]; then
				# 从协议中去除 "6" 后缀（semanage 期望 "udp" 或 "tcp"，而不是 "udp6"/"tcp6"）
				SELINUX_PROTOCOL="${PROTOCOL%6}"
				run_cmd "配置 SELinux 端口" semanage port -a -t openvpn_port_t -p "$SELINUX_PROTOCOL" "$PORT"
			fi
		fi
	fi

	# 最后，重启并启用 OpenVPN
	# OpenVPN 2.4+ 使用 openvpn-server@.service，配置位于 /etc/openvpn/server/
	log_info "配置 OpenVPN 服务..."

	# 查找服务文件（位置和名称因发行版而异）
	# 现代发行版：openvpn-server@.service 位于 /usr/lib/systemd/system/ 或 /lib/systemd/system/
	# openSUSE：openvpn@.service（旧样式），我们需要适配
	if [[ -f /usr/lib/systemd/system/openvpn-server@.service ]]; then
		SERVICE_SOURCE="/usr/lib/systemd/system/openvpn-server@.service"
	elif [[ -f /lib/systemd/system/openvpn-server@.service ]]; then
		SERVICE_SOURCE="/lib/systemd/system/openvpn-server@.service"
	elif [[ -f /usr/lib/systemd/system/openvpn@.service ]]; then
		# openSUSE 使用旧样式服务，我们将创建自己的 openvpn-server@.service
		SERVICE_SOURCE="/usr/lib/systemd/system/openvpn@.service"
	elif [[ -f /lib/systemd/system/openvpn@.service ]]; then
		SERVICE_SOURCE="/lib/systemd/system/openvpn@.service"
	else
		log_fatal "无法找到 openvpn-server@.service 或 openvpn@.service 文件"
	fi

	# 不要修改包提供的服务，复制到 /etc/systemd/system/
	run_cmd_fatal "复制 OpenVPN 服务文件" cp "$SERVICE_SOURCE" /etc/systemd/system/openvpn-server@.service

	# 修复 OpenVZ 上的 OpenVPN 服务的变通方法
	run_cmd "修补服务文件 (LimitNPROC)" sed -i 's|LimitNPROC|#LimitNPROC|' /etc/systemd/system/openvpn-server@.service

	# 确保服务使用 /etc/openvpn/server/ 作为工作目录
	# 这对于默认使用旧样式路径的 openSUSE 是必需的
	if grep -q "cd /etc/openvpn/" /etc/systemd/system/openvpn-server@.service; then
		run_cmd "修补服务文件 (路径)" sed -i 's|/etc/openvpn/|/etc/openvpn/server/|g' /etc/systemd/system/openvpn-server@.service
	fi

	run_cmd "重新加载 systemd" systemctl daemon-reload
	run_cmd "启用 OpenVPN 服务" systemctl enable openvpn-server@server
	# 在指纹模式下，延迟服务启动直到第一个客户端创建
	# （OpenVPN 需要至少一个指纹或 CA 才能启动）
	if [[ $AUTH_MODE == "pki" ]]; then
		run_cmd "启动 OpenVPN 服务" systemctl restart openvpn-server@server
	fi

	if [[ $DNS == "unbound" ]]; then
		installUnbound
	fi

	# 配置防火墙规则
	# 对 VPN 流量使用基于源的规则（无论 OpenVPN 使用哪个 tun 接口都能可靠工作）
	log_info "配置防火墙规则..."

	if systemctl is-active --quiet firewalld; then
		# 对激活了 firewalld 的系统使用 firewalld 原生命令
	log_info "检测到 firewalld，使用 firewall-cmd..."
	run_cmd "将 OpenVPN 端口添加到 firewalld" firewall-cmd --permanent --add-port="$PORT/$PROTOCOL"
	run_cmd "将 masquerade 添加到 firewalld" firewall-cmd --permanent --add-masquerade

	# 为 VPN 流量添加丰富规则（仅基于源，因为 firewalld 在使用 nftables 后端时
	# 不能可靠地支持带有直接规则的接口模式）
	if [[ $CLIENT_IPV4 == 'y' ]]; then
		run_cmd "添加 IPv4 VPN 子网规则" firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" source address=\"$VPN_SUBNET_IPV4/24\" accept"
	fi

	if [[ $CLIENT_IPV6 == 'y' ]]; then
		run_cmd "添加 IPv6 VPN 子网规则" firewall-cmd --permanent --add-rich-rule="rule family=\"ipv6\" source address=\"${VPN_SUBNET_IPV6}/112\" accept"
	fi

	run_cmd "重新加载 firewalld" firewall-cmd --reload
	elif systemctl is-active --quiet nftables; then
		# 对激活了 nftables 的系统使用 nftables 原生规则
		log_info "检测到 nftables，配置 nftables 规则..."
		run_cmd_fatal "创建 nftables 目录" mkdir -p /etc/nftables

		# 创建 nftables 规则文件
		{
			echo "table inet openvpn {"
			echo "	chain input {"
			echo "		type filter hook input priority 0; policy accept;"
			if [[ $CLIENT_IPV4 == 'y' ]]; then
				echo "		iifname \"tun*\" ip saddr $VPN_SUBNET_IPV4/24 accept"
			fi
			if [[ $CLIENT_IPV6 == 'y' ]]; then
				echo "		iifname \"tun*\" ip6 saddr ${VPN_SUBNET_IPV6}/112 accept"
			fi
			echo "		iifname \"$NIC\" $PROTOCOL dport $PORT accept"
			echo "	}"
			echo ""
			echo "	chain forward {"
			echo "		type filter hook forward priority 0; policy accept;"
			if [[ $CLIENT_IPV4 == 'y' ]]; then
				echo "		iifname \"tun*\" ip saddr $VPN_SUBNET_IPV4/24 accept"
				echo "		oifname \"tun*\" ip daddr $VPN_SUBNET_IPV4/24 accept"
			fi
			if [[ $CLIENT_IPV6 == 'y' ]]; then
				echo "		iifname \"tun*\" ip6 saddr ${VPN_SUBNET_IPV6}/112 accept"
				echo "		oifname \"tun*\" ip6 daddr ${VPN_SUBNET_IPV6}/112 accept"
			fi
			echo "	}"
			echo "}"
		} >/etc/nftables/openvpn.nft

		# IPv4 NAT 规则（仅当客户端获得 IPv4 时）
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "
table ip openvpn-nat {
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip saddr $VPN_SUBNET_IPV4/24 oifname \"$NIC\" masquerade
	}
}" >>/etc/nftables/openvpn.nft
		fi

		# IPv6 NAT 规则（仅当客户端获得 IPv6 时）
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "
table ip6 openvpn-nat {
	chain postrouting {
		type nat hook postrouting priority 100; policy accept;
		ip6 saddr ${VPN_SUBNET_IPV6}/112 oifname \"$NIC\" masquerade
	}
}" >>/etc/nftables/openvpn.nft
		fi

		# 如果尚未存在，将包含添加到 nftables.conf
		if ! grep -q 'include.*/etc/nftables/openvpn.nft' /etc/nftables.conf; then
			run_cmd "将包含添加到 nftables.conf" sh -c 'echo "include \"/etc/nftables/openvpn.nft\"" >> /etc/nftables.conf'
		fi

		# 重新加载 nftables 以应用规则
		run_cmd "重新加载 nftables" systemctl reload nftables
	else
		# 对没有 firewalld 或 nftables 的系统使用 iptables
		run_cmd_fatal "创建 iptables 目录" mkdir -p /etc/iptables

		# 添加规则的脚本
		echo "#!/bin/sh" >/etc/iptables/add-openvpn-rules.sh

		# IPv4 规则（仅当客户端获得 IPv4 时）
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "iptables -t nat -I POSTROUTING 1 -s $VPN_SUBNET_IPV4/24 -o $NIC -j MASQUERADE
iptables -I INPUT 1 -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -I FORWARD 1 -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -I FORWARD 1 -o tun+ -d $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
		fi

		# IPv6 规则（仅当客户端获得 IPv6 时）
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "ip6tables -t nat -I POSTROUTING 1 -s ${VPN_SUBNET_IPV6}/112 -o $NIC -j MASQUERADE
ip6tables -I INPUT 1 -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -I FORWARD 1 -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -I FORWARD 1 -o tun+ -d ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -I INPUT 1 -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/add-openvpn-rules.sh
		fi

		# 移除规则的脚本
		echo "#!/bin/sh" >/etc/iptables/rm-openvpn-rules.sh

		# IPv4 移除规则
		if [[ $CLIENT_IPV4 == 'y' ]]; then
			echo "iptables -t nat -D POSTROUTING -s $VPN_SUBNET_IPV4/24 -o $NIC -j MASQUERADE
iptables -D INPUT -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -D FORWARD -i tun+ -s $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -D FORWARD -o tun+ -d $VPN_SUBNET_IPV4/24 -j ACCEPT
iptables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
		fi

		# IPv6 移除规则
		if [[ $CLIENT_IPV6 == 'y' ]]; then
			echo "ip6tables -t nat -D POSTROUTING -s ${VPN_SUBNET_IPV6}/112 -o $NIC -j MASQUERADE
ip6tables -D INPUT -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -D FORWARD -i tun+ -s ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -D FORWARD -o tun+ -d ${VPN_SUBNET_IPV6}/112 -j ACCEPT
ip6tables -D INPUT -i $NIC -p $PROTOCOL --dport $PORT -j ACCEPT" >>/etc/iptables/rm-openvpn-rules.sh
		fi

		run_cmd "使 add-openvpn-rules.sh 可执行" chmod +x /etc/iptables/add-openvpn-rules.sh
		run_cmd "使 rm-openvpn-rules.sh 可执行" chmod +x /etc/iptables/rm-openvpn-rules.sh

		# 通过 systemd 脚本处理规则
		echo "[Unit]
Description=iptables rules for OpenVPN
After=firewalld.service
Before=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/etc/iptables/add-openvpn-rules.sh
ExecStop=/etc/iptables/rm-openvpn-rules.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target" >/etc/systemd/system/iptables-openvpn.service

		# 启用服务并应用规则
		run_cmd "重新加载 systemd" systemctl daemon-reload
		run_cmd "启用 iptables 服务" systemctl enable iptables-openvpn
		run_cmd "启动 iptables 服务" systemctl start iptables-openvpn
	fi

	# 如果服务器在 NAT 后面，使用正确的 IP 地址让客户端连接
	if [[ $ENDPOINT != "" ]]; then
		IP=$ENDPOINT
	fi

	# 创建 client-template.txt，以便以后添加更多用户时使用该模板
	log_info "创建客户端模板..."
	echo "client" >/etc/openvpn/server/client-template.txt
	if [[ $PROTOCOL == 'udp' ]]; then
		echo "proto udp" >>/etc/openvpn/server/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/server/client-template.txt
	elif [[ $PROTOCOL == 'udp6' ]]; then
		echo "proto udp6" >>/etc/openvpn/server/client-template.txt
		echo "explicit-exit-notify" >>/etc/openvpn/server/client-template.txt
	elif [[ $PROTOCOL == 'tcp' ]]; then
		echo "proto tcp-client" >>/etc/openvpn/server/client-template.txt
	elif [[ $PROTOCOL == 'tcp6' ]]; then
		echo "proto tcp6-client" >>/etc/openvpn/server/client-template.txt
	fi
	# 通用客户端模板选项
	# PKI 模式添加 remote-cert-tls 和 verify-x509-name
	# 指纹模式在生成客户端配置时添加 peer-fingerprint
	{
		echo "remote $IP $PORT
dev tun
resolv-retry infinite
nobind
persist-key
persist-tun"
		[[ $AUTH_MODE == "pki" ]] && echo "remote-cert-tls server
verify-x509-name $SERVER_NAME name"
		echo "auth $HMAC_ALG
auth-nocache
cipher $CIPHER
ignore-unknown-option data-ciphers
data-ciphers $CIPHER
ncp-ciphers $CIPHER
tls-client
tls-version-min $TLS_VERSION_MIN
tls-cipher $CC_CIPHER
tls-ciphersuites $TLS13_CIPHERSUITES
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns # Prevent Windows 10 DNS leak
verb 3"
	} >>/etc/openvpn/server/client-template.txt

	if [[ -n $MTU ]]; then
		echo "tun-mtu $MTU" >>/etc/openvpn/server/client-template.txt
	fi

	# 生成自定义 client.ovpn
	if [[ $NEW_CLIENT == "n" ]]; then
		if [[ $AUTH_MODE == "fingerprint" ]]; then
			log_info "未添加客户端。在添加至少一个客户端之前，OpenVPN 将不会启动。"
		else
			log_info "未添加客户端。要添加客户端，只需再次运行此脚本。"
		fi
	else
		log_info "生成第一个客户端证书..."
		newClient
		# 在指纹模式下，现在我们至少有一个指纹了，可以启动服务
		if [[ $AUTH_MODE == "fingerprint" ]]; then
			run_cmd "启动 OpenVPN 服务" systemctl restart openvpn-server@server
		fi
		log_success "如果您想添加更多客户端，只需再次运行此脚本即可！"
	fi
}

# 辅助函数：获取用于存储客户端配置的主目录
function getHomeDir() {
	local client="$1"
	if [ -d "/home/${client}" ]; then
		echo "/home/${client}"
	elif [ "${SUDO_USER}" ]; then
		if [ "${SUDO_USER}" == "root" ]; then
			echo "/root"
		else
			echo "/home/${SUDO_USER}"
		fi
	else
		echo "/root"
	fi
}

# 辅助函数：获取客户端配置文件的所有者（如果客户端匹配系统用户）
function getClientOwner() {
	local client="$1"
	# 检查客户端名称是否对应具有主目录的现有系统用户
	if id "$client" &>/dev/null && [ -d "/home/${client}" ]; then
		echo "${client}"
	elif [ "${SUDO_USER}" ] && [ "${SUDO_USER}" != "root" ]; then
		echo "${SUDO_USER}"
	fi
}

# 辅助函数：设置客户端配置文件的正确所有者和权限
function setClientConfigPermissions() {
	local filepath="$1"
	local owner="$2"

	if [[ -n "$owner" ]]; then
		local owner_group
		owner_group=$(id -gn "$owner")
		chmod go-rw "$filepath"
		chown "$owner:$owner_group" "$filepath"
	fi
}

# 辅助函数：写入带有正确路径和权限的客户端配置文件
# 用法：writeClientConfig <client_name>
# 如果设置了 CLIENT_FILEPATH 环境变量则使用该变量，否则默认为主目录
# 副作用：设置 GENERATED_CONFIG_PATH 全局变量，包含最终路径
function writeClientConfig() {
	local client="$1"
	local clientFilePath

	# 确定输出文件路径
	if [[ -n "$CLIENT_FILEPATH" ]]; then
		clientFilePath="$CLIENT_FILEPATH"
		# 确保自定义路径的父目录存在
		local parentDir
		parentDir=$(dirname "$clientFilePath")
		if [[ ! -d "$parentDir" ]]; then
			run_cmd_fatal "Creating directory $parentDir" mkdir -p "$parentDir"
		fi
	else
		local homeDir
		homeDir=$(getHomeDir "$client")
		clientFilePath="$homeDir/$client.ovpn"
	fi

	# 生成 .ovpn 配置文件
	generateClientConfig "$client" "$clientFilePath"

	# 如果客户端匹配系统用户，则设置正确的所有者和权限
	local clientOwner
	clientOwner=$(getClientOwner "$client")
	setClientConfigPermissions "$clientFilePath" "$clientOwner"

	# 导出路径供调用者使用
	GENERATED_CONFIG_PATH="$clientFilePath"
}

# 辅助函数：在证书变更后重新生成 CRL
function regenerateCRL() {
	export EASYRSA_CRL_DAYS=$DEFAULT_CRL_VALIDITY_DURATION_DAYS
	run_cmd_fatal "重新生成 CRL" ./easyrsa gen-crl
	run_cmd "移除旧的 CRL" rm -f /etc/openvpn/server/crl.pem
	run_cmd_fatal "复制新的 CRL" cp /etc/openvpn/server/easy-rsa/pki/crl.pem /etc/openvpn/server/crl.pem
	run_cmd "设置 CRL 权限" chmod 644 /etc/openvpn/server/crl.pem
}

# 辅助函数：生成 .ovpn 客户端配置文件
# 用法：generateClientConfig <client_name> <filepath>
function generateClientConfig() {
	local client="$1"
	local filepath="$2"

	# 读取认证模式
	local auth_mode="pki"
	if [[ -f /etc/openvpn/server/easy-rsa/AUTH_MODE_GENERATED ]]; then
		auth_mode=$(cat /etc/openvpn/server/easy-rsa/AUTH_MODE_GENERATED)
	fi

	# 确定使用 tls-crypt-v2、tls-crypt 还是 tls-auth
	local tls_sig=""
	if grep -qs "^tls-crypt-v2" /etc/openvpn/server/server.conf; then
		tls_sig="1"
	elif grep -qs "^tls-crypt" /etc/openvpn/server/server.conf; then
		tls_sig="2"
	elif grep -qs "^tls-auth" /etc/openvpn/server/server.conf; then
		tls_sig="3"
	fi

	# 生成自定义 client.ovpn
	run_cmd "Creating client config" cp /etc/openvpn/server/client-template.txt "$filepath"
	{
		if [[ $auth_mode == "pki" ]]; then
			# PKI 模式：包含 CA 证书
			echo "<ca>"
			cat "/etc/openvpn/server/easy-rsa/pki/ca.crt"
			echo "</ca>"
		else
			# 指纹模式：使用服务器指纹代替 CA
			local server_fingerprint
			if [[ ! -f /etc/openvpn/server/server-fingerprint ]]; then
			log_error "服务器指纹文件未找到"
			exit 1
		fi
		server_fingerprint=$(cat /etc/openvpn/server/server-fingerprint)
		if [[ -z $server_fingerprint ]]; then
			log_error "服务器指纹为空"
			exit 1
		fi
		echo "peer-fingerprint $server_fingerprint"
		fi

		echo "<cert>"
		awk '/BEGIN/,/END CERTIFICATE/' "/etc/openvpn/server/easy-rsa/pki/issued/$client.crt"
		echo "</cert>"

		echo "<key>"
		cat "/etc/openvpn/server/easy-rsa/pki/private/$client.key"
		echo "</key>"

		case $tls_sig in
		1)
			# Generate per-client tls-crypt-v2 key in /etc/openvpn/server/
			# Using /tmp would fail on Ubuntu 25.04+ due to AppArmor restrictions
			tls_crypt_v2_tmpfile=$(mktemp /etc/openvpn/server/tls-crypt-v2-client.XXXXXX)
			if [[ -z "$tls_crypt_v2_tmpfile" ]] || [[ ! -f "$tls_crypt_v2_tmpfile" ]]; then
				log_error "无法创建 tls-crypt-v2 客户端密钥的临时文件"
				exit 1
			fi
			if ! openvpn --tls-crypt-v2 /etc/openvpn/server/tls-crypt-v2.key \
				--genkey tls-crypt-v2-client "$tls_crypt_v2_tmpfile"; then
				rm -f "$tls_crypt_v2_tmpfile"
				log_error "无法生成 tls-crypt-v2 客户端密钥"
				exit 1
			fi
			echo "<tls-crypt-v2>"
			cat "$tls_crypt_v2_tmpfile"
			echo "</tls-crypt-v2>"
			rm -f "$tls_crypt_v2_tmpfile"
			;;
		2)
			echo "<tls-crypt>"
			cat /etc/openvpn/server/tls-crypt.key
			echo "</tls-crypt>"
			;;
		3)
			echo "key-direction 1"
			echo "<tls-auth>"
			cat /etc/openvpn/server/tls-auth.key
			echo "</tls-auth>"
			;;
		esac
	} >>"$filepath"
}

# 辅助函数：列出有效客户端并选择一个
# 参数：show_expiry（可选，"true" 显示过期信息）
# 设置全局变量：
#   CLIENT - 所选客户端名称
#   CLIENTNUMBER - 所选客户端编号（基于1的索引）
#   NUMBEROFCLIENTS - 有效客户端总数
function selectClient() {
	local show_expiry="${1:-false}"
	local client_number

	NUMBEROFCLIENTS=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -c "^V")
	if [[ $NUMBEROFCLIENTS == '0' ]]; then
		log_fatal "您没有现有客户端！"
	fi

	# 如果 CLIENT 已设置，验证它是否是有效的客户端
	if [[ -n $CLIENT ]]; then
		if tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | grep -qx "$CLIENT"; then
			return
		else
			log_fatal "客户端 '$CLIENT' 未找到或无效"
		fi
	fi

	if [[ $show_expiry == "true" ]]; then
		local i=1
		while read -r client; do
			local client_cert="/etc/openvpn/server/easy-rsa/pki/issued/$client.crt"
			local days
			days=$(getDaysUntilExpiry "$client_cert")
			local expiry
			expiry=$(formatExpiry "$days")
			echo "     $i) $client $expiry"
			((i++))
		done < <(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2)
	else
		tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | nl -s ') '
	fi

	until [[ ${CLIENTNUMBER:-$client_number} -ge 1 && ${CLIENTNUMBER:-$client_number} -le $NUMBEROFCLIENTS ]]; do
		if [[ $NUMBEROFCLIENTS == '1' ]]; then
			read -rp "选择一个客户端 [1]: " client_number
		else
			read -rp "选择一个客户端 [1-$NUMBEROFCLIENTS]: " client_number
		fi
	done
	CLIENTNUMBER="${CLIENTNUMBER:-$client_number}"
	CLIENT=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep "^V" | cut -d '=' -f 2 | sed -n "$CLIENTNUMBER"p)
}

# 转义字符串用于 JSON 输出
function json_escape() {
	local str="$1"
	# 先转义反斜杠，然后是引号，最后是控制字符
	str="${str//\\/\\\\}"
	str="${str//\"/\\\"}"
	str="${str//$'\n'/\\n}"
	str="${str//$'\r'/\\r}"
	str="${str//$'\t'/\\t}"
	printf '%s' "$str"
}

function listClients() {
	local index_file="/etc/openvpn/server/easy-rsa/pki/index.txt"
	local cert_dir="/etc/openvpn/server/easy-rsa/pki/issued"
	local number_of_clients
	local format="${OUTPUT_FORMAT:-table}"

	# 排除服务器证书（CN 以 server_ 开头）
	number_of_clients=$(tail -n +2 "$index_file" | grep "^[VR]" | grep -cv "/CN=server_")

	if [[ $number_of_clients == '0' ]]; then
		if [[ $format == "json" ]]; then
			echo '{"clients":[]}'
		else
			log_warn "您没有现有客户端证书！"
		fi
		return
	fi

	# 收集客户端数据
	local clients_data=()
	while read -r line; do
		local status="${line:0:1}"
		local client_name
		client_name=$(echo "$line" | sed 's/.*\/CN=//')

		local status_text
		if [[ "$status" == "V" ]]; then
			status_text="valid"
		elif [[ "$status" == "R" ]]; then
			status_text="revoked"
		else
			status_text="unknown"
		fi

		local cert_file="$cert_dir/$client_name.crt"
		local expiry_date="unknown"
		local days_remaining="null"

		if [[ -f "$cert_file" ]]; then
			local enddate
			enddate=$(openssl x509 -enddate -noout -in "$cert_file" 2>/dev/null | cut -d= -f2)

			if [[ -n "$enddate" ]]; then
				local expiry_epoch
				expiry_epoch=$(date -d "$enddate" +%s 2>/dev/null || date -j -f "%b %d %H:%M:%S %Y %Z" "$enddate" +%s 2>/dev/null)

				if [[ -n "$expiry_epoch" ]]; then
					expiry_date=$(date -d "@$expiry_epoch" +%Y-%m-%d 2>/dev/null || date -r "$expiry_epoch" +%Y-%m-%d 2>/dev/null)
					local now_epoch
					now_epoch=$(date +%s)
					days_remaining=$(((expiry_epoch - now_epoch) / 86400))
				fi
			fi
		fi

		clients_data+=("$client_name|$status_text|$expiry_date|$days_remaining")
	done < <(tail -n +2 "$index_file" | grep "^[VR]" | grep -v "/CN=server_" | sort -t$'\t' -k2)

	if [[ $format == "json" ]]; then
		# 输出 JSON
		echo '{"clients":['
		local first=true
		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name status expiry days <<<"$client_entry"
			[[ $first == true ]] && first=false || printf ','
			# 处理 days_remaining 的 null 值（JSON null 不需要引号）
			local days_json
			if [[ "$days" == "null" || -z "$days" ]]; then
				days_json="null"
			else
				days_json="$days"
			fi
			printf '{"name":"%s","status":"%s","expiry":"%s","days_remaining":%s}\n' \
				"$(json_escape "$name")" "$(json_escape "$status")" "$(json_escape "$expiry")" "$days_json"
		done
		echo ']}'
	else
		# 输出表格
		log_header "客户端证书"
		log_info "找到 $number_of_clients 个客户端证书"
		log_menu ""
		printf "   %-25s %-10s %-12s %s\n" "Name" "Status" "Expiry" "Remaining"
		printf "   %-25s %-10s %-12s %s\n" "----" "------" "------" "---------"

		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name status expiry days <<<"$client_entry"
			local relative
			if [[ $days == "null" ]]; then
				relative="unknown"
			elif [[ $days -lt 0 ]]; then
				relative="$((-days)) days ago"
			elif [[ $days -eq 0 ]]; then
				relative="today"
			elif [[ $days -eq 1 ]]; then
				relative="1 day"
			else
				relative="$days days"
			fi
			# 为表格显示将状态首字母大写
			local status_display="${status^}"
			printf "   %-25s %-10s %-12s %s\n" "$name" "$status_display" "$expiry" "$relative"
		done
		log_menu ""
	fi
}

function formatBytes() {
	local bytes=$1
	# 验证输入是数字
	if ! [[ "$bytes" =~ ^[0-9]+$ ]]; then
		echo "N/A"
		return
	fi
	if [[ $bytes -ge 1073741824 ]]; then
		awk "BEGIN {printf \"%.1fG\", $bytes/1073741824}"
	elif [[ $bytes -ge 1048576 ]]; then
		awk "BEGIN {printf \"%.1fM\", $bytes/1048576}"
	elif [[ $bytes -ge 1024 ]]; then
		awk "BEGIN {printf \"%.1fK\", $bytes/1024}"
	else
		echo "${bytes}B"
	fi
}

function listConnectedClients() {
	local status_file="/var/log/openvpn/status.log"
	local format="${OUTPUT_FORMAT:-table}"

	if [[ ! -f "$status_file" ]]; then
		if [[ $format == "json" ]]; then
			echo '{"error":"Status file not found","clients":[]}'
		else
			log_warn "状态文件未找到: $status_file"
			log_info "请确保 OpenVPN 正在运行。"
		fi
		return
	fi

	local client_count
	client_count=$(grep -c "^CLIENT_LIST" "$status_file" 2>/dev/null) || client_count=0

	if [[ "$client_count" -eq 0 ]]; then
		if [[ $format == "json" ]]; then
			echo '{"clients":[]}'
		else
			log_header "已连接客户端"
			log_info "当前没有客户端连接。"
			log_info "注意：数据每 60 秒刷新一次。"
		fi
		return
	fi

	# 收集客户端数据
	local clients_data=()
	while IFS=',' read -r _ name real_addr vpn_ip _ bytes_recv bytes_sent connected_since _; do
		clients_data+=("$name|$real_addr|$vpn_ip|$bytes_recv|$bytes_sent|$connected_since")
	done < <(grep "^CLIENT_LIST" "$status_file")

	if [[ $format == "json" ]]; then
		echo '{"clients":['
		local first=true
		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name real_addr vpn_ip bytes_recv bytes_sent connected_since <<<"$client_entry"
			[[ $first == true ]] && first=false || printf ','
			printf '{"name":"%s","real_address":"%s","vpn_ip":"%s","bytes_received":%s,"bytes_sent":%s,"connected_since":"%s"}\n' \
				"$(json_escape "$name")" "$(json_escape "$real_addr")" "$(json_escape "$vpn_ip")" \
				"${bytes_recv:-0}" "${bytes_sent:-0}" "$(json_escape "$connected_since")"
		done
		echo ']}'
	else
		log_header "已连接客户端"
		log_info "找到 $client_count 个已连接客户端"
		log_menu ""
		printf "   %-20s %-22s %-16s %-20s %s\n" "名称" "真实地址" "VPN IP" "连接时间" "传输数据"
		printf "   %-20s %-22s %-16s %-20s %s\n" "----" "------------" "------" "---------------" "--------"

		for client_entry in "${clients_data[@]}"; do
			IFS='|' read -r name real_addr vpn_ip bytes_recv bytes_sent connected_since <<<"$client_entry"
			local recv_human sent_human
			recv_human=$(formatBytes "$bytes_recv")
			sent_human=$(formatBytes "$bytes_sent")
			local transfer="↓${recv_human} ↑${sent_human}"
			printf "   %-20s %-22s %-16s %-20s %s\n" "$name" "$real_addr" "$vpn_ip" "$connected_since" "$transfer"
		done
		log_menu ""
		log_info "注意：数据每 60 秒刷新一次。"
	fi
}

function newClient() {
	log_header "新客户端设置"

	# 仅当客户端名称未设置或无效时提示输入
	if ! is_valid_client_name "$CLIENT"; then
		log_prompt "请告诉我客户端的名称。"
		log_prompt "名称必须由字母数字字符、下划线或连字符组成（最多 $MAX_CLIENT_NAME_LENGTH 个字符）。"
		until is_valid_client_name "$CLIENT"; do
			read -rp "客户端名称: " -e CLIENT
		done
	fi

	# 仅当证书有效期未设置时提示输入
	if [[ -z $CLIENT_CERT_DURATION_DAYS ]] || ! [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $CLIENT_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "客户端证书应该有效期为多少天？"
		until [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] && [[ $CLIENT_CERT_DURATION_DAYS -ge 1 ]]; do
			read -rp "证书有效期（天）: " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS CLIENT_CERT_DURATION_DAYS
		done
	fi

	# 仅当密码设置未确定时提示输入
	if ! [[ $PASS =~ ^[1-2]$ ]]; then
		log_menu ""
		log_prompt "您想使用密码保护配置文件吗？"
		log_prompt "(例如：使用密码加密私钥)"
	log_menu "   1) 添加无密码客户端"
	log_menu "   2) 为客户端使用密码"
		until [[ $PASS =~ ^[1-2]$ ]]; do
			read -rp "选择选项 [1-2]: " -e -i 1 PASS
		done
	fi

	cd /etc/openvpn/server/easy-rsa/ || return

	# 读取认证模式
	if [[ -f AUTH_MODE_GENERATED ]]; then
		AUTH_MODE=$(cat AUTH_MODE_GENERATED)
	else
		AUTH_MODE="pki"
	fi

	# 检查客户端是否已存在
	if [[ -f pki/index.txt ]]; then
		CLIENTEXISTS=$(tail -n +2 /etc/openvpn/server/easy-rsa/pki/index.txt | grep -E "^V" | grep -c -E "/CN=$CLIENT\$")
	else
		CLIENTEXISTS=0
	fi

	if [[ $CLIENTEXISTS != '0' ]]; then
		log_error "指定的客户端 CN 已在 easy-rsa 中找到，请选择另一个名称。"
		exit 1
	fi

	log_info "生成客户端证书..."
	export EASYRSA_CERT_EXPIRE=$CLIENT_CERT_DURATION_DAYS

	# 根据认证模式确定 easyrsa 命令
	local easyrsa_cmd cert_desc
	if [[ $AUTH_MODE == "pki" ]]; then
		easyrsa_cmd="build-client-full"
		cert_desc="客户端证书"
	else
		easyrsa_cmd="self-sign-client"
		cert_desc="自签名客户端证书"
	fi

	case $PASS in
	1)
		run_cmd_fatal "构建 $cert_desc" ./easyrsa --batch "$easyrsa_cmd" "$CLIENT" nopass
		;;
	2)
		if [[ -z "$PASSPHRASE" ]]; then
			log_warn "下面将要求您输入客户端密码"
			if ! ./easyrsa --batch "$easyrsa_cmd" "$CLIENT"; then
				log_fatal "构建 $cert_desc 失败"
			fi
		else
			log_info "使用提供的密码保护客户端证书"
			export EASYRSA_PASSPHRASE="$PASSPHRASE"
			run_cmd_fatal "构建 $cert_desc" ./easyrsa --batch --passin=env:EASYRSA_PASSPHRASE --passout=env:EASYRSA_PASSPHRASE "$easyrsa_cmd" "$CLIENT"
			unset EASYRSA_PASSPHRASE
		fi
		;;
esac

	# 指纹模式：向服务器注册客户端指纹
	if [[ $AUTH_MODE == "fingerprint" ]]; then
		CLIENT_FINGERPRINT=$(openssl x509 -in "pki/issued/$CLIENT.crt" -fingerprint -sha256 -noout | cut -d'=' -f2)
		if [[ -z $CLIENT_FINGERPRINT ]]; then
			log_error "无法提取客户端证书指纹"
			exit 1
		fi
		log_info "客户端指纹: $CLIENT_FINGERPRINT"

		# 将指纹添加到 server.conf 的 <peer-fingerprint> 块中
		# 如果是第一个客户端，则创建该块
		if ! grep -q '<peer-fingerprint>' /etc/openvpn/server/server.conf; then
			echo "# 客户端指纹列在下面
<peer-fingerprint>
# $CLIENT
$CLIENT_FINGERPRINT
</peer-fingerprint>" >>/etc/openvpn/server/server.conf
		else
			# 在结束标签前插入注释和指纹
			sed -i "/<\/peer-fingerprint>/i # $CLIENT\n$CLIENT_FINGERPRINT" /etc/openvpn/server/server.conf
		fi

		# 重新加载 OpenVPN 以应用新指纹
		log_info "重新加载 OpenVPN 以应用新指纹..."
		if systemctl is-active --quiet openvpn-server@server; then
			systemctl reload openvpn-server@server 2>/dev/null || systemctl restart openvpn-server@server
		fi
	fi

	log_success "客户端 $CLIENT 已添加，有效期为 $CLIENT_CERT_DURATION_DAYS 天。"

	# 写入带有正确路径和权限的 .ovpn 配置文件
	writeClientConfig "$CLIENT"

	log_menu ""
	log_success "配置文件已写入 $GENERATED_CONFIG_PATH。"
	log_info "请下载 .ovpn 文件并导入到您的 OpenVPN 客户端中。"
}

function revokeClient() {
	log_header "吊销客户端"
	log_prompt "选择您要吊销的现有客户端证书"
	selectClient

	cd /etc/openvpn/server/easy-rsa/ || return

	# 读取认证模式
	local auth_mode="pki"
	if [[ -f AUTH_MODE_GENERATED ]]; then
		auth_mode=$(cat AUTH_MODE_GENERATED)
	fi

	log_info "正在吊销 $CLIENT 的证书..."

	if [[ $auth_mode == "pki" ]]; then
		# PKI 模式：使用 Easy-RSA 吊销和 CRL
		run_cmd_fatal "吊销证书" ./easyrsa --batch revoke-issued "$CLIENT"
		regenerateCRL
		run_cmd "备份索引" cp /etc/openvpn/server/easy-rsa/pki/index.txt{,.bk}
	else
		# 指纹模式：从 server.conf 中移除指纹并删除证书文件
		log_info "正在从服务器配置中移除客户端指纹..."

		# 从 server.conf 中移除注释行和其下方的指纹行
		sed -i "/^# $CLIENT\$/{N;d;}" /etc/openvpn/server/server.conf

		# 删除客户端证书和密钥
		rm -f "pki/issued/$CLIENT.crt" "pki/private/$CLIENT.key"

		# 如果 index.txt 存在，则将其标记为已吊销（用于客户端列表）
		if [[ -f pki/index.txt ]]; then
			sed -i "s|^V\(.*\)/CN=$CLIENT\$|R\1/CN=$CLIENT|" pki/index.txt
		fi

		# 重新加载 OpenVPN 以应用指纹移除
		log_info "重新加载 OpenVPN 以应用指纹移除..."
		if systemctl is-active --quiet openvpn-server@server; then
			systemctl reload openvpn-server@server 2>/dev/null || systemctl restart openvpn-server@server
		fi
	fi

	run_cmd "从 /home 移除客户端配置" find /home/ -maxdepth 2 -name "$CLIENT.ovpn" -delete
	run_cmd "从 /root 移除客户端配置" rm -f "/root/$CLIENT.ovpn"
	run_cmd "移除 IP 分配" sed -i "/^$CLIENT,.*/d" /etc/openvpn/server/ipp.txt

	# 如果客户端当前已连接，则断开连接
	disconnectClient "$CLIENT"

	log_success "客户端 $CLIENT 的证书已吊销。"
}

# 通过管理接口断开客户端连接
function disconnectClient() {
	local client_name="$1"
	local mgmt_socket="/var/run/openvpn/server.sock"

	if [[ ! -S "$mgmt_socket" ]]; then
		log_warning "管理套接字未找到。客户端可能仍处于连接状态，直到他们重新连接。"
		return 0
	fi

	log_info "正在断开客户端 $client_name 的连接..."
	if echo "kill $client_name" | socat - UNIX-CONNECT:"$mgmt_socket" >/dev/null 2>&1; then
		log_success "客户端 $client_name 已断开连接。"
	else
		log_warning "无法断开客户端连接（他们可能未连接）。"
	fi
}

function renewClient() {
	local client_cert_duration_days

	log_header "续订客户端证书"
	log_prompt "选择您要续订的现有客户端证书"
	selectClient "true"

	# 允许用户指定续订有效期（无头模式下使用 CLIENT_CERT_DURATION_DAYS 环境变量）
	if [[ -z $CLIENT_CERT_DURATION_DAYS ]] || ! [[ $CLIENT_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $CLIENT_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "续订后的证书应该有效期为多少天？"
		until [[ $client_cert_duration_days =~ ^[0-9]+$ ]] && [[ $client_cert_duration_days -ge 1 ]]; do
			read -rp "证书有效期（天）: " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS client_cert_duration_days
		done
	else
		client_cert_duration_days=$CLIENT_CERT_DURATION_DAYS
	fi

	cd /etc/openvpn/server/easy-rsa/ || return
	log_info "正在续订 $CLIENT 的证书..."

	# 在续订前备份旧证书
	run_cmd "备份旧证书" cp "/etc/openvpn/server/easy-rsa/pki/issued/$CLIENT.crt" "/etc/openvpn/server/easy-rsa/pki/issued/$CLIENT.crt.bak"

	# 续订证书（保持相同的私钥）
	export EASYRSA_CERT_EXPIRE=$client_cert_duration_days
	run_cmd_fatal "续订证书" ./easyrsa --batch renew "$CLIENT"

	# 吊销旧证书
	run_cmd_fatal "吊销旧证书" ./easyrsa --batch revoke-renewed "$CLIENT"

	# 重新生成 CRL
	regenerateCRL

	# 写入带有正确路径和权限的 .ovpn 配置文件
	writeClientConfig "$CLIENT"

	log_menu ""
	log_success "客户端 $CLIENT 的证书已续订，有效期为 $client_cert_duration_days 天。"
	log_info "新配置文件已写入 $GENERATED_CONFIG_PATH。"
	log_info "请下载新的 .ovpn 文件并导入到您的 OpenVPN 客户端中。"
}

function renewServer() {
	local server_name server_cert_duration_days

	log_header "续订服务器证书"

	# 从配置中获取服务器名称（提取 basename，因为路径可能是相对的）
	server_name=$(basename "$(grep '^cert ' /etc/openvpn/server/server.conf | cut -d ' ' -f 2)" .crt)
	if [[ -z "$server_name" ]]; then
		log_fatal "无法从 /etc/openvpn/server/server.conf 确定服务器证书名称"
	fi

	log_prompt "这将续订服务器证书：$server_name"
	log_warn "续订后将重启OpenVPN服务。"
	if [[ -z $CONTINUE ]]; then
		read -rp "您想继续吗？[y/n]: " -e -i n CONTINUE
	fi
	if [[ $CONTINUE != "y" ]]; then
		log_info "续订已取消。"
		return
	fi

	# 允许用户指定续订有效期（无头模式下使用 SERVER_CERT_DURATION_DAYS 环境变量）
	if [[ -z $SERVER_CERT_DURATION_DAYS ]] || ! [[ $SERVER_CERT_DURATION_DAYS =~ ^[0-9]+$ ]] || [[ $SERVER_CERT_DURATION_DAYS -lt 1 ]]; then
		log_menu ""
		log_prompt "续订后的证书应该有效期为多少天？"
		until [[ $server_cert_duration_days =~ ^[0-9]+$ ]] && [[ $server_cert_duration_days -ge 1 ]]; do
			read -rp "证书有效期（天）: " -e -i $DEFAULT_CERT_VALIDITY_DURATION_DAYS server_cert_duration_days
		done
	else
		server_cert_duration_days=$SERVER_CERT_DURATION_DAYS
	fi

	cd /etc/openvpn/server/easy-rsa/ || return
	log_info "正在续订服务器证书..."

	# 在续订前备份旧证书
	run_cmd "备份旧证书" cp "/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt" "/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt.bak"

	# 续订证书（保持相同的私钥）
	export EASYRSA_CERT_EXPIRE=$server_cert_duration_days
	run_cmd_fatal "续订证书" ./easyrsa --batch renew "$server_name"

	# 吊销旧证书
	run_cmd_fatal "吊销旧证书" ./easyrsa --batch revoke-renewed "$server_name"

	# 重新生成 CRL
	regenerateCRL

	# 将新证书复制到 /etc/openvpn/server/
	run_cmd_fatal "复制新证书" cp "/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt" /etc/openvpn/server/

	# 重启 OpenVPN
	log_info "正在重启 OpenVPN 服务..."
	run_cmd "重启 OpenVPN" systemctl restart openvpn-server@server

	log_success "服务器证书已成功续订，有效期为 $server_cert_duration_days 天。"
}

function getDaysUntilExpiry() {
	local cert_file="$1"
	if [[ -f "$cert_file" ]]; then
		local expiry_date
		expiry_date=$(openssl x509 -in "$cert_file" -noout -enddate | cut -d= -f2)
		local expiry_epoch
		expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry_date" +%s 2>/dev/null)
		if [[ -z "$expiry_epoch" ]]; then
			echo "?"
			return
		fi
		local now_epoch
		now_epoch=$(date +%s)
		echo $(((expiry_epoch - now_epoch) / 86400))
	else
		echo "?"
	fi
}

function formatExpiry() {
	local days="$1"
	if [[ "$days" == "?" ]]; then
		echo "(未知过期时间)"
	elif [[ $days -lt 0 ]]; then
		echo "(已过期 $((-days)) 天)"
	elif [[ $days -eq 0 ]]; then
		echo "(今天过期)"
	elif [[ $days -eq 1 ]]; then
		echo "(1 天后过期)"
	else
		echo "($days 天后过期)"
	fi
}

function renewMenu() {
	local server_name server_cert server_days server_expiry renew_option

	log_header "证书续订"

	# 获取服务器证书过期时间用于菜单显示（提取 basename，因为路径可能是相对的）
	server_name=$(basename "$(grep '^cert ' /etc/openvpn/server/server.conf | cut -d ' ' -f 2)" .crt)
	if [[ -z "$server_name" ]]; then
		server_expiry="(未知过期时间)"
	else
		server_cert="/etc/openvpn/server/easy-rsa/pki/issued/$server_name.crt"
		server_days=$(getDaysUntilExpiry "$server_cert")
		server_expiry=$(formatExpiry "$server_days")
	fi

	log_menu ""
	log_prompt "您想要续订什么？"
	log_menu "   1) 续订客户端证书"
	log_menu "   2) 续订服务器证书 $server_expiry"
	log_menu "   3) 返回主菜单"
	until [[ ${RENEW_OPTION:-$renew_option} =~ ^[1-3]$ ]]; do
		read -rp "选择选项 [1-3]: " renew_option
	done
	renew_option="${RENEW_OPTION:-$renew_option}"

	case $renew_option in
	1)
		renewClient
		;;
	2)
		renewServer
		;;
	3)
		manageMenu
		;;
	esac
}

function removeUnbound() {
	run_cmd "移除 OpenVPN Unbound 配置" rm -f /etc/unbound/unbound.conf.d/openvpn.conf

	# 如果 conf.d 目录现在为空，则清理 include 指令
	if [[ -d /etc/unbound/unbound.conf.d ]] && [[ -z "$(ls -A /etc/unbound/unbound.conf.d)" ]]; then
		run_cmd "清理 Unbound include 指令" \
			sed -i '/^include: "\/etc\/unbound\/unbound\.conf\.d\/\*\.conf"$/d' /etc/unbound/unbound.conf
	fi

	until [[ $REMOVE_UNBOUND =~ (y|n) ]]; do
		log_info "如果您在安装 OpenVPN 之前已经在使用 Unbound，我已经移除了与 OpenVPN 相关的配置。"
		read -rp "您想要完全移除 Unbound 吗？[y/n]: " -e REMOVE_UNBOUND
	done

	if [[ $REMOVE_UNBOUND == 'y' ]]; then
		log_info "正在移除 Unbound..."
		run_cmd "停止 Unbound" systemctl stop unbound

		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "移除 Unbound" apt-get remove --purge -y unbound
		elif [[ $OS == 'arch' ]]; then
			run_cmd "移除 Unbound" pacman --noconfirm -R unbound
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd "移除 Unbound" yum remove -y unbound
		elif [[ $OS =~ (fedora|amzn2023) ]]; then
			run_cmd "移除 Unbound" dnf remove -y unbound
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd "移除 Unbound" zypper remove -y unbound
		fi

		run_cmd "移除 Unbound 配置" rm -rf /etc/unbound/
		log_success "Unbound 已移除!"
	else
		run_cmd "重启 Unbound" systemctl restart unbound
		log_info "Unbound 未被移除。"
	fi
}

function removeOpenVPN() {
	log_header "移除 OpenVPN"
	if [[ -z $REMOVE ]]; then
		read -rp "您确定要移除 OpenVPN 吗？[y/n]: " -e -i n REMOVE
	fi
	if [[ $REMOVE == 'y' ]]; then
		# 获取 OpenVPN 配置
		PORT=$(grep '^port ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		PROTOCOL=$(grep '^proto ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		# 移除防火墙/SELinux 命令的 "6" 后缀（它们需要 "udp"/"tcp"，而不是 "udp6"/"tcp6"）
		PROTOCOL_BASE="${PROTOCOL%6}"
		# 提取 IPv4 子网（如果未启用 IPv4 则可能为空）
		VPN_SUBNET_IPV4=$(grep '^server ' /etc/openvpn/server/server.conf | cut -d " " -f 2)
		# 提取 IPv6 子网（如果未启用 IPv6 则可能为空）
		VPN_SUBNET_IPV6=$(grep '^server-ipv6 ' /etc/openvpn/server/server.conf | cut -d " " -f 2 | sed 's|/.*||')

		# 停止 OpenVPN
		log_info "正在停止 OpenVPN 服务..."
		run_cmd "禁用 OpenVPN 服务" systemctl disable openvpn-server@server
		run_cmd "停止 OpenVPN 服务" systemctl stop openvpn-server@server
		# 移除自定义服务
		run_cmd "移除服务文件" rm -f /etc/systemd/system/openvpn-server@.service

		# 移除防火墙规则
		log_info "正在移除防火墙规则..."
		if systemctl is-active --quiet firewalld && firewall-cmd --list-ports | grep -q "$PORT/$PROTOCOL_BASE"; then
			# 使用了 firewalld
			run_cmd "从 firewalld 移除 OpenVPN 端口" firewall-cmd --permanent --remove-port="$PORT/$PROTOCOL_BASE"
			run_cmd "从 firewalld 移除 masquerade" firewall-cmd --permanent --remove-masquerade
			# 如果配置了 IPv4 富规则，则移除
			if [[ -n $VPN_SUBNET_IPV4 ]]; then
				firewall-cmd --permanent --remove-rich-rule="rule family=\"ipv4\" source address=\"$VPN_SUBNET_IPV4/24\" accept" 2>/dev/null || true
			fi
			# 如果配置了 IPv6 富规则，则移除
			if [[ -n $VPN_SUBNET_IPV6 ]]; then
				firewall-cmd --permanent --remove-rich-rule="rule family=\"ipv6\" source address=\"${VPN_SUBNET_IPV6}/112\" accept" 2>/dev/null || true
			fi
			run_cmd "重新加载 firewalld" firewall-cmd --reload
		elif [[ -f /etc/nftables/openvpn.nft ]]; then
			# 使用了 nftables
			# 删除表（抑制错误，以防表不存在）
			nft delete table inet openvpn 2>/dev/null || true
			nft delete table ip openvpn-nat 2>/dev/null || true
			nft delete table ip6 openvpn-nat 2>/dev/null || true
			run_cmd "从 nftables.conf 移除 include" sed -i '/include.*openvpn\.nft/d' /etc/nftables.conf
			run_cmd "移除 nftables 规则文件" rm -f /etc/nftables/openvpn.nft
		elif [[ -f /etc/systemd/system/iptables-openvpn.service ]]; then
			# 使用了 iptables
			run_cmd "停止 iptables 服务" systemctl stop iptables-openvpn
			run_cmd "禁用 iptables 服务" systemctl disable iptables-openvpn
			run_cmd "移除 iptables 服务文件" rm /etc/systemd/system/iptables-openvpn.service
			run_cmd "重新加载 systemd" systemctl daemon-reload
			run_cmd "移除 iptables 添加脚本" rm -f /etc/iptables/add-openvpn-rules.sh
			run_cmd "移除 iptables 移除脚本" rm -f /etc/iptables/rm-openvpn-rules.sh
		fi

		# SELinux
		if hash sestatus 2>/dev/null; then
			if sestatus | grep "Current mode" | grep -qs "enforcing"; then
				if [[ $PORT != '1194' ]]; then
					run_cmd "移除 SELinux 端口" semanage port -d -t openvpn_port_t -p "$PROTOCOL_BASE" "$PORT"
				fi
			fi
		fi

		log_info "正在移除 OpenVPN 包..."
		if [[ $OS =~ (debian|ubuntu) ]]; then
			run_cmd "移除 OpenVPN" apt-get remove --purge -y openvpn
			# 移除 OpenVPN 官方仓库和 GPG 密钥
			if [[ -e /etc/apt/sources.list.d/openvpn-aptrepo.list ]]; then
				run_cmd "移除 OpenVPN 仓库" rm /etc/apt/sources.list.d/openvpn-aptrepo.list
			fi
			if [[ -e /etc/apt/keyrings/openvpn-repo-public.asc ]]; then
				run_cmd "移除 OpenVPN GPG 密钥" rm /etc/apt/keyrings/openvpn-repo-public.asc
			fi
			run_cmd_fatal "更新包列表" apt-get update
		elif [[ $OS == 'arch' ]]; then
			run_cmd "移除 OpenVPN" pacman --noconfirm -R openvpn
		elif [[ $OS =~ (centos|oracle) ]]; then
			run_cmd "移除 OpenVPN" yum remove -y openvpn
			# 如果启用了 Copr 仓库，则禁用
			if command -v dnf &>/dev/null; then
				run_cmd "禁用 OpenVPN Copr 仓库" dnf copr disable -y @OpenVPN/openvpn-release-2.6 2>/dev/null || true
			else
				run_cmd "禁用 OpenVPN Copr 仓库" yum copr disable -y @OpenVPN/openvpn-release-2.6 2>/dev/null || true
			fi
		elif [[ $OS == 'amzn2023' ]]; then
			run_cmd "移除 OpenVPN" dnf remove -y openvpn
		elif [[ $OS == 'fedora' ]]; then
			run_cmd "移除 OpenVPN" dnf remove -y openvpn
		elif [[ $OS == 'opensuse' ]]; then
			run_cmd "移除 OpenVPN" zypper remove -y openvpn
		fi

		# 清理
		run_cmd "从 /home 移除客户端配置" find /home/ -maxdepth 2 -name "*.ovpn" -delete
		run_cmd "从 /root 移除客户端配置" find /root/ -maxdepth 1 -name "*.ovpn" -delete
		run_cmd "移除 /etc/openvpn" rm -rf /etc/openvpn
		run_cmd "移除 OpenVPN 文档" rm -rf /usr/share/doc/openvpn*
		run_cmd "移除 sysctl 配置" rm -f /etc/sysctl.d/99-openvpn.conf
		run_cmd "移除 OpenVPN 日志" rm -rf /var/log/openvpn

		# Unbound
		if [[ -e /etc/unbound/unbound.conf.d/openvpn.conf ]]; then
			removeUnbound
		fi
		log_success "OpenVPN 已移除!"
	else
		log_info "移除已中止!"
	fi
}

function manageMenu() {
	local menu_option

	log_header "OpenVPN 管理"
	log_prompt "Git仓库地址：https://github.com/plutobe/openvpn-install-zh"
	log_success "OpenVPN 已经安装。"
	log_menu ""
	log_prompt "您想做什么？"
	log_menu "   1) 添加新用户"
	log_menu "   2) 列出客户端证书"
	log_menu "   3) 吊销现有用户"
	log_menu "   4) 续订证书"
	log_menu "   5) 移除OpenVPN"
	log_menu "   6) 列出已连接客户端"
	log_menu "   7) 退出"
	until [[ ${MENU_OPTION:-$menu_option} =~ ^[1-7]$ ]]; do
		read -rp "选择选项 [1-7]: " menu_option
	done
	menu_option="${MENU_OPTION:-$menu_option}"

	case $menu_option in
	1)
		newClient
		exit 0
		;;
	2)
		listClients
		;;
	3)
		revokeClient
		;;
	4)
		renewMenu
		;;
	5)
		removeOpenVPN
		;;
	6)
		listConnectedClients
		;;
	7)
		exit 0
		;;
	esac
}

# =============================================================================
# 主入口点
# =============================================================================
parse_args "$@"
