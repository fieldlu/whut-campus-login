# WHUT 校园网双网自动登录器

武汉理工大学校园网自动登录 / 断线保活脚本，**一套代码同时支持两个校园网**：

| 网络 | 说明 | 认证门户 |
|---|---|---|
| **WHUT-WLAN** | 教学办公区无线 | `tpl/whut` 门户（API + CSRF 令牌） |
| **WHUT-ISP** | 宿舍区 / 运营商接入 | 深澜 srun 门户 `172.30.16.34` |

程序会自动判断当前在哪个网、该走哪套协议，不需要手动切换；掉线后自动重连。

## 特性

- **双网自动识别**：auto 模式下先探测门户重定向，拿不到再回落到 srun 门户
- **防误判**：在线判定失败后二次确认（等 3 秒重试），避免瞬时抖动触发登录把已有会话顶掉
- **保活模式**：`--watch` 定时检测，掉线自动重连
- **绕过系统代理**：未认证时绝不会把登录请求送进 Clash 类代理（`trust_env = False`）
- **凭据与代码分离**：账号密码只放在 `config.json`，已写入 `.gitignore`
- **零重依赖**：仅需 `requests`

## 快速开始

```bash
pip install -r requirements.txt

# 1) 生成凭据文件（交互输入，明文保存在本地 config.json）
python whut_login.py --init-config

# 2) 检查当前联网状态
python whut_login.py --check-only

# 3) 未联网则登录
python whut_login.py

# 4) 保活模式：每 60 秒检测一次，掉线自动重连
python whut_login.py --watch 60
```

指定网络（自动识别失败时用）：

```bash
python whut_login.py --net wlan    # 强制走 WHUT-WLAN 门户
python whut_login.py --net isp     # 强制走 WHUT-ISP srun 门户
```

## 命令行参数

| 参数 | 说明 |
|---|---|
| `--net {auto,wlan,isp}` | 指定网络，默认 `auto` 自动识别 |
| `--watch [SEC]` | 保活模式，检测间隔秒数（默认 300，最小 30） |
| `--check-only` | 仅输出当前在线状态与 SSID |
| `--init-config` | 交互式生成 `config.json` 后退出 |

退出码：`0` 在线 / 登录成功，`1` 登录失败或凭据缺失，`130` 用户中断。

## 认证协议说明

### WHUT-WLAN（tpl/whut 门户）

1. 访问 HTTP 种子站点触发门户劫持重定向，从 `Location` 中解析门户 `host` 与 `nasId`
2. `GET /tpl/whut/login.html?nasId=...` 建立会话、拿 cookie
3. `GET /tpl/whut/static/js/config.js`，正则解析 `host_url` 得到 API 前缀
4. `GET {api_base}/csrf-token` 取 CSRF 令牌
5. `POST {api_base}/account/login`（带 `X-Csrf-Token`），返回 `code == 0` 即成功

### WHUT-ISP（深澜 srun 门户）

`POST http://172.30.16.34/include/auth_action.php`，表单含 `action=login`、`ac_id`（依次尝试 `0` / `5`）、`username`、`password`（`{B}` + base64）、`user_mac`（本机真实 MAC）。返回含 `login_ok` / `successful` 即成功。

> 门户 IP 与 `ac_id` 会随校区、楼栋、接入设备变化。若你的位置连不上默认门户，用 `--net` 指定，或直接把脚本里 `ISP_PORTAL` 改成你自己的门户地址（浏览器未登录时随便打开一个 HTTP 网站，看跳转后的地址即可）。

## 常见问题

**Q：在线判定会不会误报，导致重复登录把会话顶掉？**
不会。`is_online_sure()` 在首次探测失败后等 3 秒重试，两次都失败才判定离线；auto 模式在 WLAN 探测落空后还会再确认一次在线状态。

**Q：为什么脚本要禁用系统代理？**
认证门户都在内网地址上，走代理必然失败；而门户未认证时会劫持 HTTP 请求，走代理则会绕过劫持，导致拿不到 `nasId`。

**Q：密码明文存在 `config.json` 安全吗？**
文件不入库、不随代码分发，但**并非加密**。若要收紧权限，Windows 下可执行：

```powershell
icacls config.json /inheritance:r /grant:r "$env:USERNAME:(R,W)"
```

**Q：双击运行 / 开机自启？**
仓库自带 `run_keepalive.bat`：双击即进入保活，且**进程退出后会自动重启**。把它的快捷方式放进 `shell:startup` 即可开机自启。

**Q：能不能同时开好几个保活？**
不能，也不必要。保活模式启动时会对 `watch.lock` 加排他锁，第二个进程会打印「检测到已有保活进程在运行」后直接退出——多开会让两边同时判定离线、互相把会话顶掉。

**Q：宿舍网已连接状态下重复认证会不会断网？**
部分宿舍网会。脚本已通过二次确认在线判定尽量规避，但如果你手动反复运行，仍可能触发。保活模式足够，不必手动重复登录。

## 测试

```bash
python test_whut_login.py          # 或 python -m unittest -v test_whut_login
```

46 个用例，全部离线运行（假 session，不访问真实网络），覆盖：

| 范围 | 覆盖点 |
|---|---|
| URL 拼装 | 绝对前缀 / 相对前缀 / 尾斜杠 / 空前缀 / https |
| 门户探测 | 拿到 nasId、无 nasId、空 URL、首个种子报错后换种子、全部失败 |
| WLAN 登录 | 握手异常、绝对前缀成功、绝对失败后回退同主机 `/api`、双候选都失败、`csrf` 嵌套在 `data`、登录响应非 dict、`code != 0`、config.js 取不到 |
| ISP | 门户不可达直接跳过、ac_id=0 成功、两个 ac_id 都失败、密码 `{B}` 编码 |
| 编排 | `--net` 三种取值、auto 的「WLAN 失败但实际在线」与「转 ISP」分支 |
| 凭据 | 明文 / base64 / JSON 损坏 / 非对象 / 文件缺失 / 字段为空 |
| 主流程 | `--check-only`、登录成败退出码、保活循环遇异常不退出并计数 |
| 单实例 | 加解锁循环、第二进程被拒、被锁时 `--watch` 安静退出 |

## 变更记录

- **2026-10-28** 修复 WLAN 登录必然失败：`config.js` 的 `host_url` 是绝对地址，原代码按前缀拼接得到非法主机名；改为 `_api_url()` 并增加同主机 `/api` 兜底。同时补齐 6 处健壮性缺陷（握手异常未捕获、登录响应非 dict、`get_host_ip` 变量未绑定、凭据文件损坏、空输入、死常量），新增保活单实例锁与 46 个离线回归用例。
- **2026-10-27** 修复 `_fetch_portal` 把字符串当 `urlparse` 结果取 `.netloc` 导致的崩溃；保活循环加异常兜底，单次失败不再终止进程。

## 协议来源与致谢

协议细节整理自以下开源项目，特此致谢：

- [FeliksLv01/WHUT-WLAN](https://github.com/FeliksLv01/WHUT-WLAN) — tpl/whut 门户登录思路
- [lxidea/whut-online-keeper](https://github.com/lxidea/whut-online-keeper)（Apache-2.0）— nasId 获取、CSRF、`account/login` 完整流程
- [PGA1293/WHUT-WLAN-DORM](https://github.com/PGA1293/WHUT-WLAN-DORM) — 宿舍网 srun 表单字段
- [MuZiCul/Login_whut](https://github.com/MuZiCul/Login_whut) — srun 门户结构与 `ac_id` 尝试策略

## 免责声明

本项目仅供**个人学习与自动化研究**使用，请使用**本人账号**登录本人所在的校园网。请遵守学校网络管理规定，勿用于账号共享、代认证等违规用途。因使用本脚本产生的一切后果由使用者自行承担。

## License

[MIT](LICENSE)
