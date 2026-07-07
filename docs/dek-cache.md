# DEK 缓存方案（approve 时选择缓存时长，过期前免审批解密）

状态：**已实现并部署**。§1–§10 是设计/讨论过程（含 codex-expert 审查的 M/S/N 项），保留以记录权衡与理由；落地过程中有几处与最初计划不同——**以 §11「最终实现状态」为准**（单一 `CACHE_SECKEY`、统一审计表、仅命中入审计、缓存管理并入审计页等）。

## 1. 需求复述

- approve 审批页加几个"缓存时长"按钮：默认 **0 秒（不缓存，行为同现在）**，外加 **8 分钟 / 20 分钟 / 2 小时**。
- 审批时若选了 >0 的时长，则把这次 ceremony 涉及的 DEK 以该 TTL 写入服务端缓存（KV 或 DO storage），到期自动删除。
- 客户端发起解密时，**先查这次请求的所有 salt 对应的 DEK 是否都在缓存里且未过期**；若全部命中，则直接下发 DEK、跳过手机审批，客户端正常解密。
- 部分命中 / 未命中 → 回退到现有的手机审批 ceremony。

## 2. 必须先讲清楚的安全权衡（这是方案的核心，不是脚注）

当前 vt 的核心不变量（见 `CLAUDE.md` / `src/cf.rs` 头注）：

> **No master_key cache. Worker 永不接触明文 DEK。每一次解密操作都需要手机 WebAuthn 审批。**

DEK 之所以 worker 拿不到，是因为 PWA 用 `crypto_box_seal(deks, daemon_pubkey)` 把 DEK 封到**客户端本次 ceremony 的临时 X25519 公钥**上（`approve.js:140`）。每次 ceremony 的 daemon keypair 都是新的（`cf.rs:258` `crypto_box_keypair()`），所以 worker 存下来的 `sealed_deks` 只有**当时那个客户端进程**能解，**换一个请求就解不开**。这就是为什么"缓存 sealed_deks 再重发"在密码学上行不通。

要实现"另一个进程、稍后、不连手机"也能拿到 DEK，服务端缓存里就必须存**能被任意未来请求重新封装的 DEK**，也就是 **worker 在 TTL 窗口内持有可还原的明文 DEK**。

### 这等于主动放弃一项核心安全保证

| 维度 | 现状 | 启用缓存（TTL 窗口内） |
|---|---|---|
| worker 是否接触明文 DEK | 否（只见 sealed_box） | **是**（缓存命中时由 worker 重新封装下发） |
| 每次解密是否需手机在场 | 是 | **否**（窗口内对已缓存 salt 免审批） |
| 服务器被攻陷时能否解密 | 不能（缺手机第二因子） | **窗口内能**，对已缓存的那些记录 |

换言之：一旦某次审批选了 2 小时，未来 2 小时内**任何持有 `VT_PASSKEY_TOKEN` 的人/进程**（包括攻陷了该服务器的攻击者），对那批 salt 对应的记录都能免审批解密。这正是"用便利换安全"的取舍——必须让用户在知情的前提下、**每次审批显式选择**，且默认 0（不缓存）。

**`VT_PASSKEY_TOKEN` 的威胁等级因此被抬高（S1）。** 它通常作为环境变量存在于该 Linux 主机上**每一个会跑 `vt` 的进程**里（cron、脚本、部署的应用）。从 `/proc/<pid>/environ` 或泄露的 `.env` 读到它，过去只能"发起一次注定要等手机的 ceremony"，**现在在缓存窗口内足以直接解出明文 DEK，无需任何手机交互**。即它从"第一因子、单独无害"变成"对已缓存记录的唯一充分因子"，且攻击面是窗口内整条软件栈（含被投毒的依赖/脚本），不限于交互式攻击者。

**三个被混为一谈的攻陷等级要分层（S1）：**
- L1 存储泄露（DO 导出 / 备份），无运行进程 → 被 §3 的 CACHE_SECKEY 层挡住。
- L2 worker 进程被攻陷（代码注入 / 供应链 / CF 账号被夺）→ `CACHE_SECKEY` 在进程内，**挡不住**。
- L3 跑 CLI 的主机被攻陷到能读环境变量 → 持 `VT_PASSKEY_TOKEN` 调 `/api/dek-cache` 即可，**挡不住**。
只有 L1 被纵深防御覆盖；L2/L3 不在缓解范围内，必须说清。

绑定/MITM 防护（`verify_binding`）在缓存路径下天然失效：缓存命中时 DEK 由 worker 提供，"恶意 worker 替换 DEK"在这条路径上本就不可防（worker 本来就持有 DEK）。我们只能依赖 TLS 防网络中间人，并用"封给客户端本次临时公钥的 sealed_box"保证只有发起方能解开下发内容。

> 决策点①：是否接受该取舍？若不可接受，应改为**客户端本地缓存**（见 §7 备选 B），但那与"另一进程免审批"和"服务端 KV"诉求冲突，需要重新对齐需求。

## 2.5 缓存绑定 IP + PWD（曾含 PPID，已移除）

缓存条目不再只按 salt 全局有效，而是**绑定到首次审批时发起方的源 IP 及其工作目录（pwd）**。`/api/dek-cache` 命中要求请求方的 **IP 与审批时记录的一致，且 pwd 一致**（任一不同即视为未命中，回退手机审批）。

**两个绑定项：**

| 绑定项 | 来源 | 可信度 | 实际防住什么 |
|---|---|---|---|
| **IP** | worker 从 `CF-Connecting-IP` 取（**客户端无法伪造**，沿用 `index.ts` 现有做法） | **强（硬边界）** | token 被偷到**另一台机器/另一个出口 IP** 后无法命中缓存——这是真正有意义的边界 |
| **PWD** | 客户端在请求体 `meta.pwd` 上报（`std::env::current_dir()`，`capChallengeMeta` 截断 200 字节） | **弱（advisory）** | 同主机上从**无关目录**发起的解密不再命中——把爆炸半径从「整个 egress IP」收窄到「该 IP + 该项目目录」 |
| **~~PPID~~（已移除）** | ~~客户端在请求体里上报的数字~~ | ~~弱（advisory）~~ | 移除原因见下 |

**PWD 与被移除的 PPID 有一处关键区别——稳定性：**
- PWD 与 PPID **同样**是客户端上报、worker 无法独立核验的 advisory 值，本机攻击者都能伪造 → 都**不扩大** IP 这条真正的硬边界。
- 但 PWD 在编排器（Claude Code / CI / make / tmux）下**稳定**：这些工具虽每条命令 fork 新 shell（`getppid()` 每次都变，导致 PPID 从不命中），但 cwd 通常固定在项目目录 → 同一逻辑会话内 pwd 不变，缓存正常命中。这正是 PPID 做不到、PWD 能做到的。

诚实结论:**IP 仍是唯一的硬边界**；PWD 只在同一 IP 内**进一步收窄**爆炸半径，绝不放宽。窗口内有效保证 = **同一 egress IP + 同一 pwd + 持有 `VT_PASSKEY_TOKEN` + TTL 未过**。

**接受的取舍**:窗口内绑定粒度 = egress IP + 工作目录。同主机、同 IP、**同目录**下另一个持有 token 的进程,在 TTL 窗口内仍能免审批命中同一批记录（它既然持有 token 本就能自行发起审批,缓存只是省掉那一次手机点击）。要收紧爆炸半径,用更短的 TTL 或事后在审计页「清除缓存」。

**命中条件的运维注意（否则会"缓存不生效"）：**
- **稳定的出口 IP 族**：cache ctx 绑定 `CF-Connecting-IP`。双栈主机若在两次请求间在 IPv4/IPv6 间漂移，worker 看到的 IP 不同 → ctx 不同 → 不命中。客户端已统一通过 `cf_post()` 固定走 IPv4（IPv6-only 主机自动回退 IPv6），消除这种漂移。
- **稳定的 pwd**：审批与后续解密必须在**同一工作目录**发起。切换 cwd（或 pwd 超过 200 字节被截断后不一致）→ ctx 不同 → 不命中。审批与命中两侧都经 `capChallengeMeta(pwd, 200)`，取值一致。
- **必须配置 `CACHE_SECKEY` 且审批时选了 >0 时长**：未配置 secret 时审批页根本不显示时长选项、缓存全程禁用；默认 0 不缓存。
- 诊断：缓存命中/清除/写入失败都在 admin「审计」页（类型=DEK缓存\*，op_kind='cache'），授予过缓存的审批行在「缓存」列显示 TTL/「过期」、并带「清除缓存」按钮；「带缓存」过滤一键筛出。审计行展示 IP/PWD/PPID（PPID 仅供取证,不参与绑定）。（注：未命中**不**写审计，只进 CF 日志 `cache.miss`。）

绑定上下文取自**首次 `/api/challenge` 的客户端**（不是手机）：审批时把 `ch.meta.ip` 与 `ch.meta.pwd` 编进缓存键 ctx（`ch.meta.ppid` 仍冗余存,仅审计用）。

## 3. 缓存键、粒度与存储位置

- **缓存单元 = 单个 DEK，键含上下文：`dek:{ctx}:{salt_b64u}`**，其中 `ctx = b64u(SHA-256("vt-dek-ctx-v3" || len_be32(ip) || ip_utf8 || pwd_utf8))`（tag 演进 v1→v2→v3:v1 含 ppid_le 已移除,v2 仅 IP,v3 增加 pwd）。IP 做定长前缀避免 `(ip,pwd)` 拼接歧义。
  - `DEK = HKDF(master_key, salt, "vt-dek-v2")`，salt（vt:// URL 里携带，16 字节随机）唯一决定 DEK，按 salt 收敛到被审批记录。
  - 把 IP + pwd 编进键的好处：(1) 不同 IP/目录上下文不会相互覆盖；(2) 读取时直接按"本次请求的 ctx + salt"取，命中即天然满足绑定，无需"取出再比对"的分支；(3) 不同 ctx 下的同一 salt 一律表现为 miss，**不产生 oracle**。
  - 条目里仍冗余存原始 `ip`/`ppid`/`ppid_cmd` 供审计展示（`ppid` 仅取证,不参与键；pwd 已在键内，审计行由 challenge meta 展示）。
- **只对解密有意义。** 加密每次生成新随机 salt（`client.rs:500`），永远不会命中缓存；auth-only（`salts=[]`）无 DEK，不涉及。符合需求"请求解密时先查缓存"。
- **存储位置：优先 DO storage，不用 KV。** 理由：
  - `AccountDO` 是账号级单例，已有 storage + alarm 清扫器 + SQLite 审计表，TTL 清理可直接复用 `alarm()`（`do_account.ts:226`）。
  - KV 是最终一致、写后可读延迟，且要引入第二套系统与绑定；DO 强一致更适合"刚审批完立刻命中"。
  - DO storage 在 CF 侧静态加密；我们再叠加一层"封给 worker 缓存公钥"做纵深防御（见下）。
- **不信任 alarm 时序：读取时强制校验 `expires_ms`，过期即视为未命中并惰性删除。** alarm 只做兜底批量清理。

### 缓存条目内容（DO storage key：`dek:{ctx}:{salt_b64u}`）

```
{
  sealed_to_cache_b64u: string,  // crypto_box_seal(DEK_raw, CACHE_PUBKEY)
  expires_ms: number,
  origin_token_id: string,       // 审计：哪次审批写入的（= 审批行 token_id）
  ip: string,                    // 绑定上下文（冗余存，便于审计）
  ppid: number,
  ppid_cmd: string
}
```

**纵深防御（决策点②，建议采纳）**：不直接存明文 DEK，而是 PWA 把 DEK 用一个 **worker 持有私钥的"缓存公钥" `CACHE_PUBKEY`** 再封一层（libsodium sealed_box）。

- `CACHE_PUBKEY` 公钥编进 worker（或随 page data 下发给 PWA），`CACHE_SECKEY` 作为 `wrangler secret`。
- 好处：单纯 dump DO storage（没有 `CACHE_SECKEY`）拿不到明文 DEK；轮换 `CACHE_SECKEY` 即可一键作废所有缓存。
- 诚实地说：worker 运行时仍持有 `CACHE_SECKEY` 与解出的明文 DEK——**对 worker 的信任边界没变**，这层只挡"存储泄露/快照"（L1）而非"worker 被攻陷"（L2）。

**CACHE_PUBKEY 的产生方式（M5，已落地）。** 最终实现：**只配一个 `CACHE_SECKEY` secret**，公钥在运行时由 `nacl.scalarMult.base(sk)` 推导（杜绝配错密钥对的运维风险）。Worker 侧的 sealed_box 不用 libsodium-wrappers——它的 ESM 构建在 wrangler/esbuild 下无法打包（`./libsodium.mjs` 解析失败）；改用纯 JS 的 **tweetnacl（X25519 + NaCl box）+ blakejs（BLAKE2b nonce）**，逐字节复刻 libsodium `crypto_box_seal`/`seal_open`。已用 cf.rs 单测 `worker_sealed_box_opens_with_dryoc` 交叉验证：Node 端 tweetnacl+blakejs 封的盒子能被 Rust 客户端 dryoc 打开，确保线缆兼容。

**轮换 `CACHE_SECKEY` 的错误处理必须明确（M3）。** 轮换后，用旧 `CACHE_PUBKEY` 封过的旧条目会 `crypto_box_seal_open` **失败**。实现必须把"解封失败"当作 **miss** 处理：惰性删除该孤儿条目、返回 `{miss:true}`，**绝不抛 500**。否则在一个还活着的 2h 窗口内轮换密钥，会导致整段窗口内缓存读取 500 风暴。轮换是主要的应急吊销手段，因此这条是硬要求。

## 4. 端到端流程

### 4.1 审批写入缓存（TTL > 0）

1. approve 页 PWA 渲染缓存时长单选：`0s(默认) / 8m / 20m / 2h`（见 §6 UI）。
2. 用户选时长并触摸 Passkey。PWA 照常派生 DEK、封给 daemon 公钥（现有逻辑不变）。
3. **新增**：若 `ttl_s > 0`，PWA 对每个 DEK 额外做 `crypto_box_seal(DEK, CACHE_PUBKEY)`，连同 `salts_b64u`、`ttl_s` 一起放进 `/api/approve` 请求。
4. `opApprove` 验签通过后（现有逻辑），把每个 `salt → {sealed_to_cache, expires_ms = now + ttl_s*1000}` 写入 DO storage（`dek:` 前缀）。审计行记录 `cache_ttl_s`。
5. TTL 由 `alarm()` 兜底清扫 + 读取时惰性过期。

> **核心不变量（M1，载荷性安全属性）：worker 无法在用户没选缓存时偷偷写缓存。** 因为只有当用户选了 `ttl_s>0` 时，PWA 才会计算并发送 `cache_sealed_deks_b64u`；TTL=0 时这块密文根本不上传。所以即便 worker 被攻陷或 CLI 被攻陷，也**造不出**一条 TTL=0 ceremony 的缓存条目——"是否缓存"这个决定权握在手机侧。这必须作为设计不变量写进代码注释与测试。

> **`ttl_s` 不进签名的真实影响要分两件事说清（M1/S2）：**
> - "能否伪造/强制缓存写入"——**不能**：见上，取决于 PWA 是否发 `cache_sealed_deks_b64u`，而那只在用户选 >0 时才发。
> - "能否篡改/拉长已选的 TTL"——**能**，由能改请求体的一方（被攻陷的 worker，或能破 TLS 的网络中间人）把 `ttl_s` 在白名单内从 0→7200 升级。服务端白名单只挡白名单外的值，挡不住白名单内升级。被攻陷 worker 本就能解密（§2 已认账），所以拉长 TTL 是次生风险；网络中间人升级 TTL 需要先破 TLS，门槛很高。
> 结论：`ttl_s` 初版**不纳入**签名承诺（纳入需让用户在看到 challenge 详情前先选 TTL，UX 倒置）；服务端对 `ttl_s` 做白名单（仅 `{0,480,1200,7200}`）。这是 UX 取舍，不是不可能。

### 4.2 解密时查缓存（免审批快路径）

客户端 `cf_decrypt`（`client.rs:515`）在走 ceremony 之前，先尝试缓存：

1. 生成临时 X25519 keypair（同现在）。
2. **新增**：`POST /api/dek-cache`（HMAC 鉴权，body：`{daemon_pubkey_b64u, salts_b64u, timestamp_ms, ppid}`）。`ppid` 由客户端上报（`libc::getppid()`），仅供审计展示、不参与绑定；IP 由 worker 从 `CF-Connecting-IP` 取，**不信任请求体里的 IP**。
3. worker → DO：先用本次请求的 `ctx = SHA-256("vt-dek-ctx-v2" || ip)` + 每个 salt 拼出键，**用批量 `storage.get([...keys])` 一次性取回（M2）**，再统一判定，避免顺序查找的时序侧信道。全部命中且未过期才算成功（IP 不符则对应键根本不存在 → 自然 miss）：
   - 用 `CACHE_SECKEY` `crypto_box_seal_open` 解出明文 DEK（解封失败按 miss 处理 + 惰性删除，见 M3）；
   - 再 `crypto_box_seal(DEK, daemon_pubkey)` 重新封给**本次客户端临时公钥**；
   - 拼成与现有 `sealed_deks` 相同的 `n*32+48` 布局返回 `{source:"cache", sealed_deks_b64u}`。
   - 任一 salt 缺失/过期 → 返回 `{miss:true}`（不区分原因、不泄露命中了哪些）。
   - **空 salts 数组 → 直接返回 `{miss:true}`（或 400），绝不进命中路径（S4）。**
   - **命中写审计（最终：仅命中）：** 命中时在统一审计表写一行（op_kind='cache', status='approved'，含 IP/ppid/salt 数）——这是"被免审批取走 DEK"的痕迹。**未命中不写审计**（用户决定：未命中是常规回退，其触发的 ceremony 本身已被审计），仅写 CF 日志 `cache.miss`。
4. 客户端命中：直接 `open_sealed_deks`（复用 `cf.rs:370`），**跳过 binding 校验**（缓存路径无 PWA、无 binding_tag）。**必须用显式判别字段防状态混淆（M5/S5）**：响应带 `source:"cache"`，Rust 客户端在跳过 `verify_binding` 前断言该字段；普通 ceremony 响应缺这块字段则照常要求 binding。绝不能让某条路径误把另一条的响应当自己处理。
5. 客户端未命中：原样走现有 ceremony（`get_deks`）。

> **不加单独的 no-cache 开关（用户决定）：** TTL=0 即"不缓存"——只要从不选 >0 的时长，缓存永远是空的，每次都走手机审批。无需 `--no-cache`/`VT_DEK_CACHE`。若曾选过 >0 又想立刻恢复强制审批，用审计页的"清空缓存"按钮（§5 S3）或等 TTL 到期。

## 5. 代码改动清单（按文件）

### Worker（TypeScript）

- `src/types.ts`
  - `ApproveRequest` 增加可选 `cache_ttl_s?: number`、`cache_sealed_deks_b64u?: string[]`（每个 salt 一项，封给 CACHE_PUBKEY）。
  - `ApprovePageData` 增加 `cache_options_s: number[]`（供 PWA 渲染按钮）与 `cache_pubkey_b64u`。
  - 新增 `DekCacheRequest`（`{daemon_pubkey_b64u, salts_b64u, timestamp_ms, ppid}`）/ `DekCacheResponse`（`{source:"cache", sealed_deks_b64u}` 或 `{miss:true}`）、DO op 类型。
  - `ChallengeMeta` / `ChallengeRequest.meta` 增加数字 `ppid`（与现有 `ppid_cmd` 并存）。
  - `Env` 增加 `CACHE_SECKEY` + `CACHE_PUBKEY`（两个 secret，M5）；`AuditRow` 增加 `cache_ttl_s`，并新增缓存读取审计列/表。
- `src/index.ts`
  - `buildApprovePage` / `opPageData` 注入 `cache_options_s` 与 `cache_pubkey_b64u`。
  - 新增 `POST /api/dek-cache`（HMAC 鉴权，复用 `/api/challenge` 的 HMAC 校验逻辑；含 replay window），转发 DO `op/dek-cache`。
  - `/api/approve` 转发时透传新字段。
- `src/do_account.ts`
  - `opApprove`：验签通过后，若 `cache_ttl_s>0` 且在白名单，写入 `dek:{salt}` 条目；审计写 `cache_ttl_s`。
  - 新增 `opDekCache`：查/解/重封逻辑（见 §4.2）。命中要恒定时间地"全有或全无"，miss 不区分原因。
  - `alarm()`：增加 `dek:` 前缀的过期清扫。
  - 审计表加列 `cache_ttl_s`（沿用现有 drop/rebuild 迁移策略）。
  - 新增 `CACHE_PUBKEY` 的来源：可由 `CACHE_SECKEY` 在 DO 构造时推导公钥，或单独配 `CACHE_PUBKEY` 环境变量。建议只配 `CACHE_SECKEY`，公钥用 `crypto_scalarmult_base` 推导（需在 worker 侧确认 libsodium/Web Crypto 可用，X25519 base point 乘法）。
- `pwa/approve.js`
  - 渲染缓存时长单选，默认 0。
  - `runApprove` 读取所选 `ttl_s`；若 >0，对每个 DEK 额外 `crypto_box_seal(dek, cache_pubkey)`，随 `/api/approve` 提交。
  - **注意 DEK 清零时序**：现在 DEK 在封给 daemon 后立即 `deks.fill(0)`（`approve.js:141`）；缓存封装必须在清零之前完成。
- `pwa/approve.css`：缓存按钮组样式。
- `pwa/admin/audit.js` + 审计页：展示 `cache_ttl_s` 列、展示缓存命中读取记录（M4）；**"立即清空 DEK 缓存"按钮为一等功能而非可选（S3）**——既然支持 2h 窗口，必须有一条快速吊销路径：批量删除所有 `dek:*` 键、走 Cloudflare Access 鉴权、操作本身入审计。

### 客户端（Rust）

- `src/cf.rs`
  - 新增 `try_cache(config, salts, daemon_pk, ppid) -> Result<Option<Vec<DEK>>>`：POST `/api/dek-cache`，命中（响应 `source=="cache"`）则 `open_sealed_deks`（cache 模式，**跳过 binding**），miss 返回 `None`。用 `source` 判别字段防状态混淆（S5）。
  - 上报数字 `ppid`（`collect_client_meta` 增加 `ppid`，或 `try_cache` 现取 `libc::getppid()`）。
  - 调用方先 `try_cache`，miss 再走 ceremony；ephemeral keypair 生成提取复用。
- `src/client.rs`
  - `cf_decrypt`：先 `try_cache`，命中直接用；miss 回退 `get_deks`。**不加 no-cache 开关。**
- 文档：更新 `CLAUDE.md` 顶部"No master_key cache"表述，明确缓存是 opt-in、有窗口期、绑定 IP（仅）、削弱了哪条保证。

## 6. approve 页 UI

在 `#actions` 上方加一组缓存时长选择（单选，默认"不缓存"）：

```
缓存解密授权（默认关闭）
( ) 不缓存   ( ) 8 分钟   ( ) 20 分钟   ( ) 2 小时
```

- 文案需明确告知风险：例如"选择后，该时长内本机对这些记录的解密将免手机审批"。
- 默认选中"不缓存"，与现状完全一致。
- 时长选项由 `cache_options_s` 下发，便于后续调整，不硬编码在 PWA。

## 7. 备选方案

- **备选 A（更安全的服务端缓存）**：不缓存 DEK，而是缓存"短期免审批授权票据"，DEK 仍每次由手机派生——但这要求手机在场，与"免手机"诉求矛盾，不成立。
- **备选 B（客户端本地缓存）**：DEK 解出后在客户端进程/磁盘按 TTL 缓存。优点：worker 仍永不持明文 DEK，安全模型几乎不变。缺点：(1) 跨独立进程要落盘，等于在被保护主机上存明文 DEK，反而更危险；(2) 与"服务端 KV"诉求不符。**若 §2 的取舍不可接受，应回到这条并重新对齐需求。**
- **存储用 KV 而非 DO**：可行（KV 原生 `expirationTtl`），但放弃强一致与统一 alarm 清扫，且多一套绑定。不推荐。

## 8. 威胁模型小结

- **token 被偷到另一台机器（远程外泄）**：**被 IP 绑定拦死**——攻击者的出口 IP 不同，缓存键 ctx 不同，一律 miss，必须重新走手机审批。这是 IP 绑定带来的最实在收益（也是唯一的硬边界）。
- **服务器在缓存窗口内被本机攻陷**：能读 token + 同一出口 IP 的本机攻击者，可对已缓存 salt 免审批解密。**注：曾经的 PPID 绑定已移除**（见 §2.5：它可伪造又不稳定，从未真正收窄本机攻击面）。缓解：默认 0、短 TTL、随时轮换 `CACHE_SECKEY` 清空缓存、审计记录每次审批 `cache_ttl_s` 与每次缓存读取。
- **DO storage / 备份泄露（无 CACHE_SECKEY）**：拿不到明文 DEK（§3 纵深防御）。
- **网络 MITM**：TLS + sealed_box（封给发起方临时公钥）保证只有发起方能解开下发。
- **被篡改的 TTL**：worker 端对 `ttl_s` 做白名单校验。
- **审计可见性**：每次审批记录 `cache_ttl_s`，可追溯"谁在何时开了多长的窗口"。

## 9. codex-expert 审查结论（已并入上文）

**必须在编码前落实（M1–M5）：**
- M1：把"worker 无法在 TTL=0 时偷偷写缓存（决定权在手机侧）"作为设计不变量，写进代码注释 + 测试（§4.1）。
- M2：`opDekCache` 用批量 `storage.get([keys])` 取回再判定，避免时序侧信道（§4.2）。
- M3：CACHE_SECKEY 轮换后旧条目解封失败必须当 miss + 惰性删除，绝不 500（§3）。
- M4：缓存命中写审计行（时间/IP/salt 数）。落地时按用户意见**只记命中**（未命中不入表，仅 CF 日志）。
- M5：最终用**单一 `CACHE_SECKEY`**，公钥运行时由 `nacl.scalarMult.base` 推导（libsodium-wrappers 在 esbuild 下打包失败，改用 tweetnacl+blakejs）。

**应当落实（S1–S5）：** 抬高并分层 `VT_PASSKEY_TOKEN` 威胁描述（S1）；讲清 ttl_s 的"能否强制缓存 vs 能否拉长 TTL"两件事（S2）；清空缓存按钮设为一等功能（S3）；空 salts 显式拒绝（S4）；Rust 客户端用 `source:"cache"` 判别字段防状态混淆（S5）。

**可选（N1–N5）：** 轮换后旧条目惰性失效说明（N1）；DEK 清零顺序写成代码级注释不变量（N2）；说明新端点 replay 语义同 /api/challenge——时间窗内可重放但下发同一份 DEK、TLS 已覆盖（N3）；建议 `VT_PASSKEY_TOKEN` 定期轮换（N4）；文档建议 cron/无人值守脚本默认 `VT_DEK_CACHE=0` 保留双因子（N5）。

## 10. 已确认的决策（用户）

1. ✅ 接受 §2 核心安全取舍。
2. ✅ 保留详细审计（审批 `cache_ttl_s` + 每次缓存读取 hit/miss）。
3. ✅ 不加单独 no-cache 开关，TTL=0 即不缓存。
4. ✅ 缓存绑定 IP（最初为 IP+PPID，**后续移除 PPID**，见 §2.5）；IP 不符即不走缓存，回退手机审批。
5. 待定（不阻塞）：时长是否就 `0/8m/20m/2h`、是否要全局最大 TTL 上限。

## 11. 最终实现状态（权威，与上文计划如有出入以此为准）

### 密码学 / 存储
- **单一 secret `CACHE_SECKEY`**（32 字节 X25519，b64u）。公钥运行时由 `nacl.scalarMult.base(sk)` 推导，无需配第二个 secret。未配置 → 缓存全程禁用、审批页不显示时长选项。
- Worker 用 **tweetnacl（NaCl box / X25519）+ blakejs（BLAKE2b nonce）** 复刻 libsodium `crypto_box_seal`/`seal_open`（`cf-worker/src/cache_crypto.ts`）。原因：`libsodium-wrappers` 的 ESM 包在 wrangler/esbuild 下无法解析 `./libsodium.mjs`。线缆兼容由 `src/cf.rs` 单测 `worker_sealed_box_opens_with_dryoc` 交叉验证（Node 封盒 → Rust dryoc 开盒）。
- 缓存条目 `dek:{ctx}:{salt_b64u}`，`ctx = b64u(SHA-256("vt-dek-ctx-v2" || ip_utf8))`（**仅 IP**；tag v1→v2，旧版含 `0x00 || u32le(ppid)`，PPID 已移除，见 §2.5）；条目仍存 `sealed_to_cache_b64u, expires_ms, origin_token_id, ip, ppid, ppid_cmd`（`ppid`/`ppid_cmd` 仅审计）。读取批量 `storage.get`、惰性过期、解封失败当 miss。

### IP 一致性修复（关键）
- 客户端 `src/cf.rs` 的两条 worker POST（`/api/challenge` 写、`/api/dek-cache` 读）统一走 `cf_post()`：**固定 IPv4 出口**，连接失败再回退无约束（IPv6-only 主机）。否则双栈主机在两次独立进程间漂移 IPv4/IPv6 → `CF-Connecting-IP` 不同 → ctx 不同 → 永久不命中。

### 审计（统一一张表，无独立 cache_audit）
- DEK 缓存事件就是 `audit` 表的行：`op_kind='cache'`，`status ∈ {approved=命中, write_failed=授予了TTL但写入失败}`。命中行带完整 meta（host/user/command/…，与 ceremony 行同样丰富）。审计表新增数字 `ppid` 列（ceremony 行也填）。
- **只记有取证价值的事件**：命中（免审批取走 DEK）、写入失败（配置问题）。**未命中**（常规回退，ceremony 自身已审计）与**缓存清除**（管理员主动操作、不涉密钥泄露）都**不入审计**，仅写 CF 日志（`cache.miss` / `cache.cleared` / `cache.cleared_by_origin`）。授予缓存的审批行通过 `cache_ttl_s` 列携带 TTL。
- 迁移：构造器对老库 `ALTER ADD cache_ttl_s` / `ALTER ADD ppid`，并 `DROP TABLE IF EXISTS cache_audit`（清掉早期分支的独立表）。

### 命中实时通知（Pushover / Slack）
- 缓存命中意味着「**没有手机在环**就取走了 DEK」，所以除了入审计表，`opDekCache` 在命中后通过 `notifyCacheHit()` 复用审批用的同一批 opt-in 通道（`PUSHOVER_JSON` / `SLACK_JSON`），给操作者一条实时「已免审批解密」提示。标题与审批请求区分（`VT 缓存命中(免审批)`），正文带 host/user/cmd/ip/记录数，**无审批链接**（命中无可点的动作）。
- **尽力而为、绝不阻塞**：通过 DO 的 `this.ctx.waitUntil()` fire-and-forget 触发，投递失败（或未配置任何通道）都不影响 DEK 响应；失败仅记 `notify.cachehit_failed` CF 日志。审计行才是持久记录。
- 未配置通道 ≠ 警告（与审批不同）：命中通知是纯增益信号，无通道时静默。

### 管理界面（已删除独立「DEK 缓存」tab，全部并入「审计」页）
- 「缓存」列：有效缓存显示 TTL（如 `8m`）、过期显示灰色「过期」、从未授予显示 `—`。
- 「操作」列：对仍有效的、授予过缓存的审批行显示「清除缓存」按钮（按 `origin_token_id` 删除该次审批写入的所有条目）。
- 过滤栏：「带缓存」按钮 / 状态下拉「带缓存的记录」= `cache_ttl_s IS NOT NULL`（只列授予过缓存的审批，不含命中/清除事件行）。
- 过滤栏右侧：「清除所有 DEK 缓存」「清空全部审计」两个危险按钮。
- 详情对话框：展示「审批链接」`/a/{token_id}`（token_id 即完整 approve_token），点击新标签页打开。
- 端点：`GET /<seg>/api/audit`、`POST /<seg>/api/cache-clear-origin`、`POST /<seg>/api/clear-cache`、`POST /<seg>/api/clear-audit`（均 Cloudflare-Access 网关）。

### 客户端
- `vt read`（`cf_decrypt`）解密前先 `cf::try_cache(config, salts, current_ppid())`：命中（响应 `source=="cache"`，**跳过 binding**）直接解密;否则回退 `get_deks` 手机审批。无 `--no-cache` 开关（TTL=0 即不缓存）。
- ⚠️ 客户端改了 `cf.rs`，部署缓存功能必须**重新编译并安装 `vt` 二进制**（旧二进制无 `try_cache`、走不到缓存快路径）。`ppid` 仍随请求上报但仅供审计,不再影响命中。
- ⚠️ **绑定 ctx 从 v1(含 ppid)改为 v2(仅 IP)** → 部署新 worker 后,旧 worker 写入的缓存条目一律 miss(≤2h TTL 内过渡几次后自然消失);客户端无需改动即可受益(ppid 字段被忽略)。

### 部署
```bash
# worker（含 PWA 资源 + 审计/缓存接口）
cd cf-worker && wrangler secret put CACHE_SECKEY   # 32B: head -c32 /dev/urandom|base64|tr +/ -_|tr -d =
just deploy-worker
# 客户端（musl-static on Linux, native on macOS → ~/.local/bin/vt）
just install
```

### 验证缓存命中
同一交互式 shell 内：`vt read 'vt://…'` → 审批选 8 分钟 → 8 分钟内再 `vt read 'vt://…'` → 免手机直接解密。审计页出现「DEK缓存自动审批」。
```
