# Slack App（Bot token）通知通道

第四个可选、独立的通知通道。与 `docs/feishu.md` 的能力一致（**@相关人** + **审批后回改原消息**），只是走 Slack 而非飞书。它与项目里已有的 **Slack（Incoming Webhook）** 通道是两回事：

- **Slack（webhook，`SLACK_JSON`）**：单向通知，只能发一条新消息，Slack 只回 `ok`、不返回消息 `ts`，因此**无法**在审批后回改，也不 @ 人。
- **Slack App（bot token，`SLACK_APP_JSON`，本通道）**：用自建应用的 Bot User OAuth Token 走 Web API（`chat.postMessage` / `chat.update`），拿到 `ts` 后即可 **@人** 并 **回改原消息**。

## 能力对比

| 能力 | Pushover | Slack（webhook） | Slack App（bot） | 飞书 / Lark |
|---|---|---|---|---|
| 审批实时通知 | ✅ | ✅ | ✅ | ✅ |
| @ 相关人 | ❌ | ❌ | ✅ | ✅ |
| **决策后回改原消息**（✅/❌/⌛）| ❌ | ❌ | ✅ | ✅ |
| 传输方式 | 单向 API | 单向 Incoming Webhook | Bot Web API | 自建应用 Bot API |

> 与飞书不同，Slack 的 Bot token 是**长期有效**的（不需要像飞书那样换 `tenant_access_token`），所以本通道没有 token 缓存。

配置产物是一个 Worker secret `SLACK_APP_JSON`，在 Access 网关保护的 admin「推送渠道」页（`/<ADMIN_SEG>/channels`）里生成，再 `wrangler secret put SLACK_APP_JSON` 部署。缺省 / 非法 → 通道停用。

---

## 一、创建 Slack App 并拿 Bot Token

1. 打开 [api.slack.com/apps](https://api.slack.com/apps) → **Create New App** → **From scratch**，填名字（如 `vt-approval`）并选择目标 workspace。
2. 左侧 **OAuth & Permissions** → **Scopes** → **Bot Token Scopes** 里添加：
   - `chat:write`（发消息 + 更新自己发的消息，本通道核心权限）。
   - 若你想用**频道名**（而不是频道 ID）发送，或让 Bot 不必先被拉进公开频道就能发，额外加 `chat:write.public`。推荐仍然用频道 ID + 把 Bot 拉进群，权限更小。
3. 同页顶部 **Install to Workspace** → 授权，得到 **Bot User OAuth Token**（形如 `xoxb-…`）——这是机器人凭证，**等同密码**，勿泄露、勿进 git。

> 最小化原则：只授予 `chat:write`（必要时 `chat:write.public`），并且只把 Bot 拉进**目标那一个频道**。Token 一旦泄露，攻击者可冒充 Bot 在其可达的频道里发/改消息——把爆炸半径限制在这一个频道。

## 二、把 Bot 拉进目标频道

在要接收审批通知的频道里：`/invite @你的App名` （或频道设置 → Integrations → Add apps）。私聊发送则把 `channel` 填成该用户的 member ID（`U…`）或 DM ID（`D…`），并确保 Bot 有权私聊对方。

## 三、取频道 ID 与要 @ 的人的成员 ID

- **频道 ID（`C…`，推荐作为 `channel`）**：在 Slack 桌面端右键频道 → **View channel details**，弹窗底部即有 `Channel ID`；或频道链接末段。
- **成员 ID（`U…`，用于 @ 人）**：点开某人资料 → **⋮ (More)** → **Copy member ID**。

## 四、生成并部署 `SLACK_APP_JSON`

进入 admin「推送渠道」页，打开「Slack App」开关，填写：

| 字段 | 说明 |
|---|---|
| `bot_token` | Bot User OAuth Token（`xoxb-…`） |
| `channel` | 目标频道 ID（`C…`），或私聊 `D…`/用户 `U…` |
| `mention` | 审批时 @ 的人的成员 ID（`U…`），每行一个，可留空 |

点「生成」得到 JSON，复制并部署：

```bash
wrangler secret put SLACK_APP_JSON
# 粘贴生成的 JSON
wrangler deploy    # 全部 secret 设好后统一 deploy 生效
```

生成的 JSON 形如：

```jsonc
{
  "bot_token": "xoxb-xxxxxxxx",
  "channel": "C0123456789",
  "mention": ["U01ABCDEF", "U02GHIJKL"]
}
```

---

## 行为

| 事件 | 消息 |
|---|---|
| 收到审批请求 | `⏳ 待审批`，橙色边条，`@` mention 列表里的人，带「去审批」按钮（跳转到 `/a/<token>` 审批页） |
| 手机端批准 | 回改为 `✅ 已批准`，绿色，去掉 @/按钮，显示**批准所用的 Passkey 标签**与用时 |
| 手机端拒绝 | 回改为 `❌ 已拒绝`，红色 |
| 5 分钟超时未处理 | 回改为 `⌛ 已过期`，灰色 |
| 免审批（DEK 缓存命中）| 单独一条精简消息（一两行、不 @、无按钮、不回改），仅作「已自动解密」的实时告知 |

「去审批」按钮是**纯 URL 跳转链接**（不是交互 action），因此 Worker **不需要**配置任何 Request URL / 交互回调端点。

## 安全模型

- **Bot Token = 机器人凭证**：作为 Worker secret 存储，**永不写日志、永不回显到 admin 页**（同 Pushover/Slack/飞书）。泄露后攻击者可冒充 Bot 在其可达频道收发/编辑消息，范围受 scope 与「只拉进目标频道」限制。
- **审批 URL 不是承载凭证**：消息里的 `/a/<token>` 即使被频道里任何人点开，真正的「批准」仍需**已注册的 Passkey + PRF**。频道成员身份 =「谁能看到 / 发起」，不等于「谁能批准」。这与 Slack webhook / Pushover / 飞书的信任模型一致。
- **标题只出现一次 + 每字段一行**：标题（含状态 emoji ✅/❌/⏳/⌛）只放在消息顶层 `text`，不再额外发 `header` block（否则会在带色附件里把标题「引用」重复一遍）；状态另由附件左侧色条表示。上下文（who/pwd/cmd/ssh/ip/reason）按 `\n` **每字段独占一行**渲染。
- **上下文按 `mrkdwn`（转义后）渲染**：who/pwd/cmd/ssh/ip/reason 都是调用方（CLI）上报的。之所以用 `mrkdwn` 而非 `plain_text`，是因为 Slack 的 `plain_text` section 会把内嵌 `\n` **压成空格**，导致所有字段挤成一行（本次修复的问题）。每个上下文值先经 `escapeMrkdwn()` 转义 `& < >`，因此恶意 CLI 仍无法注入链接或伪造「像 Worker 权威行」的内容（与 `plain_text` 同等保证）。只有 @-mention 行是 mrkdwn（`<@id>` 必需），其 id 在 `parseSlackAppConfig` 里做了字符校验，无法逃逸出 mention 标签。
- **SSRF 收口**：API 域名硬编码为 `slack.com`，绝不取用户填的任意 URL，因此坏配置无法把本通道变成 SSRF 原语（同 Slack webhook 绑定 `hooks.slack.com`、飞书绑定 `base` 枚举）。
- **不阻塞审批仪式**：所有 Slack 调用都 best-effort、6s 超时、经 `waitUntil` 异步触发；任何失败只记日志，绝不影响 WebAuthn 仪式或 DEK 下发。

## 已知取舍 / gap（与飞书一致）

- **消息编辑失败不重试**：回改是 best-effort。若 `chat.update` 失败，消息可能停留在 `⏳ 待审批`，但审批本身已正确完成（以审计表为准）。
- **发送响应丢失 → 消息卡 ⏳**：审批消息异步发送（不阻塞仪式），6s 超时。若消息已发出但响应超时/丢失，Worker 拿不到 `ts`，之后就无法回改，消息停在 `⏳`。审批本身不受影响。
- **发送与决策竞态（罕见、仅影响观感）**：若审批人在消息 `ts` 落库前就完成了决策，`opApprove`/`opReject` 会从最新存储合并回 `slackapp` 引用（不再因覆盖而永久卡 ⏳）；但补发路径拿不到「批准所用 Passkey」标签，仅显示用时。
- **免审批精简是全通道的**：Pushover/Slack/Slack App/飞书的缓存命中文案都精简（首行摘要 + `pwd` + `cmd`），不 @ 人。
