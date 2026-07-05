# 飞书 / Lark 通知通道

第三个可选、独立的通知通道（与 Pushover、Slack 并列），但能力不同：

- **@相关人**：审批请求会 `@` 你配置的人。
- **回改卡片**：审批通过 / 拒绝 / 超时后，**编辑最初那张卡片**把结果填上（✅ 已批准 / ❌ 已拒绝 / ⌛ 已过期），而不是再发一条新消息。
- **免审批（DEK 缓存命中）通知精简**为一两行、且不 `@` 任何人。

为什么必须用「自建应用（机器人）」而不是自定义机器人 webhook：webhook 发出去拿不到 `message_id`、也不能编辑，无法满足「@人」和「回改卡片」。所以本通道走飞书开放平台的自建应用 API：换 `tenant_access_token` → `im/v1/messages` 发交互卡片拿 `message_id` → 决策后 `PATCH im/v1/messages/:id` 原地回改。

## 通道能力对比

| 能力 | Pushover | Slack | 飞书 / Lark |
|---|---|---|---|
| 审批实时通知 | ✅ | ✅ | ✅ |
| @ 相关人 | ❌ | ❌ | ✅ |
| **决策后回改原消息**（✅/❌/⌛）| ❌ | ❌ | ✅ |
| 传输方式 | 单向 API | 单向 Incoming Webhook | 自建应用 Bot API |

> **Slack 是单向通知**：用的是 Incoming Webhook，Slack 只回 `ok`、不返回消息 `ts`，因此**无法在审批通过/拒绝后编辑原消息**（Slack 本身支持 `chat.update`，但需改用 Bot token + Web API，本项目未采用）。审批结果只在审批页与审计页更新。要「@人 + 决策后回改」，用飞书 / Lark 通道。

配置产物是一个 Worker secret `FEISHU_JSON`，在 Access 网关保护的 admin「推送渠道」页（`/<ADMIN_SEG>/channels`）里生成，再 `wrangler secret put FEISHU_JSON` 部署。缺省 / 非法 → 通道停用。

---

## 一、创建自建应用

1. 打开 [飞书开放平台 · 开发者后台](https://open.feishu.cn/app)（国际版 Lark：<https://open.larksuite.com/app>）→ **创建企业自建应用**，填名称（如 `vt-approval`）与图标。
2. 记下 **App ID**（`cli_…`）和 **App Secret**——App Secret 是机器人凭证，**等同密码**，勿泄露、勿进 git。

## 二、开启机器人能力 + 授权

1. 左侧 **添加应用能力** → 开启 **机器人**。
2. 左侧 **权限管理**，添加以下最小权限（scope）：
   - `im:message`（读写消息，含更新已发送消息卡片）
   - `im:message:send_as_bot`（以机器人身份发消息）
   - 若要按 `open_id` @ 人，通常还需能拿到成员 open_id，可临时用 `contact:user.id:readonly` 或直接用「获取群成员」接口（见第四步）。
3. **版本管理与发布** → 创建版本 → 提交发布（企业内自建应用一般管理员审批后即生效）。

> 最小化原则：只授予上面的 scope，并且只把机器人拉进**目标那一个群**。App Secret 一旦泄露，攻击者可冒充机器人在其所在的群里收发、编辑消息——把爆炸半径限制在这一个群。

## 三、把机器人拉进目标群

在要接收审批通知的飞书群里：**群设置 → 群机器人 → 添加机器人 → 选择你的自建应用**。

## 四、取 `receive_id`（群 chat_id）与要 @ 的人的 `open_id`

**群 `chat_id`（推荐作为 `receive_id`，`receive_id_type=chat_id`）：**
- 最简单：调用 [获取用户/机器人所在的群列表](https://open.feishu.cn/document/server-docs/group/chat/list) `GET /open-apis/im/v1/chats`，在返回里找到目标群，`chat_id` 形如 `oc_…`。
- 或在群里让机器人收到一条消息 / 用「获取群信息」接口拿到 `chat_id`。

**要 @ 的人的 `open_id`（`ou_…`）：**
- `open_id` 是**按应用隔离**的用户标识，同一个人在不同应用下不同。
- 最直接：对目标群调用 [获取群成员列表](https://open.feishu.cn/document/server-docs/group/chat-member/get) `GET /open-apis/im/v1/chats/:chat_id/members`，返回里每个成员带 `member_id`（即该应用视角的 `open_id`）。
- 或用 [通过手机号/邮箱批量获取用户 ID](https://open.feishu.cn/document/server-docs/contact-v3/user/batch_get_id) `POST /open-apis/contact/v3/users/batch_get_id`。

> 换用私聊：`receive_id_type=open_id`、`receive_id` 填某人的 `open_id` 即可，机器人会私聊发卡片。

调 API 前先拿一个 `tenant_access_token` 测试：

```bash
curl -s https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal \
  -H 'Content-Type: application/json' \
  -d '{"app_id":"cli_xxx","app_secret":"xxx"}'
# → {"code":0,"tenant_access_token":"t-xxx","expire":7200,...}

curl -s https://open.feishu.cn/open-apis/im/v1/chats \
  -H "Authorization: Bearer t-xxx"     # 找 chat_id
```

## 五、生成并部署 `FEISHU_JSON`

进入 admin「推送渠道」页，打开「飞书 / Lark」开关，填写：

| 字段 | 说明 |
|---|---|
| `app_id` | `cli_…` |
| `app_secret` | 机器人凭证 |
| `receive_id` | 目标群 `chat_id`（`oc_…`）或私聊 `open_id`（`ou_…`） |
| `receive_id_type` | `chat_id`（默认）\| `open_id` \| `user_id` \| `email` |
| `mention` | 审批时 @ 的人的 `open_id`，每行一个，可留空 |
| `base` | `feishu`（open.feishu.cn，中国版）\| `larksuite`（open.larksuite.com，国际版 Lark） |

点「生成」得到 JSON，复制并部署：

```bash
wrangler secret put FEISHU_JSON
# 粘贴生成的 JSON
wrangler deploy    # 全部 secret 设好后统一 deploy 生效
```

生成的 JSON 形如：

```jsonc
{
  "app_id": "cli_xxx",
  "app_secret": "xxx",
  "receive_id": "oc_xxx",
  "receive_id_type": "chat_id",
  "mention": ["ou_aaa", "ou_bbb"],
  "base": "feishu"
}
```

---

## 行为

| 事件 | 卡片 |
|---|---|
| 收到审批请求 | `⏳ 待审批`，橙色抬头，`@` mention 列表里的人，带「去审批」按钮（跳转到 `/a/<token>` 审批页） |
| 手机端批准 | 回改为 `✅ 已批准`，绿色，去掉 @/按钮，显示**批准所用的 Passkey 标签**与用时 |
| 手机端拒绝 | 回改为 `❌ 已拒绝`，红色 |
| 5 分钟超时未处理 | 回改为 `⌛ 已过期`，灰色 |
| 免审批（DEK 缓存命中）| 单独一条精简卡片（一两行、不 @、无按钮、不回改），仅作「已自动解密」的实时告知 |

「去审批」按钮是**纯跳转链接**（不是卡片回调 action），因此 Worker **不需要**任何新的入站回调端点。

## 安全模型

- **App Secret = 机器人凭证**：作为 Worker secret 存储，**永不写日志、永不回显到 admin 页**（同 Pushover/Slack 的处理）。泄露后攻击者可冒充机器人在其所在群收发/编辑消息，范围受 scope 与「只拉进目标群」限制。
- **审批 URL 不是承载凭证**：卡片里的 `/a/<token>` 即使被群里任何人点开，真正的「批准」仍需**已注册的 Passkey + PRF**。群成员身份 = 「谁能看到 / 发起」，不等于「谁能批准」。这与 Slack/Pushover 的信任模型一致。
- **`mention` 里的 open_id** 不是机密（应用维度的用户标识），但同样随 secret 存储。
- **SSRF 收口**：API 域名只由 `base` 枚举决定（`feishu`/`larksuite`），绝不取用户填的任意 URL，因此坏配置无法把本通道变成 SSRF 原语（同 Slack 绑定 `hooks.slack.com`）。
- **不阻塞审批仪式**：所有飞书调用都 best-effort、6s 超时、经 `waitUntil` 异步触发；任何失败只记日志，绝不影响 WebAuthn 仪式或 DEK 下发。

## 已知取舍 / gap

- **卡片编辑失败不重试**：回改是 best-effort。若 `PATCH` 失败，卡片可能停留在 `⏳ 待审批`，但审批本身已正确完成（以审计表为准）。
- **发送响应丢失 → 卡片卡 ⏳**：审批卡异步发送（不阻塞仪式），6s 超时。若卡片已发出但响应超时/丢失，Worker 拿不到 `message_id`，之后就无法回改，卡片停在 `⏳`。审批本身不受影响（以审计表为准）。
- **发送与决策竞态（罕见、仅影响观感）**：若审批人在卡片 `message_id` 落库前就完成了决策，`opApprove`/`opReject` 会从最新存储合并回 `message_id`（不再因覆盖而永久卡 ⏳）；但补发路径拿不到「批准所用 Passkey」标签，仅显示用时，且极端情况下可能对已决策的请求多 @ 一次。
- **免审批精简是全通道的**：Pushover/Slack/飞书的缓存命中文案都精简（首行摘要 + `pwd` + `cmd`），不 @ 人。
