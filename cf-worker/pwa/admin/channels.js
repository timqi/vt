'use strict';

// Pure client-side notification-secret generator. Each channel is a card with
// an enable switch; flipping it on expands the card to reveal its guidance and
// fields. "生成" emits the JSON secret(s) for the enabled channels to deploy via
// `wrangler secret put`. Nothing is POSTed anywhere; existing secret plaintext
// is never sent to the page (only set/not-set booleans, for the badge + the
// "leave unchanged" behaviour).

(function () {
  var data = vt.bootData() || {};

  var chkPushover = document.getElementById('chk-pushover');
  var chkSlack = document.getElementById('chk-slack');
  var chkSlackApp = document.getElementById('chk-slackapp');
  var chkFeishu = document.getElementById('chk-feishu');
  var poBody = document.getElementById('pushover-body');
  var slBody = document.getElementById('slack-body');
  var saBody = document.getElementById('slackapp-body');
  var fsBody = document.getElementById('feishu-body');
  var out = document.getElementById('output-section');

  function bind(chk, body) {
    chk.addEventListener('change', function () { body.hidden = !chk.checked; });
  }
  bind(chkPushover, poBody);
  bind(chkSlack, slBody);
  bind(chkSlackApp, saBody);
  bind(chkFeishu, fsBody);

  // ── Output rendering (DOM only — values are never interpolated into HTML) ──

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function copyButton(getText) {
    var b = el('button', 'ghost', '复制');
    b.type = 'button';
    b.addEventListener('click', function () {
      navigator.clipboard.writeText(getText()).then(
        function () { vt.setStatus('已复制到剪贴板', 'ok'); },
        function () { vt.setStatus('复制失败，请手动选择文本', 'error'); }
      );
    });
    return b;
  }

  // One result card: channel title + copy, the JSON in a readonly textarea, and
  // the exact `wrangler secret put` command.
  function resultCard(title, json, secretName) {
    var card = el('section', 'card');
    var head = el('div', 'card-head');
    head.appendChild(el('h2', null, title));
    var ta = el('textarea');
    ta.readOnly = true;
    ta.rows = json.split('\n').length + 1;
    ta.value = json;
    head.appendChild(copyButton(function () { return ta.value; }));
    card.appendChild(head);
    card.appendChild(ta);
    var cmd = el('pre', 'cmd');
    cmd.appendChild(el('code', null, 'wrangler secret put ' + secretName));
    card.appendChild(cmd);
    return card;
  }

  function disableHint(channel, secretName) {
    var p = el('p', 'warn', channel + ' 当前已配置但已关闭。如要停用该渠道，请执行： ');
    p.appendChild(el('code', null, 'wrangler secret delete ' + secretName));
    return p;
  }

  function render(cards, notes) {
    out.innerHTML = '';
    notes.forEach(function (n) { out.appendChild(n); });
    cards.forEach(function (c) { out.appendChild(c); });
    if (cards.length) {
      out.appendChild(el('p', 'hint',
        '复制后逐个 wrangler secret put，全部设置完再执行 wrangler deploy 生效。'));
    }
    out.hidden = (cards.length === 0 && notes.length === 0);
  }

  // ── Generate ────────────────────────────────────────────────────────────────

  function val(id) { return (document.getElementById(id).value || '').trim(); }

  document.getElementById('run').addEventListener('click', function () {
    var cards = [];
    var notes = [];
    try {
      // Pushover
      if (chkPushover.checked) {
        var appToken = val('po-app');
        var userKey = val('po-user');
        if (appToken || userKey) {
          if (!appToken || !userKey) throw new Error('Pushover：app_token 和 user_key 需同时填写');
          cards.push(resultCard('Pushover',
            JSON.stringify({ app_token: appToken, user_key: userKey }, null, 2), 'PUSHOVER_JSON'));
        } else if (data.pushover_set) {
          notes.push(el('p', 'hint', 'Pushover：未填写新值，保持现有配置不变。'));
        } else {
          throw new Error('Pushover 已启用：请填写 app_token 和 user_key');
        }
      } else if (data.pushover_set) {
        notes.push(disableHint('Pushover', 'PUSHOVER_JSON'));
      }

      // Slack
      if (chkSlack.checked) {
        var webhook = val('sl-webhook');
        if (webhook) {
          if (!/^https:\/\/hooks\.slack\.com\//.test(webhook)) {
            throw new Error('Slack：webhook_url 必须是 https://hooks.slack.com/… 开头');
          }
          cards.push(resultCard('Slack',
            JSON.stringify({ webhook_url: webhook }, null, 2), 'SLACK_JSON'));
        } else if (data.slack_set) {
          notes.push(el('p', 'hint', 'Slack：未填写新值，保持现有配置不变。'));
        } else {
          throw new Error('Slack 已启用：请填写 webhook_url');
        }
      } else if (data.slack_set) {
        notes.push(disableHint('Slack', 'SLACK_JSON'));
      }

      // Slack App (Bot token)
      if (chkSlackApp.checked) {
        var botToken = val('sa-bot-token');
        var channel = val('sa-channel');
        var saMention = val('sa-mention').split(/[\s,]+/).filter(function (s) { return s; });
        if (botToken || channel) {
          if (!botToken || !channel) {
            throw new Error('Slack App：bot_token 和 channel 需同时填写');
          }
          if (/\s/.test(botToken) || /\s/.test(channel)) {
            throw new Error('Slack App：bot_token / channel 不能包含空白');
          }
          cards.push(resultCard('Slack App',
            JSON.stringify({
              bot_token: botToken,
              channel: channel,
              mention: saMention,
            }, null, 2), 'SLACK_APP_JSON'));
        } else if (data.slackapp_set) {
          notes.push(el('p', 'hint', 'Slack App：未填写新值，保持现有配置不变。'));
        } else {
          throw new Error('Slack App 已启用：请填写 bot_token 和 channel');
        }
      } else if (data.slackapp_set) {
        notes.push(disableHint('Slack App', 'SLACK_APP_JSON'));
      }

      // Feishu / Lark
      if (chkFeishu.checked) {
        var appId = val('fs-app-id');
        var appSecret = val('fs-app-secret');
        var receiveId = val('fs-receive-id');
        var receiveIdType = val('fs-receive-id-type') || 'chat_id';
        var base = val('fs-base') || 'feishu';
        var mention = val('fs-mention').split(/[\s,]+/).filter(function (s) { return s; });
        if (appId || appSecret || receiveId) {
          if (!appId || !appSecret || !receiveId) {
            throw new Error('飞书：app_id、app_secret、receive_id 需同时填写');
          }
          cards.push(resultCard('飞书 / Lark',
            JSON.stringify({
              app_id: appId,
              app_secret: appSecret,
              receive_id: receiveId,
              receive_id_type: receiveIdType,
              mention: mention,
              base: base,
            }, null, 2), 'FEISHU_JSON'));
        } else if (data.feishu_set) {
          notes.push(el('p', 'hint', '飞书：未填写新值，保持现有配置不变。'));
        } else {
          throw new Error('飞书 已启用：请填写 app_id、app_secret、receive_id');
        }
      } else if (data.feishu_set) {
        notes.push(disableHint('飞书 / Lark', 'FEISHU_JSON'));
      }

      if (!cards.length && !notes.length) {
        throw new Error('请至少启用并配置一个渠道');
      }
      render(cards, notes);
      vt.setStatus(cards.length ? '✓ 已生成，请按下方命令部署。' : '✓ 无新配置；见下方说明。', 'ok');
    } catch (e) {
      out.hidden = true;
      vt.setStatus('错误：' + ((e && e.message) ? e.message : String(e)), 'error');
    }
  });
})();
