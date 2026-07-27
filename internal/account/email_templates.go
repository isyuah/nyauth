package account

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"
)

type accountActionEmailDefinition struct {
	Path        string
	Subject     string
	Preheader   string
	Heading     string
	Intro       string
	ButtonLabel string
}

type accountActionEmailTemplateData struct {
	Title       string
	Preheader   string
	Heading     string
	Username    string
	Intro       string
	ButtonLabel string
	Link        string
	Expiry      string
}

var accountActionHTMLTemplate = template.Must(template.New("account-action-email").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>{{.Title}}</title>
</head>
<body style="margin:0;padding:0;background:#f5f3ff;color:#252235;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',Arial,sans-serif;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">{{.Preheader}}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;background:#f5f3ff;">
    <tr>
      <td align="center" style="padding:32px 16px;">
        <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:600px;background:#ffffff;border:1px solid #e7e3f2;border-radius:16px;box-shadow:0 8px 24px rgba(56,42,90,0.08);">
          <tr>
            <td style="padding:24px 32px;border-bottom:1px solid #eeeaf6;">
              <span style="font-size:22px;font-weight:750;letter-spacing:-0.02em;color:#6d4aff;">Nyauth</span>
              <span style="margin-left:10px;font-size:13px;color:#77718a;">账户安全</span>
            </td>
          </tr>
          <tr>
            <td style="padding:32px;">
              <h1 style="margin:0 0 20px;font-size:26px;line-height:1.3;color:#252235;">{{.Heading}}</h1>
              <p style="margin:0 0 14px;font-size:16px;line-height:1.7;color:#4c475d;">你好，<strong style="color:#252235;">{{.Username}}</strong>：</p>
              <p style="margin:0 0 24px;font-size:16px;line-height:1.7;color:#4c475d;">{{.Intro}}</p>
              <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:0 0 24px;">
                <tr>
                  <td align="center" bgcolor="#6d4aff" style="border-radius:10px;">
                    <a href="{{.Link}}" style="display:inline-block;padding:13px 22px;font-size:16px;font-weight:700;line-height:1;color:#ffffff;text-decoration:none;border-radius:10px;">{{.ButtonLabel}}</a>
                  </td>
                </tr>
              </table>
              <p style="margin:0 0 8px;font-size:13px;line-height:1.6;color:#77718a;">如果按钮无法打开，请复制下面的完整链接到浏览器：</p>
              <p style="margin:0 0 20px;padding:12px 14px;background:#f8f7fc;border:1px solid #eeeaf6;border-radius:8px;font-size:13px;line-height:1.6;word-break:break-all;">
                <a href="{{.Link}}" style="color:#5b3fe5;text-decoration:underline;">{{.Link}}</a>
              </p>
              <p style="margin:0 0 20px;font-size:14px;line-height:1.7;color:#625d73;">{{.Expiry}}</p>
              <div style="padding-top:20px;border-top:1px solid #eeeaf6;">
                <p style="margin:0 0 8px;font-size:13px;line-height:1.7;color:#77718a;">如果你没有发起此操作，可以忽略这封邮件。请不要转发邮件或向任何人分享上面的链接。</p>
                <p style="margin:0;font-size:12px;line-height:1.7;color:#9892a8;">这是一封由 Nyauth 自动发送的安全邮件，请勿直接回复。</p>
              </div>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>`))

func accountActionEmailDefinitionFor(action Action, ttlText string) (accountActionEmailDefinition, error) {
	switch action {
	case ActionPasswordReset:
		return accountActionEmailDefinition{
			Path:        "/reset-password",
			Subject:     "[Nyauth] 重置你的密码",
			Preheader:   "请在 " + ttlText + "内完成 Nyauth 密码重置。",
			Heading:     "重置你的密码",
			Intro:       "我们收到了为你的 Nyauth 账户重置密码的请求。请使用下面的安全链接继续。",
			ButtonLabel: "重置密码",
		}, nil
	case ActionEmailVerification:
		return accountActionEmailDefinition{
			Path:        "/verify-email",
			Subject:     "[Nyauth] 验证你的邮箱地址",
			Preheader:   "请在 " + ttlText + "内验证你的 Nyauth 邮箱地址。",
			Heading:     "验证你的邮箱地址",
			Intro:       "请确认此邮箱地址属于你的 Nyauth 账户。完成验证后，你就可以继续使用需要已验证邮箱的功能。",
			ButtonLabel: "验证邮箱",
		}, nil
	case ActionEmailChange:
		return accountActionEmailDefinition{
			Path:        "/change-email",
			Subject:     "[Nyauth] 确认邮箱地址变更",
			Preheader:   "请在 " + ttlText + "内确认 Nyauth 邮箱地址变更。",
			Heading:     "确认新的邮箱地址",
			Intro:       "请确认将此邮箱地址绑定到你的 Nyauth 账户。确认后，后续账户邮件将发送到这个地址。",
			ButtonLabel: "确认邮箱变更",
		}, nil
	default:
		return accountActionEmailDefinition{}, fmt.Errorf("unsupported account action %q", action)
	}
}

func renderAccountActionEmail(
	recipient, username, link string,
	ttlText string,
	definition accountActionEmailDefinition,
) (EmailMessage, error) {
	expiry := "此安全链接将在 " + ttlText + "后失效，并且只能使用一次。"
	data := accountActionEmailTemplateData{
		Title: definition.Subject, Preheader: definition.Preheader,
		Heading: definition.Heading, Username: username, Intro: definition.Intro,
		ButtonLabel: definition.ButtonLabel, Link: link, Expiry: expiry,
	}
	var htmlBody bytes.Buffer
	if err := accountActionHTMLTemplate.Execute(&htmlBody, data); err != nil {
		return EmailMessage{}, fmt.Errorf("rendering account action email: %w", err)
	}
	textBody := strings.Join([]string{
		"Nyauth 账户安全",
		"",
		definition.Heading,
		"",
		"你好，" + username + "：",
		"",
		definition.Intro,
		"",
		definition.ButtonLabel + "：",
		link,
		"",
		expiry,
		"",
		"如果你没有发起此操作，可以忽略这封邮件。请不要转发邮件或向任何人分享上面的链接。",
		"",
		"这是一封由 Nyauth 自动发送的安全邮件，请勿直接回复。",
	}, "\n")
	return EmailMessage{
		To: recipient, Subject: definition.Subject,
		TextBody: textBody, HTMLBody: htmlBody.String(),
	}, nil
}
