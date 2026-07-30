package account

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	EmailVariableSiteName = "site_name"
	EmailVariableUsername = "username"
	EmailVariableTTL      = "ttl"
	EmailVariableRole     = "role"
	EmailVariableStatus   = "status"
	EmailVariableProvider = "provider"
)

const (
	maxEmailSubjectRunes     = 160
	maxEmailHeadingRunes     = 120
	maxEmailBodyRunes        = 2400
	maxEmailButtonLabelRunes = 48
	maxEmailFooterRunes      = 600
)

type EmailTemplateContent struct {
	Subject     string `json:"subject"`
	Heading     string `json:"heading"`
	Body        string `json:"body"`
	ButtonLabel string `json:"button_label,omitempty"`
}

type EmailTemplateSettings struct {
	Footer    string                          `json:"footer"`
	Templates map[string]EmailTemplateContent `json:"templates"`
}

type EmailPresentation struct {
	SiteName string
	Settings EmailTemplateSettings
}

type EmailRenderData struct {
	Username  string
	TTL       string
	Role      string
	Status    string
	Provider  string
	ActionURL string
}

type emailTemplateDefinition struct {
	ID                    string
	Action                bool
	BodyVariables         []string
	RequiredBodyVariables []string
	Default               EmailTemplateContent
}

var emailTemplateDefinitions = []emailTemplateDefinition{
	{
		ID: MessagePasswordReset, Action: true,
		BodyVariables: []string{EmailVariableSiteName, EmailVariableUsername},
		Default: EmailTemplateContent{
			Subject: "[{{site_name}}] 重置你的密码", Heading: "重置你的密码",
			Body:        "你好，{{username}}。我们收到了为你的 {{site_name}} 账户重置密码的请求。请使用下面的安全链接继续。",
			ButtonLabel: "重置密码",
		},
	},
	{
		ID: MessageEmailVerification, Action: true,
		BodyVariables: []string{EmailVariableSiteName, EmailVariableUsername},
		Default: EmailTemplateContent{
			Subject: "[{{site_name}}] 验证你的邮箱地址", Heading: "验证你的邮箱地址",
			Body:        "你好，{{username}}。请确认此邮箱地址属于你的 {{site_name}} 账户。完成验证后，你就可以继续使用需要已验证邮箱的功能。",
			ButtonLabel: "验证邮箱",
		},
	},
	{
		ID: MessageEmailChangeConfirm, Action: true,
		BodyVariables: []string{EmailVariableSiteName, EmailVariableUsername},
		Default: EmailTemplateContent{
			Subject: "[{{site_name}}] 确认邮箱地址变更", Heading: "确认新的邮箱地址",
			Body:        "你好，{{username}}。请确认将此邮箱地址绑定到你的 {{site_name}} 账户。确认后，后续账户邮件将发送到这个地址。",
			ButtonLabel: "确认邮箱变更",
		},
	},
	{
		ID: MessagePasswordChanged, BodyVariables: []string{EmailVariableSiteName},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 密码已修改", Heading: "密码已修改", Body: "你的 {{site_name}} 本地密码刚刚被修改。如果这不是你本人操作，请立即联系管理员。"},
	},
	{
		ID: MessageEmailChangedOld, BodyVariables: []string{EmailVariableSiteName},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 邮箱地址已变更", Heading: "邮箱地址已变更", Body: "你的 {{site_name}} 账户邮箱地址刚刚被变更。如果这不是你本人操作，请立即联系管理员。"},
	},
	{
		ID: MessageEmailChangedNew, BodyVariables: []string{EmailVariableSiteName},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 新邮箱已确认", Heading: "新邮箱已确认", Body: "此邮箱现已绑定到你的 {{site_name}} 账户。"},
	},
	{
		ID: MessageRoleChanged, BodyVariables: []string{EmailVariableSiteName, EmailVariableRole}, RequiredBodyVariables: []string{EmailVariableRole},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 账户角色已变更", Heading: "账户角色已变更", Body: "你的 {{site_name}} 账户角色已变更为“{{role}}”。如果这不是你本人或你信任的管理员操作，请立即联系管理员。"},
	},
	{
		ID: MessageStatusChanged, BodyVariables: []string{EmailVariableSiteName, EmailVariableStatus}, RequiredBodyVariables: []string{EmailVariableStatus},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 账户状态已变更", Heading: "账户状态已变更", Body: "你的 {{site_name}} 账户状态已变更为“{{status}}”。如果这不是你本人或你信任的管理员操作，请立即联系管理员。"},
	},
	{
		ID: MessagePasswordConfigured, BodyVariables: []string{EmailVariableSiteName},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 本地密码已设置", Heading: "本地密码已设置", Body: "你的 {{site_name}} 账户刚刚设置了本地密码。如果这不是你本人操作，请立即联系管理员。"},
	},
	{
		ID: MessagePasswordResetAdmin, BodyVariables: []string{EmailVariableSiteName},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 密码已由管理员重置", Heading: "密码已由管理员重置", Body: "你的 {{site_name}} 本地密码刚刚由管理员重置，下一次登录时必须修改密码。如果你不认识这次操作，请立即联系管理员。"},
	},
	{
		ID: MessageIdentityBound, BodyVariables: []string{EmailVariableSiteName, EmailVariableProvider}, RequiredBodyVariables: []string{EmailVariableProvider},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 外部身份已绑定", Heading: "外部身份已绑定", Body: "你的 {{site_name}} 账户刚刚绑定了外部身份“{{provider}}”。如果这不是你本人操作，请立即联系管理员。"},
	},
	{
		ID: MessageIdentityUnbound, BodyVariables: []string{EmailVariableSiteName, EmailVariableProvider}, RequiredBodyVariables: []string{EmailVariableProvider},
		Default: EmailTemplateContent{Subject: "[{{site_name}}] 外部身份已解绑", Heading: "外部身份已解绑", Body: "你的 {{site_name}} 账户刚刚解绑了外部身份“{{provider}}”。如果这不是你本人操作，请立即联系管理员。"},
	},
}

type emailHTMLTemplateData struct {
	SiteName    string
	Subject     string
	Heading     string
	Body        string
	ButtonLabel string
	ActionURL   string
	Expiry      string
	Footer      string
	HasAction   bool
	HasFooter   bool
}

var structuredEmailHTMLTemplate = template.Must(template.New("structured-email").Parse(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="light">
  <title>{{.Subject}}</title>
</head>
<body style="margin:0;padding:0;background:#f4f5f7;color:#252235;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',Arial,sans-serif;">
  <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">{{.Subject}}</div>
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;background:#f4f5f7;">
    <tr><td align="center" style="padding:32px 16px;">
      <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="width:100%;max-width:600px;background:#ffffff;border:1px solid #e2e4e9;border-radius:8px;">
        <tr><td style="padding:22px 30px;border-bottom:1px solid #e8e9ed;">
          <span style="font-size:21px;font-weight:700;color:#5b45d6;">{{.SiteName}}</span>
          <span style="margin-left:10px;font-size:13px;color:#6f7280;">账户安全</span>
        </td></tr>
        <tr><td style="padding:30px;">
          <h1 style="margin:0 0 18px;font-size:25px;line-height:1.35;color:#252235;">{{.Heading}}</h1>
          <p style="margin:0 0 22px;white-space:pre-line;font-size:16px;line-height:1.75;color:#4c4f5d;">{{.Body}}</p>
          {{if .HasAction}}
          <table role="presentation" cellspacing="0" cellpadding="0" border="0" style="margin:0 0 22px;"><tr>
            <td align="center" bgcolor="#5b45d6" style="border-radius:8px;"><a href="{{.ActionURL}}" style="display:inline-block;padding:13px 22px;font-size:16px;font-weight:700;line-height:1;color:#ffffff;text-decoration:none;border-radius:8px;">{{.ButtonLabel}}</a></td>
          </tr></table>
          <p style="margin:0 0 8px;font-size:13px;line-height:1.6;color:#6f7280;">如果按钮无法打开，请复制下面的完整链接到浏览器：</p>
          <p style="margin:0 0 18px;padding:12px 14px;background:#f7f7fa;border:1px solid #e8e9ed;border-radius:6px;font-size:13px;line-height:1.6;word-break:break-all;"><a href="{{.ActionURL}}" style="color:#4f3bc4;text-decoration:underline;">{{.ActionURL}}</a></p>
          <p style="margin:0 0 18px;font-size:14px;line-height:1.7;color:#5f6270;">{{.Expiry}}</p>
          <p style="margin:0 0 18px;font-size:13px;line-height:1.7;color:#6f7280;">如果你没有发起此操作，可以忽略这封邮件。请不要转发邮件或向任何人分享上面的链接。</p>
          {{end}}
          <div style="padding-top:18px;border-top:1px solid #e8e9ed;">
            {{if .HasFooter}}<p style="margin:0 0 6px;white-space:pre-line;font-size:12px;line-height:1.7;color:#777a87;">{{.Footer}}</p>{{end}}
            <p style="margin:0;font-size:12px;line-height:1.7;color:#9295a1;">这是一封自动发送的事务邮件，请勿直接回复。</p>
          </div>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`))

func DefaultEmailTemplateSettings() EmailTemplateSettings {
	templates := make(map[string]EmailTemplateContent, len(emailTemplateDefinitions))
	for _, definition := range emailTemplateDefinitions {
		templates[definition.ID] = definition.Default
	}
	return EmailTemplateSettings{
		Footer:    "由 {{site_name}} 自动发送。为保护账户安全，请勿转发包含安全链接的邮件。",
		Templates: templates,
	}
}

func EmailTemplateIDs() []string {
	ids := make([]string, 0, len(emailTemplateDefinitions))
	for _, definition := range emailTemplateDefinitions {
		ids = append(ids, definition.ID)
	}
	return ids
}

type EmailTemplateVariableRules struct {
	Subject      []string `json:"subject"`
	Heading      []string `json:"heading"`
	Body         []string `json:"body"`
	ButtonLabel  []string `json:"button_label"`
	RequiredBody []string `json:"required_body"`
}

func EmailTemplateVariables(messageType string) EmailTemplateVariableRules {
	definition, ok := emailTemplateDefinitionFor(messageType)
	if !ok {
		return EmailTemplateVariableRules{
			Subject: []string{}, Heading: []string{}, Body: []string{},
			ButtonLabel: []string{}, RequiredBody: []string{},
		}
	}
	return EmailTemplateVariableRules{
		Subject: []string{EmailVariableSiteName}, Heading: []string{},
		Body: cloneEmailVariableList(definition.BodyVariables), ButtonLabel: []string{},
		RequiredBody: cloneEmailVariableList(definition.RequiredBodyVariables),
	}
}

func cloneEmailVariableList(value []string) []string {
	if len(value) == 0 {
		return []string{}
	}
	return slices.Clone(value)
}

func NormalizeEmailTemplateSettings(value EmailTemplateSettings) (EmailTemplateSettings, error) {
	defaults := DefaultEmailTemplateSettings()
	value.Footer = strings.TrimSpace(value.Footer)
	if value.Footer != "" {
		if err := validateEmailTemplateText("footer", value.Footer, maxEmailFooterRunes, true, []string{EmailVariableSiteName}); err != nil {
			return EmailTemplateSettings{}, err
		}
	}
	for id := range value.Templates {
		if _, ok := emailTemplateDefinitionFor(id); !ok {
			return EmailTemplateSettings{}, fmt.Errorf("templates contains unsupported message type %q", id)
		}
	}
	normalized := make(map[string]EmailTemplateContent, len(emailTemplateDefinitions))
	for _, definition := range emailTemplateDefinitions {
		content, ok := value.Templates[definition.ID]
		if !ok {
			content = defaults.Templates[definition.ID]
		}
		content.Subject = strings.TrimSpace(content.Subject)
		content.Heading = strings.TrimSpace(content.Heading)
		content.Body = strings.TrimSpace(content.Body)
		content.ButtonLabel = strings.TrimSpace(content.ButtonLabel)
		if err := validateEmailTemplateText(definition.ID+" subject", content.Subject, maxEmailSubjectRunes, false, []string{EmailVariableSiteName}); err != nil {
			return EmailTemplateSettings{}, err
		}
		if err := validateEmailTemplateText(definition.ID+" heading", content.Heading, maxEmailHeadingRunes, false, nil); err != nil {
			return EmailTemplateSettings{}, err
		}
		if err := validateEmailTemplateText(definition.ID+" body", content.Body, maxEmailBodyRunes, true, definition.BodyVariables); err != nil {
			return EmailTemplateSettings{}, err
		}
		if err := requireEmailTemplateVariables(definition.ID+" body", content.Body, definition.RequiredBodyVariables); err != nil {
			return EmailTemplateSettings{}, err
		}
		if definition.Action {
			if err := validateEmailTemplateText(definition.ID+" button_label", content.ButtonLabel, maxEmailButtonLabelRunes, false, nil); err != nil {
				return EmailTemplateSettings{}, err
			}
		} else if content.ButtonLabel != "" {
			return EmailTemplateSettings{}, fmt.Errorf("%s button_label is only available for action emails", definition.ID)
		}
		normalized[definition.ID] = content
	}
	value.Templates = normalized
	return value, nil
}

func RenderEmailTemplate(messageType, recipient string, presentation EmailPresentation, data EmailRenderData) (EmailMessage, error) {
	definition, ok := emailTemplateDefinitionFor(messageType)
	if !ok {
		return EmailMessage{}, fmt.Errorf("unsupported email message type %q", messageType)
	}
	settings, err := NormalizeEmailTemplateSettings(presentation.Settings)
	if err != nil {
		return EmailMessage{}, fmt.Errorf("invalid email template settings: %w", err)
	}
	siteName := strings.TrimSpace(presentation.SiteName)
	if siteName == "" {
		siteName = "Nyauth"
	}
	if utf8.RuneCountInString(siteName) > 64 || containsUnsafeEmailText(siteName, false) {
		return EmailMessage{}, fmt.Errorf("invalid email site name")
	}
	variables := map[string]string{
		EmailVariableSiteName: siteName,
		EmailVariableUsername: strings.TrimSpace(data.Username),
		EmailVariableTTL:      strings.TrimSpace(data.TTL),
		EmailVariableRole:     strings.TrimSpace(data.Role),
		EmailVariableStatus:   strings.TrimSpace(data.Status),
		EmailVariableProvider: strings.TrimSpace(data.Provider),
	}
	content := settings.Templates[messageType]
	subject, err := renderEmailTemplateText(content.Subject, []string{EmailVariableSiteName}, variables)
	if err != nil {
		return EmailMessage{}, err
	}
	heading, err := renderEmailTemplateText(content.Heading, nil, variables)
	if err != nil {
		return EmailMessage{}, err
	}
	body, err := renderEmailTemplateText(content.Body, definition.BodyVariables, variables)
	if err != nil {
		return EmailMessage{}, err
	}
	buttonLabel := ""
	if definition.Action {
		buttonLabel, err = renderEmailTemplateText(content.ButtonLabel, nil, variables)
		if err != nil {
			return EmailMessage{}, err
		}
		if err := validateActionEmailURL(data.ActionURL); err != nil {
			return EmailMessage{}, err
		}
	}
	footer, err := renderEmailTemplateText(settings.Footer, []string{EmailVariableSiteName}, variables)
	if err != nil {
		return EmailMessage{}, err
	}
	expiry := ""
	if definition.Action {
		expiry = "此安全链接将在 " + variables[EmailVariableTTL] + "后失效，并且只能使用一次。"
	}
	htmlData := emailHTMLTemplateData{
		SiteName: siteName, Subject: subject, Heading: heading, Body: body,
		ButtonLabel: buttonLabel, ActionURL: data.ActionURL, Expiry: expiry,
		Footer: footer, HasAction: definition.Action, HasFooter: footer != "",
	}
	var htmlBody bytes.Buffer
	if err := structuredEmailHTMLTemplate.Execute(&htmlBody, htmlData); err != nil {
		return EmailMessage{}, fmt.Errorf("rendering structured email: %w", err)
	}
	textSections := []string{siteName + " 账户安全", "", heading, "", body}
	if definition.Action {
		textSections = append(textSections, "", buttonLabel+"：", data.ActionURL, "", expiry, "", "如果你没有发起此操作，可以忽略这封邮件。请不要转发邮件或向任何人分享上面的链接。")
	}
	if footer != "" {
		textSections = append(textSections, "", footer)
	}
	textSections = append(textSections, "", "这是一封自动发送的事务邮件，请勿直接回复。")
	return EmailMessage{To: recipient, Subject: subject, TextBody: strings.Join(textSections, "\n"), HTMLBody: htmlBody.String()}, nil
}

func emailTemplateDefinitionFor(messageType string) (emailTemplateDefinition, bool) {
	for _, definition := range emailTemplateDefinitions {
		if definition.ID == messageType {
			return definition, true
		}
	}
	return emailTemplateDefinition{}, false
}

func validateEmailTemplateText(field, value string, limit int, allowNewline bool, allowedVariables []string) error {
	if value == "" {
		return fmt.Errorf("%s is required", field)
	}
	if utf8.RuneCountInString(value) > limit {
		return fmt.Errorf("%s must be at most %d characters", field, limit)
	}
	if containsUnsafeEmailText(value, allowNewline) {
		return fmt.Errorf("%s contains unsupported control characters", field)
	}
	_, err := renderEmailTemplateText(value, allowedVariables, map[string]string{})
	if err != nil {
		return fmt.Errorf("%s: %w", field, err)
	}
	return nil
}

func containsUnsafeEmailText(value string, allowNewline bool) bool {
	for _, character := range value {
		if character == '\n' && allowNewline {
			continue
		}
		if character == '\r' || character == '\n' || character == 0 || isBidirectionalEmailControl(character) || unicode.IsControl(character) {
			return true
		}
	}
	return false
}

func isBidirectionalEmailControl(character rune) bool {
	return character == '\u200e' || character == '\u200f' ||
		(character >= '\u202a' && character <= '\u202e') ||
		(character >= '\u2066' && character <= '\u2069')
}

func requireEmailTemplateVariables(field, value string, required []string) error {
	if len(required) == 0 {
		return nil
	}
	used := make(map[string]bool, len(required))
	remaining := value
	for {
		start := strings.Index(remaining, "{{")
		if start < 0 {
			break
		}
		remaining = remaining[start+2:]
		end := strings.Index(remaining, "}}")
		if end < 0 {
			break
		}
		used[strings.TrimSpace(remaining[:end])] = true
		remaining = remaining[end+2:]
	}
	for _, variable := range required {
		if !used[variable] {
			return fmt.Errorf("%s must contain template variable %q", field, variable)
		}
	}
	return nil
}

func renderEmailTemplateText(value string, allowedVariables []string, variables map[string]string) (string, error) {
	var result strings.Builder
	for {
		start := strings.Index(value, "{{")
		if start < 0 {
			if strings.Contains(value, "}}") {
				return "", fmt.Errorf("contains a malformed template variable")
			}
			result.WriteString(value)
			return result.String(), nil
		}
		result.WriteString(value[:start])
		value = value[start+2:]
		end := strings.Index(value, "}}")
		if end < 0 || strings.Contains(value[:end], "{{") {
			return "", fmt.Errorf("contains a malformed template variable")
		}
		name := strings.TrimSpace(value[:end])
		if name == "" || !slices.Contains(allowedVariables, name) {
			return "", fmt.Errorf("contains unsupported template variable %q", name)
		}
		result.WriteString(variables[name])
		value = value[end+2:]
	}
}

func validateActionEmailURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" || parsed.User != nil {
		return fmt.Errorf("action email URL must be an absolute HTTP(S) URL")
	}
	return nil
}
