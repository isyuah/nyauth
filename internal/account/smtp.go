package account

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/nyasharp/nyauth/internal/crypto"
)

const (
	SMTPTLSStartTLS = "starttls"
	SMTPTLSImplicit = "implicit"
	SMTPTLSPlain    = "plain"
)

type SMTPOptions struct {
	Host           string
	Port           int
	Username       string
	Password       string
	TLSMode        string
	FromAddress    string
	FromName       string
	ConnectTimeout time.Duration
	SendTimeout    time.Duration
}

type SMTPSender struct {
	host           string
	address        string
	username       string
	password       string
	tlsMode        string
	from           *mail.Address
	connectTimeout time.Duration
	sendTimeout    time.Duration
}

func NewSMTPSender(options SMTPOptions) (*SMTPSender, error) {
	options.Host = strings.TrimSpace(options.Host)
	if options.Host == "" || containsHeaderBreak(options.Host) {
		return nil, fmt.Errorf("SMTP host is required")
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, fmt.Errorf("SMTP port must be between 1 and 65535")
	}
	options.TLSMode = strings.ToLower(strings.TrimSpace(options.TLSMode))
	if options.TLSMode == "" {
		options.TLSMode = SMTPTLSStartTLS
	}
	if options.TLSMode != SMTPTLSStartTLS && options.TLSMode != SMTPTLSImplicit && options.TLSMode != SMTPTLSPlain {
		return nil, fmt.Errorf("SMTP TLS mode must be starttls, implicit, or plain")
	}
	from, err := mail.ParseAddress(strings.TrimSpace(options.FromAddress))
	if err != nil || from.Address == "" || containsHeaderBreak(from.Address) {
		return nil, fmt.Errorf("invalid SMTP from address")
	}
	if options.FromName != "" {
		if containsHeaderBreak(options.FromName) {
			return nil, fmt.Errorf("invalid SMTP from name")
		}
		from.Name = options.FromName
	}
	if options.ConnectTimeout == 0 {
		options.ConnectTimeout = 10 * time.Second
	}
	if options.SendTimeout == 0 {
		options.SendTimeout = 30 * time.Second
	}
	if options.ConnectTimeout <= 0 || options.SendTimeout <= 0 {
		return nil, fmt.Errorf("SMTP timeouts must be positive")
	}
	if options.Username == "" && options.Password != "" {
		return nil, fmt.Errorf("SMTP username is required when a password is configured")
	}
	return &SMTPSender{
		host: options.Host, address: net.JoinHostPort(options.Host, strconv.Itoa(options.Port)),
		username: options.Username, password: options.Password, tlsMode: options.TLSMode,
		from: from, connectTimeout: options.ConnectTimeout, sendTimeout: options.SendTimeout,
	}, nil
}

func (s *SMTPSender) Send(ctx context.Context, message EmailMessage) error {
	if err := validateEmailMessage(message); err != nil {
		return err
	}
	recipient, err := mail.ParseAddress(message.To)
	if err != nil {
		return fmt.Errorf("parsing SMTP recipient: %w", err)
	}
	payload, err := buildMIMEMessage(s.from, recipient, message)
	if err != nil {
		return err
	}
	client, conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	defer client.Close()
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopCancel()

	deadline := time.Now().Add(s.sendTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("setting SMTP deadline: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.username != "" {
		if ok, _ := client.Extension("AUTH"); !ok {
			return fmt.Errorf("SMTP server does not advertise authentication")
		}
		if err := client.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return fmt.Errorf("authenticating to SMTP server: %w", err)
		}
	}
	if err := client.Mail(s.from.Address); err != nil {
		return fmt.Errorf("sending SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return fmt.Errorf("sending SMTP RCPT TO: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("starting SMTP DATA: %w", err)
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return fmt.Errorf("writing SMTP DATA: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("finishing SMTP DATA: %w", err)
	}
	if err := client.Quit(); err != nil {
		return fmt.Errorf("closing SMTP transaction: %w", err)
	}
	return nil
}

func (s *SMTPSender) connect(ctx context.Context) (*smtp.Client, net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.connectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to SMTP server: %w", err)
	}
	deadline := time.Now().Add(s.connectTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("setting SMTP connection deadline: %w", err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.host}
	if s.tlsMode == SMTPTLSImplicit {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("performing implicit SMTP TLS handshake: %w", err)
		}
		conn = tlsConn
	}
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("creating SMTP client: %w", err)
	}
	if s.tlsMode == SMTPTLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			client.Close()
			conn.Close()
			return nil, nil, fmt.Errorf("SMTP server does not advertise STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			client.Close()
			conn.Close()
			return nil, nil, fmt.Errorf("starting SMTP TLS: %w", err)
		}
	}
	return client, conn, nil
}

func buildMIMEMessage(from, recipient *mail.Address, message EmailMessage) ([]byte, error) {
	messageID, err := crypto.GenerateRandomString(18)
	if err != nil {
		return nil, fmt.Errorf("generating email message ID: %w", err)
	}
	var body bytes.Buffer
	body.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	body.WriteString("Message-ID: <" + messageID + "@nyauth.local>\r\n")
	body.WriteString("From: " + from.String() + "\r\n")
	body.WriteString("To: " + recipient.String() + "\r\n")
	body.WriteString("Subject: " + mime.QEncoding.Encode("utf-8", message.Subject) + "\r\n")
	body.WriteString("MIME-Version: 1.0\r\n")

	if message.HTMLBody == "" {
		body.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
		body.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
		writer := quotedprintable.NewWriter(&body)
		if _, err := io.WriteString(writer, normalizeCRLF(message.TextBody)); err != nil {
			return nil, fmt.Errorf("encoding text email body: %w", err)
		}
		if err := writer.Close(); err != nil {
			return nil, fmt.Errorf("finishing text email body: %w", err)
		}
		return body.Bytes(), nil
	}

	multipartWriter := multipart.NewWriter(&body)
	body.WriteString("Content-Type: multipart/alternative; boundary=\"" + multipartWriter.Boundary() + "\"\r\n\r\n")
	for _, part := range []struct {
		contentType string
		content     string
	}{
		{contentType: "text/plain; charset=utf-8", content: message.TextBody},
		{contentType: "text/html; charset=utf-8", content: message.HTMLBody},
	} {
		headers := make(textproto.MIMEHeader)
		headers.Set("Content-Type", part.contentType)
		headers.Set("Content-Transfer-Encoding", "quoted-printable")
		partWriter, err := multipartWriter.CreatePart(headers)
		if err != nil {
			return nil, fmt.Errorf("creating MIME part: %w", err)
		}
		quotedWriter := quotedprintable.NewWriter(partWriter)
		if _, err := io.WriteString(quotedWriter, normalizeCRLF(part.content)); err != nil {
			return nil, fmt.Errorf("encoding MIME part: %w", err)
		}
		if err := quotedWriter.Close(); err != nil {
			return nil, fmt.Errorf("finishing MIME part: %w", err)
		}
	}
	if err := multipartWriter.Close(); err != nil {
		return nil, fmt.Errorf("finishing multipart email: %w", err)
	}
	return body.Bytes(), nil
}

func normalizeCRLF(value string) string {
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	return strings.ReplaceAll(value, "\n", "\r\n")
}
