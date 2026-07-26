package account

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
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

type SMTPErrorCategory string

const (
	SMTPErrorConfiguration  SMTPErrorCategory = "configuration"
	SMTPErrorAuthentication SMTPErrorCategory = "authentication"
	SMTPErrorTLS            SMTPErrorCategory = "tls"
	SMTPErrorTransport      SMTPErrorCategory = "transport"
	SMTPErrorRecipient      SMTPErrorCategory = "recipient"
	SMTPErrorUnknown        SMTPErrorCategory = "unknown"
)

// SMTPError classifies delivery failures without exposing SMTP credentials or
// message contents. Permanent configuration, authentication, and TLS failures
// are used by the runtime mail circuit breaker.
type SMTPError struct {
	Category  SMTPErrorCategory
	Operation string
	Permanent bool
	Err       error
}

func (e *SMTPError) Error() string {
	if e == nil {
		return "SMTP error"
	}
	if e.Err == nil {
		return e.Operation
	}
	return e.Operation + ": " + e.Err.Error()
}

func (e *SMTPError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

func SMTPErrorDetails(err error) (SMTPErrorCategory, bool) {
	var smtpErr *SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr.Category, smtpErr.Permanent
	}
	return SMTPErrorUnknown, false
}

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
		return smtpFailure(SMTPErrorRecipient, "validating SMTP message", true, err)
	}
	recipient, err := mail.ParseAddress(message.To)
	if err != nil {
		return smtpFailure(SMTPErrorRecipient, "parsing SMTP recipient", true, err)
	}
	payload, err := buildMIMEMessage(s.from, recipient, message)
	if err != nil {
		return err
	}
	client, conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	clientOpen := true
	defer func() {
		stopCancel()
		if clientOpen {
			_ = client.Close()
		}
	}()

	deadline := time.Now().Add(s.sendTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return smtpFailure(SMTPErrorTransport, "setting SMTP deadline", false, err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.authenticate(client); err != nil {
		return err
	}
	if err := client.Mail(s.from.Address); err != nil {
		return smtpProtocolFailure(SMTPErrorConfiguration, "sending SMTP MAIL FROM", err)
	}
	if err := client.Rcpt(recipient.Address); err != nil {
		return smtpProtocolFailure(SMTPErrorRecipient, "sending SMTP RCPT TO", err)
	}
	writer, err := client.Data()
	if err != nil {
		return smtpProtocolFailure(SMTPErrorTransport, "starting SMTP DATA", err)
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return smtpFailure(SMTPErrorTransport, "writing SMTP DATA", false, err)
	}
	if err := writer.Close(); err != nil {
		return smtpDataFailure("finishing SMTP DATA", err)
	}

	// A successful DATA close means the server accepted the message. QUIT is
	// only a best-effort session shutdown from this point; surfacing its error
	// would cause the outbox to retry an already accepted message.
	stopCancel()
	if err := client.Quit(); err == nil {
		clientOpen = false
	}
	return nil
}

// Probe verifies the connection, TLS policy, authentication, and envelope
// sender without sending a message. It is used only for circuit recovery;
// candidate tests still send a real email.
func (s *SMTPSender) Probe(ctx context.Context) error {
	client, conn, err := s.connect(ctx)
	if err != nil {
		return err
	}
	stopCancel := context.AfterFunc(ctx, func() { _ = conn.Close() })
	clientOpen := true
	defer func() {
		stopCancel()
		if clientOpen {
			_ = client.Close()
		}
	}()
	if err := s.authenticate(client); err != nil {
		return err
	}
	if err := client.Mail(s.from.Address); err != nil {
		return smtpProtocolFailure(SMTPErrorConfiguration, "probing SMTP MAIL FROM", err)
	}
	if err := client.Reset(); err != nil {
		return smtpProtocolFailure(SMTPErrorTransport, "resetting SMTP probe transaction", err)
	}
	if err := client.Noop(); err != nil {
		return smtpProtocolFailure(SMTPErrorTransport, "probing SMTP connection", err)
	}

	// The probe has already established server health. A failed QUIT must not
	// reverse that result, but a successful QUIT owns and closes the client so
	// the deferred cleanup does not close it twice.
	stopCancel()
	if err := client.Quit(); err == nil {
		clientOpen = false
	}
	return nil
}

func (s *SMTPSender) authenticate(client *smtp.Client) error {
	if s.username == "" {
		return nil
	}
	if ok, _ := client.Extension("AUTH"); !ok {
		return smtpFailure(SMTPErrorAuthentication, "authenticating to SMTP server", true, errors.New("server does not advertise AUTH"))
	}
	if err := client.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
		return smtpProtocolFailure(SMTPErrorAuthentication, "authenticating to SMTP server", err)
	}
	return nil
}

func (s *SMTPSender) connect(ctx context.Context) (*smtp.Client, net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.connectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", s.address)
	if err != nil {
		return nil, nil, smtpFailure(SMTPErrorTransport, "connecting to SMTP server", false, err)
	}
	deadline := time.Now().Add(s.connectTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, nil, smtpFailure(SMTPErrorTransport, "setting SMTP connection deadline", false, err)
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: s.host}
	if s.tlsMode == SMTPTLSImplicit {
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			conn.Close()
			return nil, nil, smtpTLSFailure("performing implicit SMTP TLS handshake", err)
		}
		conn = tlsConn
	}
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		conn.Close()
		return nil, nil, smtpFailure(SMTPErrorTransport, "creating SMTP client", false, err)
	}
	if s.tlsMode == SMTPTLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			client.Close()
			conn.Close()
			return nil, nil, smtpFailure(SMTPErrorTLS, "starting SMTP TLS", true, errors.New("server does not advertise STARTTLS"))
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			client.Close()
			conn.Close()
			return nil, nil, smtpTLSFailure("starting SMTP TLS", err)
		}
	}
	return client, conn, nil
}

func smtpFailure(category SMTPErrorCategory, operation string, permanent bool, err error) error {
	return &SMTPError{Category: category, Operation: operation, Permanent: permanent, Err: err}
}

func smtpProtocolFailure(category SMTPErrorCategory, operation string, err error) error {
	permanent := false
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) {
		permanent = protocolErr.Code >= 500
	}
	return smtpFailure(category, operation, permanent, err)
}

// A permanent final DATA rejection means the server rejected this specific
// message or recipient after reading it; retrying it or opening the global
// SMTP circuit would not help. Temporary DATA replies remain transport errors.
func smtpDataFailure(operation string, err error) error {
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) && protocolErr.Code >= 500 {
		return smtpFailure(SMTPErrorRecipient, operation, true, err)
	}
	return smtpFailure(SMTPErrorTransport, operation, false, err)
}

func smtpTLSFailure(operation string, err error) error {
	var protocolErr *textproto.Error
	if errors.As(err, &protocolErr) {
		return smtpFailure(SMTPErrorTLS, operation, protocolErr.Code >= 500, err)
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameError x509.HostnameError
	var certificateInvalid x509.CertificateInvalidError
	var recordHeader tls.RecordHeaderError
	permanent := errors.As(err, &unknownAuthority) || errors.As(err, &hostnameError) ||
		errors.As(err, &certificateInvalid) || errors.As(err, &recordHeader)
	return smtpFailure(SMTPErrorTLS, operation, permanent, err)
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
