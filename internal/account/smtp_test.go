package account

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"net"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type smtpTestServer struct {
	listener net.Listener
	wg       sync.WaitGroup
	sessions chan smtpTestSession
}

type smtpTestServerOptions struct {
	mailFromStatus      int
	recipientStatus     int
	dataStatus          int
	quitStatus          int
	disconnectAfterData bool
}

type smtpTestSession struct {
	commands []string
	message  string
}

func newSMTPTestServer(t *testing.T, connections int, options smtpTestServerOptions) *smtpTestServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen SMTP test server: %v", err)
	}
	server := &smtpTestServer{listener: listener, sessions: make(chan smtpTestSession, connections)}
	server.wg.Add(connections)
	go func() {
		for index := 0; index < connections; index++ {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				server.wg.Done()
				continue
			}
			go server.serve(connection, options)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		server.wg.Wait()
		close(server.sessions)
	})
	return server
}

func (s *smtpTestServer) address(t *testing.T) (string, int) {
	t.Helper()
	host, rawPort, err := net.SplitHostPort(s.listener.Addr().String())
	if err != nil {
		t.Fatalf("split SMTP test address: %v", err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		t.Fatalf("parse SMTP test port: %v", err)
	}
	return host, port
}

func (s *smtpTestServer) nextSession(t *testing.T) smtpTestSession {
	t.Helper()
	select {
	case session := <-s.sessions:
		return session
	case <-time.After(3 * time.Second):
		t.Fatal("SMTP test server did not finish the session")
		return smtpTestSession{}
	}
}

func (s *smtpTestServer) serve(connection net.Conn, options smtpTestServerOptions) {
	defer s.wg.Done()
	defer connection.Close()
	session := smtpTestSession{}
	defer func() { s.sessions <- session }()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	reader := bufio.NewReader(connection)
	writer := bufio.NewWriter(connection)
	writeLine := func(line string) bool {
		if _, err := writer.WriteString(line + "\r\n"); err != nil {
			return false
		}
		return writer.Flush() == nil
	}
	if !writeLine("220 smtp.test ESMTP") {
		return
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		command := strings.ToUpper(strings.TrimSpace(line))
		session.commands = append(session.commands, command)
		switch {
		case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
			if !writeLine("250 smtp.test") {
				return
			}
		case command == "NOOP":
			if !writeLine("250 OK") {
				return
			}
		case strings.HasPrefix(command, "MAIL FROM:"):
			status := options.mailFromStatus
			if status == 0 {
				status = 250
			}
			if !writeLine(fmt.Sprintf("%d sender response", status)) || status != 250 {
				return
			}
		case command == "RSET":
			if !writeLine("250 reset") {
				return
			}
		case strings.HasPrefix(command, "RCPT TO:"):
			status := options.recipientStatus
			if status == 0 {
				status = 250
			}
			if status != 250 {
				_ = writeLine(fmt.Sprintf("%d recipient rejected", status))
				return
			}
			if !writeLine("250 recipient accepted") {
				return
			}
		case command == "DATA":
			if !writeLine("354 end with dot") {
				return
			}
			var message strings.Builder
			for {
				dataLine, readErr := reader.ReadString('\n')
				if readErr != nil {
					return
				}
				if dataLine == ".\r\n" || dataLine == ".\n" {
					break
				}
				message.WriteString(dataLine)
			}
			session.message = message.String()
			status := options.dataStatus
			if status == 0 {
				status = 250
			}
			if !writeLine(fmt.Sprintf("%d data response", status)) || status != 250 {
				return
			}
			if options.disconnectAfterData {
				return
			}
		case command == "QUIT":
			status := options.quitStatus
			if status == 0 {
				status = 221
			}
			_ = writeLine(fmt.Sprintf("%d quit response", status))
			return
		default:
			if !writeLine("502 unsupported") {
				return
			}
		}
	}
}

func TestSMTPSenderProbeAndSend(t *testing.T) {
	server := newSMTPTestServer(t, 2, smtpTestServerOptions{})
	host, port := server.address(t)
	sender, err := NewSMTPSender(SMTPOptions{
		Host: host, Port: port, TLSMode: SMTPTLSPlain,
		FromAddress: "noreply@example.test", ConnectTimeout: time.Second, SendTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := sender.Probe(ctx); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	probeSession := server.nextSession(t)
	assertSMTPCommandOrder(t, probeSession.commands, "MAIL FROM:", "RSET", "NOOP", "QUIT")
	if hasSMTPCommand(probeSession.commands, "DATA") || probeSession.message != "" {
		t.Fatalf("probe sent message data: commands=%v message=%q", probeSession.commands, probeSession.message)
	}
	if err := sender.Send(ctx, EmailMessage{To: "alice@example.test", Subject: "Runtime test", TextBody: "hello"}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	sendSession := server.nextSession(t)
	if !strings.Contains(sendSession.message, "Subject: Runtime test") || !strings.Contains(sendSession.message, "hello") {
		t.Fatalf("unexpected SMTP message: %q", sendSession.message)
	}
	for _, header := range []string{
		"Message-ID: <", "@example.test>", "Auto-Submitted: auto-generated",
		"X-Auto-Response-Suppress: All", "Content-Language: zh-CN",
	} {
		if !strings.Contains(sendSession.message, header) {
			t.Fatalf("SMTP message is missing trusted transactional header %q: %q", header, sendSession.message)
		}
	}
	if strings.Contains(sendSession.message, "@nyauth.local>") {
		t.Fatalf("SMTP message retained the local-only Message-ID domain: %q", sendSession.message)
	}
}

func TestMessageIDDomainUsesSenderDomainAndSafeLocalFallback(t *testing.T) {
	if domain := messageIDDomain("NOREPLY@Example.COM"); domain != "example.com" {
		t.Fatalf("sender Message-ID domain = %q, want example.com", domain)
	}
	if domain := messageIDDomain("local-sender"); domain != "localhost" {
		t.Fatalf("local Message-ID fallback = %q, want localhost", domain)
	}
}

func TestSMTPSenderSendIgnoresDisconnectAfterDataAccepted(t *testing.T) {
	server := newSMTPTestServer(t, 1, smtpTestServerOptions{disconnectAfterData: true})
	host, port := server.address(t)
	sender, err := NewSMTPSender(SMTPOptions{
		Host: host, Port: port, TLSMode: SMTPTLSPlain,
		FromAddress: "noreply@example.test", ConnectTimeout: time.Second, SendTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if err := sender.Send(context.Background(), EmailMessage{To: "alice@example.test", Subject: "Accepted", TextBody: "hello"}); err != nil {
		t.Fatalf("Send returned an error after DATA was accepted: %v", err)
	}
	session := server.nextSession(t)
	assertSMTPCommandOrder(t, session.commands, "DATA")
	if hasSMTPCommand(session.commands, "QUIT") {
		t.Fatalf("server unexpectedly received QUIT after disconnect: %v", session.commands)
	}
}

func TestSMTPSenderProbeIgnoresQuitFailure(t *testing.T) {
	server := newSMTPTestServer(t, 1, smtpTestServerOptions{quitStatus: 500})
	host, port := server.address(t)
	sender, err := NewSMTPSender(SMTPOptions{
		Host: host, Port: port, TLSMode: SMTPTLSPlain,
		FromAddress: "noreply@example.test", ConnectTimeout: time.Second, SendTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	if err := sender.Probe(context.Background()); err != nil {
		t.Fatalf("Probe returned an error only because QUIT failed: %v", err)
	}
	session := server.nextSession(t)
	assertSMTPCommandOrder(t, session.commands, "MAIL FROM:", "RSET", "NOOP", "QUIT")
	if hasSMTPCommand(session.commands, "DATA") {
		t.Fatalf("probe sent DATA: %v", session.commands)
	}
}

func TestSMTPSenderProbeClassifiesMailFromFailure(t *testing.T) {
	server := newSMTPTestServer(t, 1, smtpTestServerOptions{mailFromStatus: 550})
	host, port := server.address(t)
	sender, err := NewSMTPSender(SMTPOptions{
		Host: host, Port: port, TLSMode: SMTPTLSPlain,
		FromAddress: "rejected@example.test", ConnectTimeout: time.Second, SendTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	err = sender.Probe(context.Background())
	category, permanent := SMTPErrorDetails(err)
	if category != SMTPErrorConfiguration || !permanent {
		t.Fatalf("error=%v category=%q permanent=%v", err, category, permanent)
	}
	session := server.nextSession(t)
	assertSMTPCommandOrder(t, session.commands, "MAIL FROM:")
	if hasSMTPCommand(session.commands, "RSET") || hasSMTPCommand(session.commands, "NOOP") || hasSMTPCommand(session.commands, "DATA") {
		t.Fatalf("probe continued after MAIL FROM rejection: %v", session.commands)
	}
}

func TestSMTPSenderClassifiesRecipientRejection(t *testing.T) {
	server := newSMTPTestServer(t, 1, smtpTestServerOptions{recipientStatus: 550})
	host, port := server.address(t)
	sender, err := NewSMTPSender(SMTPOptions{
		Host: host, Port: port, TLSMode: SMTPTLSPlain,
		FromAddress: "noreply@example.test", ConnectTimeout: time.Second, SendTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	err = sender.Send(context.Background(), EmailMessage{To: "rejected@example.test", Subject: "Runtime test", TextBody: "hello"})
	category, permanent := SMTPErrorDetails(err)
	if category != SMTPErrorRecipient || !permanent {
		t.Fatalf("error=%v category=%q permanent=%v", err, category, permanent)
	}
}

func TestSMTPSenderClassifiesPermanentDataRejectionAsRecipientFailure(t *testing.T) {
	server := newSMTPTestServer(t, 1, smtpTestServerOptions{dataStatus: 550})
	host, port := server.address(t)
	sender, err := NewSMTPSender(SMTPOptions{
		Host: host, Port: port, TLSMode: SMTPTLSPlain,
		FromAddress: "noreply@example.test", ConnectTimeout: time.Second, SendTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	err = sender.Send(context.Background(), EmailMessage{To: "alice@example.test", Subject: "Rejected", TextBody: "hello"})
	category, permanent := SMTPErrorDetails(err)
	if category != SMTPErrorRecipient || !permanent {
		t.Fatalf("error=%v category=%q permanent=%v", err, category, permanent)
	}
}

func TestSMTPSenderKeepsTemporaryDataRejectionRetryable(t *testing.T) {
	server := newSMTPTestServer(t, 1, smtpTestServerOptions{dataStatus: 451})
	host, port := server.address(t)
	sender, err := NewSMTPSender(SMTPOptions{
		Host: host, Port: port, TLSMode: SMTPTLSPlain,
		FromAddress: "noreply@example.test", ConnectTimeout: time.Second, SendTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewSMTPSender: %v", err)
	}
	err = sender.Send(context.Background(), EmailMessage{To: "alice@example.test", Subject: "Temporary", TextBody: "hello"})
	category, permanent := SMTPErrorDetails(err)
	if category != SMTPErrorTransport || permanent {
		t.Fatalf("error=%v category=%q permanent=%v", err, category, permanent)
	}
}

func assertSMTPCommandOrder(t *testing.T, commands []string, prefixes ...string) {
	t.Helper()
	nextCommand := 0
	for _, prefix := range prefixes {
		found := false
		for nextCommand < len(commands) {
			command := commands[nextCommand]
			nextCommand++
			if strings.HasPrefix(command, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("SMTP command %q not found in order in %v", prefix, commands)
		}
	}
}

func hasSMTPCommand(commands []string, prefix string) bool {
	for _, command := range commands {
		if strings.HasPrefix(command, prefix) {
			return true
		}
	}
	return false
}

func TestSMTPProtocolFailurePreservesTemporaryAndPermanentReplies(t *testing.T) {
	tests := []struct {
		code          int
		wantPermanent bool
	}{
		{code: 451, wantPermanent: false},
		{code: 550, wantPermanent: true},
	}
	for _, test := range tests {
		t.Run(strconv.Itoa(test.code), func(t *testing.T) {
			err := smtpProtocolFailure(SMTPErrorConfiguration, "sending SMTP MAIL FROM", &textproto.Error{Code: test.code, Msg: "test reply"})
			category, permanent := SMTPErrorDetails(err)
			if category != SMTPErrorConfiguration || permanent != test.wantPermanent {
				t.Fatalf("error=%v category=%q permanent=%v", err, category, permanent)
			}
		})
	}
}

func TestSMTPTLSFailureTreatsCertificateValidationAsPermanent(t *testing.T) {
	err := smtpTLSFailure("starting SMTP TLS", x509.HostnameError{Host: "smtp.example.test"})
	category, permanent := SMTPErrorDetails(err)
	if category != SMTPErrorTLS || !permanent {
		t.Fatalf("error=%v category=%q permanent=%v", err, category, permanent)
	}

	err = smtpTLSFailure("starting SMTP TLS", &textproto.Error{Code: 454, Msg: "TLS temporarily unavailable"})
	category, permanent = SMTPErrorDetails(err)
	if category != SMTPErrorTLS || permanent {
		t.Fatalf("error=%v category=%q permanent=%v", err, category, permanent)
	}
}
