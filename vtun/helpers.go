package vtun

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"

	"golang.org/x/net/dns/dnsmessage"
)

// TODO: Move it to gonnect

var (
	errNoSuchHost                   = errors.New("no such host")
	errLameReferral                 = errors.New("lame referral")
	errCannotUnmarshalDNSMessage    = errors.New("cannot unmarshal DNS message")
	errCannotMarshalDNSMessage      = errors.New("cannot marshal DNS message")
	errServerMisbehaving            = errors.New("server misbehaving")
	errInvalidDNSResponse           = errors.New("invalid DNS response")
	errNoAnswerFromDNSServer        = errors.New("no answer from DNS server")
	errServerTemporarilyMisbehaving = errors.New("server misbehaving")
	errCanceled                     = errors.New("operation was canceled")
	errTimeout                      = errors.New("i/o timeout")
	errNoSuitableAddress            = errors.New("no suitable address found")
)

// isDomainName checks if a string is a valid domain name.
func isDomainName(s string) bool {
	l := len(s)
	if l == 0 || l > 254 || l == 254 && s[l-1] != '.' {
		return false
	}
	last := byte('.')
	nonNumeric := false
	partlen := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		default:
			return false
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || c == '_':
			nonNumeric = true
			partlen++
		case '0' <= c && c <= '9':
			partlen++
		case c == '-':
			if last == '.' {
				return false
			}
			partlen++
			nonNumeric = true
		case c == '.':
			if last == '.' || last == '-' {
				return false
			}
			if partlen > 63 || partlen == 0 {
				return false
			}
			partlen = 0
		}
		last = c
	}
	if last == '-' || partlen > 63 {
		return false
	}
	return nonNumeric
}

// randU16 generates a random 16-bit unsigned integer.
func randU16() uint16 {
	var b [2]byte
	_, err := rand.Read(b[:])
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(b[:])
}

// newRequest creates a DNS request message for the given question and returns
// the request ID, UDP request, TCP request, and any error.
func newRequest(q dnsmessage.Question) (id uint16, udpReq, tcpReq []byte, err error) {
	id = randU16()
	b := dnsmessage.NewBuilder(make([]byte, 2, 514), dnsmessage.Header{ID: id, RecursionDesired: true})
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		return 0, nil, nil, err
	}
	if err := b.Question(q); err != nil {
		return 0, nil, nil, err
	}
	tcpReq, err = b.Finish()
	udpReq = tcpReq[2:]
	l := len(tcpReq) - 2
	tcpReq[0] = byte(l >> 8)
	tcpReq[1] = byte(l)
	return id, udpReq, tcpReq, err
}

// equalASCIIName compares two DNS names for equality, ignoring ASCII case differences.
func equalASCIIName(x, y dnsmessage.Name) bool {
	if x.Length != y.Length {
		return false
	}
	for i := 0; i < int(x.Length); i++ {
		a := x.Data[i]
		b := y.Data[i]
		if 'A' <= a && a <= 'Z' {
			a += 0x20
		}
		if 'A' <= b && b <= 'Z' {
			b += 0x20
		}
		if a != b {
			return false
		}
	}
	return true
}

// checkResponse verifies that a DNS response matches the original request ID and question.
func checkResponse(reqID uint16, reqQues dnsmessage.Question, respHdr dnsmessage.Header, respQues dnsmessage.Question) bool {
	if !respHdr.Response {
		return false
	}
	if reqID != respHdr.ID {
		return false
	}
	if reqQues.Type != respQues.Type || reqQues.Class != respQues.Class || !equalASCIIName(reqQues.Name, respQues.Name) {
		return false
	}
	return true
}

// dnsPacketRoundTrip sends a DNS query via UDP and waits for a matching response.
// TODO: Timeouts? Cancellation?
func dnsPacketRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 512)
	for {
		n, err := c.Read(b)
		if err != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, err
		}
		var p dnsmessage.Parser
		h, err := p.Start(b[:n])
		if err != nil {
			continue
		}
		q, err := p.Question()
		if err != nil || !checkResponse(id, query, h, q) {
			continue
		}
		return p, h, nil
	}
}

// dnsStreamRoundTrip sends a DNS query via TCP and waits for a matching response.
// TODO: Timeouts? Cancellation?
func dnsStreamRoundTrip(c net.Conn, id uint16, query dnsmessage.Question, b []byte) (dnsmessage.Parser, dnsmessage.Header, error) {
	if _, err := c.Write(b); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	b = make([]byte, 1280)
	if _, err := io.ReadFull(c, b[:2]); err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	l := int(b[0])<<8 | int(b[1])
	if l > len(b) {
		b = make([]byte, l)
	}
	n, err := io.ReadFull(c, b[:l])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, err
	}
	var p dnsmessage.Parser
	h, err := p.Start(b[:n])
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	q, err := p.Question()
	if err != nil {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errCannotUnmarshalDNSMessage
	}
	if !checkResponse(id, query, h, q) {
		return dnsmessage.Parser{}, dnsmessage.Header{}, errInvalidDNSResponse
	}
	return p, h, nil
}

// checkHeader validates a DNS response header and returns an error if the response
// is invalid or indicates a failure.
func checkHeader(p *dnsmessage.Parser, h dnsmessage.Header) error {
	if h.RCode == dnsmessage.RCodeNameError {
		return errNoSuchHost
	}
	_, err := p.AnswerHeader()
	if err != nil && err != dnsmessage.ErrSectionDone {
		return errCannotUnmarshalDNSMessage
	}
	if h.RCode == dnsmessage.RCodeSuccess && !h.Authoritative && !h.RecursionAvailable && err == dnsmessage.ErrSectionDone {
		return errLameReferral
	}
	if h.RCode != dnsmessage.RCodeSuccess && h.RCode != dnsmessage.RCodeNameError {
		if h.RCode == dnsmessage.RCodeServerFailure {
			return errServerTemporarilyMisbehaving
		}
		return errServerMisbehaving
	}
	return nil
}

// skipToAnswer skips DNS resource records until it finds an answer of the specified type.
func skipToAnswer(p *dnsmessage.Parser, qtype dnsmessage.Type) error {
	for {
		h, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			return errNoSuchHost
		}
		if err != nil {
			return errCannotUnmarshalDNSMessage
		}
		if h.Type == qtype {
			return nil
		}
		if err := p.SkipAnswer(); err != nil {
			return errCannotUnmarshalDNSMessage
		}
	}
}
