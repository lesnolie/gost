package gost

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/go-log/log"
	"github.com/golang/groupcache/lru"
	"github.com/lqqyt2423/go-mitmproxy/cert"
	"github.com/lunixbochs/struc"
	"golang.org/x/net/publicsuffix"
)

type zeroTCPRequest struct {
	AddressLen int `struc:"uint8,sizeof=Address"`
	Address    string
	UseMITM    bool
}

type zeroTLSRequest struct {
	ServerNameLen int `struc:"uint8,sizeof=ServerName"`
	ServerName    string
	Insecure      bool
	NextProtosLen int `struc:"uint8,sizeof=NextProtos"`
	NextProtos    string
	NeedProto     bool
}

type zeroTLSResponse struct {
	NextProtoLen int `struc:"uint8,sizeof=NextProto"`
	NextProto    string
}

type zeroNextProtoCacheKey struct {
	ServerName string
	NextProtos string
}

var (
	zeroNextProtoCache   = lru.New(1 << 10)
	zeroNextProtoCacheMu sync.Mutex
)

type ZeroMITMConfig struct {
	*cert.CA
	Hosts    *Bypass
	Insecure bool
}

func NewZeroMITMCA(caroot string) (*cert.CA, error) {
	return cert.NewCA(caroot)
}

func (c *ZeroMITMConfig) GetCertificate(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if c.CA == nil {
		return nil, fmt.Errorf("no certificate")
	}

	commonName := chi.ServerName
	if net.ParseIP(commonName) == nil {
		eTLD1, err := publicsuffix.EffectiveTLDPlusOne(commonName)
		if err == nil && commonName != eTLD1 {
			commonName = "*." + strings.SplitN(commonName, ".", 2)[1]
		}
	}

	return c.GetCert(commonName)
}

type zeroConnector struct {
	mitmConfig *ZeroMITMConfig
}

func ZeroConnector(zeroMITMConfig *ZeroMITMConfig) Connector {
	return &zeroConnector{mitmConfig: zeroMITMConfig}
}

func (c *zeroConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *zeroConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	switch network {
	case "udp", "udp4", "udp6":
		return nil, fmt.Errorf("%s unsupported", network)
	}

	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	conn.SetDeadline(time.Now().Add(timeout))
	defer conn.SetDeadline(time.Time{})

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}

	useMITM := c.mitmConfig != nil && port == "443" && c.mitmConfig.Hosts.Contains(host)
	if err := struc.Pack(conn, &zeroTCPRequest{
		Address: address,
		UseMITM: useMITM,
	}); err != nil {
		return nil, err
	}

	if useMITM {
		return &zeroMITMConn{
			Conn:       conn,
			mitmConfig: c.mitmConfig,
		}, nil
	} else {
		return conn, nil
	}
}

type zeroMITMConn struct {
	net.Conn
	mitmConfig *ZeroMITMConfig
}

func maybeWrapMITMConn(conn *net.Conn, cc net.Conn) error {
	mcc, ok := cc.(*zeroMITMConn)
	if !ok {
		return nil
	}

	tconn := tls.Server(*conn, &tls.Config{
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			key := zeroNextProtoCacheKey{
				ServerName: chi.ServerName,
				NextProtos: strings.Join(chi.SupportedProtos, " "),
			}

			zeroNextProtoCacheMu.Lock()
			nextProto, ok := zeroNextProtoCache.Get(key)
			zeroNextProtoCacheMu.Unlock()

			if err := struc.Pack(mcc, &zeroTLSRequest{
				ServerName: key.ServerName,
				Insecure:   mcc.mitmConfig.Insecure,
				NextProtos: key.NextProtos,
				NeedProto:  !ok,
			}); err != nil {
				return nil, err
			}

			if !ok {
				var response zeroTLSResponse
				if err := struc.Unpack(mcc, &response); err != nil {
					return nil, err
				}
				nextProto = response.NextProto

				zeroNextProtoCacheMu.Lock()
				zeroNextProtoCache.Add(key, nextProto)
				zeroNextProtoCacheMu.Unlock()
			}

			return &tls.Config{
				GetCertificate: mcc.mitmConfig.GetCertificate,
				NextProtos:     strings.Fields(nextProto.(string)),
			}, nil
		},
	})

	if err := tconn.Handshake(); err != nil {
		return err
	}

	*conn = tconn
	return nil
}

type zeroHandler struct {
	options *HandlerOptions
}

func ZeroHandler(opts ...HandlerOption) Handler {
	h := &zeroHandler{}
	h.Init(opts...)
	return h
}

func (h *zeroHandler) Init(options ...HandlerOption) {
	if h.options == nil {
		h.options = &HandlerOptions{}
	}
	for _, opt := range options {
		opt(h.options)
	}
}

func (h *zeroHandler) Handle(conn net.Conn) {
	defer conn.Close()

	var request zeroTCPRequest
	if err := struc.Unpack(conn, &request); err != nil {
		log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	retries := 1
	if h.options.Chain != nil && h.options.Chain.Retries > 0 {
		retries = h.options.Chain.Retries
	}
	if h.options.Retries > 0 {
		retries = h.options.Retries
	}

	var err error
	var cc net.Conn
	var route *Chain
	for i := 0; i < retries; i++ {
		route, err = h.options.Chain.selectRouteFor(request.Address)
		if err != nil {
			log.Logf("[zero] %s -> %s : %s",
				conn.RemoteAddr(), conn.LocalAddr(), err)
			continue
		}

		buf := bytes.Buffer{}
		fmt.Fprintf(&buf, "%s -> %s -> ",
			conn.RemoteAddr(), h.options.Node.String())
		for _, nd := range route.route {
			fmt.Fprintf(&buf, "%d@%s -> ", nd.ID, nd.String())
		}
		fmt.Fprintf(&buf, "%s", request.Address)
		log.Log("[route]", buf.String())

		cc, err = route.Dial(request.Address,
			TimeoutChainOption(h.options.Timeout),
			HostsChainOption(h.options.Hosts),
			ResolverChainOption(h.options.Resolver),
		)
		if err == nil {
			break
		}
		log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
	}

	if err != nil {
		return
	}
	defer cc.Close()

	if request.UseMITM {
		var request zeroTLSRequest
		if err := struc.Unpack(conn, &request); err != nil {
			log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return
		}

		tcc := tls.Client(cc, &tls.Config{
			ServerName:         request.ServerName,
			InsecureSkipVerify: request.Insecure,
			NextProtos:         strings.Fields(request.NextProtos),
		})

		if request.NeedProto {
			if err := tcc.Handshake(); err != nil {
				log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return
			}
			if err := struc.Pack(conn, &zeroTLSResponse{
				NextProto: tcc.ConnectionState().NegotiatedProtocol,
			}); err != nil {
				log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return
			}
		}

		cc = tcc
	}

	if err := maybeWrapMITMConn(&conn, cc); err != nil {
		log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), request.Address, err)
		return
	}

	log.Logf("[zero] %s <-> %s", conn.RemoteAddr(), request.Address)
	transport(conn, cc)
	log.Logf("[zero] %s >-< %s", conn.RemoteAddr(), request.Address)
}
