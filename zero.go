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

type zeroTcpRequest struct {
	AddressLen int `struc:"uint8,sizeof=Address"`
	Address    string
	UseMITM    bool
}

type zeroTlsRequest struct {
	ServerNameLen        int `struc:"uint8,sizeof=ServerName"`
	ServerName           string
	Insecure             bool
	SupportH1, SupportH2 bool
	NeedProto            bool
}

type zeroTlsResponse struct {
	UseH2 bool
}

type zeroHTTP2CacheKey struct {
	ServerName           string
	SupportH1, SupportH2 bool
}

var (
	zeroHTTP2Cache   = lru.New(1024 * 1024)
	zeroHTTP2CacheMu sync.Mutex
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
	if err := struc.Pack(conn, &zeroTcpRequest{
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
			key := zeroHTTP2CacheKey{ServerName: chi.ServerName}
			key.SupportH1, key.SupportH2 = mitmString2Bool(chi.SupportedProtos)

			zeroHTTP2CacheMu.Lock()
			useH2, ok := zeroHTTP2Cache.Get(key)
			zeroHTTP2CacheMu.Unlock()

			if err := struc.Pack(mcc, &zeroTlsRequest{
				ServerName: key.ServerName,
				Insecure:   mcc.mitmConfig.Insecure,
				SupportH1:  key.SupportH1,
				SupportH2:  key.SupportH2,
				NeedProto:  !ok,
			}); err != nil {
				return nil, err
			}

			if !ok {
				var response zeroTlsResponse
				if err := struc.Unpack(mcc, &response); err != nil {
					return nil, err
				}
				useH2 = response.UseH2

				zeroHTTP2CacheMu.Lock()
				zeroHTTP2Cache.Add(key, useH2)
				zeroHTTP2CacheMu.Unlock()
			}

			return &tls.Config{
				GetCertificate: mcc.mitmConfig.GetCertificate,
				NextProtos:     mitmBool2String(!useH2.(bool), useH2.(bool)),
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

	var request zeroTcpRequest
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
		var request zeroTlsRequest
		if err := struc.Unpack(conn, &request); err != nil {
			log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
			return
		}

		tcc := tls.Client(cc, &tls.Config{
			ServerName:         request.ServerName,
			InsecureSkipVerify: request.Insecure,
			NextProtos:         mitmBool2String(request.SupportH1, request.SupportH2),
		})

		if request.NeedProto {
			if err := tcc.Handshake(); err != nil {
				log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return
			}
			if err := struc.Pack(conn, &zeroTlsResponse{
				UseH2: tcc.ConnectionState().NegotiatedProtocol == "h2",
			}); err != nil {
				log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
				return
			}
		}

		cc = tcc
	}

	if err := maybeWrapMITMConn(&conn, cc); err != nil {
		log.Logf("[zero] %s -> %s : %s", conn.RemoteAddr(), conn.LocalAddr(), err)
		return
	}

	log.Logf("[zero] %s <-> %s", conn.RemoteAddr(), request.Address)
	transport(conn, cc)
	log.Logf("[zero] %s >-< %s", conn.RemoteAddr(), request.Address)
}

func mitmString2Bool(protos []string) (supportH1, supportH2 bool) {
	for _, proto := range protos {
		if proto == "http/1.1" {
			supportH1 = true
		}
		if proto == "h2" {
			supportH2 = true
		}
	}
	return
}

func mitmBool2String(supportH1, supportH2 bool) (protos []string) {
	if supportH1 && supportH2 {
		protos = []string{"h2", "http/1.1"}
	} else if supportH1 {
		protos = []string{"http/1.1"}
	} else if supportH2 {
		protos = []string{"h2"}
	}
	return
}
