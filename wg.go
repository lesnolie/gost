package gost

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"

	"github.com/octeep/wireproxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wireguardConnector struct {
}

func WireguardConnector() Connector {
	return &wireguardConnector{}
}

func (c *wireguardConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *wireguardConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	return conn.(*wireguardConn).DialContext(ctx, network, address)
}

type wireguardTransporter struct {
	conn *wireguardConn
}

func WireguardTransporter(confPath string) (Transporter, error) {
	conf, err := wireproxy.ParseConfig(confPath)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(conf.Device.Endpoint, conf.Device.DNS, conf.Device.MTU)
	if err != nil {
		return nil, err
	}

	logger := &device.Logger{
		Verbosef: device.DiscardLogf,
		Errorf:   func(f string, v ...any) { log.Output(2, "[wg] [E] "+fmt.Sprintf(f, v...)) },
	}
	if Debug {
		logger.Verbosef = func(f string, v ...any) { log.Output(2, "[wg] [D] "+fmt.Sprintf(f, v...)) }
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	request := &bytes.Buffer{}
	fmt.Fprintf(request, "private_key=%s\n", conf.Device.SecretKey)
	for _, peer := range conf.Device.Peers {
		fmt.Fprintf(request, "public_key=%s\n", peer.PublicKey)
		fmt.Fprintf(request, "persistent_keepalive_interval=%d\n", peer.KeepAlive)
		fmt.Fprintf(request, "preshared_key=%s\n", peer.PreSharedKey)

		if peer.Endpoint != nil {
			fmt.Fprintf(request, "endpoint=%s\n", *peer.Endpoint)
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				fmt.Fprintf(request, "allowed_ip=%s\n", ip.String())
			}
		} else {
			fmt.Fprintf(request, "allowed_ip=0.0.0.0/0\nallowed_ip=::0/0\n")
		}
	}

	err = dev.IpcSetOperation(request)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return &wireguardTransporter{
		conn: &wireguardConn{DialContext: tnet.DialContext},
	}, nil
}

func (tr *wireguardTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	return tr.conn, nil
}

func (tr *wireguardTransporter) Handshake(conn net.Conn, options ...HandshakeOption) (net.Conn, error) {
	return conn, nil
}

func (tr *wireguardTransporter) Multiplex() bool {
	return true
}

type wireguardConn struct {
	nopConn
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}
