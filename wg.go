package gost

import (
	"context"
	"fmt"
	"log"
	"net"
	"reflect"
	_ "unsafe"

	"github.com/octeep/wireproxy"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

//go:linkname createIPCRequest github.com/octeep/wireproxy.createIPCRequest
func createIPCRequest(conf *wireproxy.DeviceConfig) (*wireproxy.DeviceSetting, error)

func NewWireguardTun(confPath string) (*netstack.Net, error) {
	conf, err := wireproxy.ParseConfig(confPath)
	if err != nil {
		return nil, err
	}

	setting, err := createIPCRequest(conf.Device)
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

	err = dev.IpcSet(reflect.ValueOf(setting).Elem().FieldByName("ipcRequest").String())
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return tnet, nil
}

type wireguardConnector struct {
	tnet *netstack.Net
}

func WireguardConnector(tnet *netstack.Net) Connector {
	return &wireguardConnector{tnet: tnet}
}

func (c *wireguardConnector) Connect(conn net.Conn, address string, options ...ConnectOption) (net.Conn, error) {
	return c.ConnectContext(context.Background(), conn, "tcp", address, options...)
}

func (c *wireguardConnector) ConnectContext(ctx context.Context, conn net.Conn, network, address string, options ...ConnectOption) (net.Conn, error) {
	opts := &ConnectOptions{}
	for _, option := range options {
		option(opts)
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = ConnectTimeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	return c.tnet.DialContext(ctx, network, address)
}

type wireguardTransporter struct {
	tcpTransporter
}

func WireguardTransporter() Transporter {
	return &wireguardTransporter{}
}

func (tr *wireguardTransporter) Dial(addr string, options ...DialOption) (conn net.Conn, err error) {
	return nopClientConn, nil
}
