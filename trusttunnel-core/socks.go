package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

func readAddress(r io.Reader) (string, error) {
	kind := make([]byte, 1)
	if _, e := io.ReadFull(r, kind); e != nil {
		return "", e
	}
	var host string
	switch kind[0] {
	case 1:
		b := make([]byte, 4)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = net.IP(b).String()
	case 4:
		b := make([]byte, 16)
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = net.IP(b).String()
	case 3:
		size := make([]byte, 1)
		if _, e := io.ReadFull(r, size); e != nil || size[0] == 0 {
			return "", errors.New("invalid domain")
		}
		b := make([]byte, int(size[0]))
		if _, e := io.ReadFull(r, b); e != nil {
			return "", e
		}
		host = string(b)
	default:
		return "", errors.New("invalid address type")
	}
	port := make([]byte, 2)
	if _, e := io.ReadFull(r, port); e != nil {
		return "", e
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port)))), nil
}
func addressBytes(address *net.UDPAddr) []byte {
	ip := address.IP.To4()
	kind := byte(1)
	if ip == nil {
		kind = 4
		ip = address.IP.To16()
	}
	b := append([]byte{kind}, ip...)
	return binary.BigEndian.AppendUint16(b, uint16(address.Port))
}
func reply(conn net.Conn, code byte, addr *net.UDPAddr) {
	if addr == nil {
		addr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	}
	conn.Write(append([]byte{5, code, 0}, addressBytes(addr)...))
}
func (c *Client) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))
	head := make([]byte, 2)
	if _, e := io.ReadFull(conn, head); e != nil || head[0] != 5 || head[1] == 0 {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, e := io.ReadFull(conn, methods); e != nil {
		return
	}
	auth := false
	for _, m := range methods {
		if m == 0 {
			auth = true
		}
	}
	if !auth {
		conn.Write([]byte{5, 255})
		return
	}
	if _, e := conn.Write([]byte{5, 0}); e != nil {
		return
	}
	req := make([]byte, 3)
	if _, e := io.ReadFull(conn, req); e != nil || req[0] != 5 || req[2] != 0 {
		return
	}
	target, e := readAddress(conn)
	if e != nil {
		return
	}
	if req[1] == 3 {
		c.serveUDP(conn)
		return
	}
	if req[1] != 1 {
		reply(conn, 7, nil)
		return
	}
	host, _, e := net.SplitHostPort(target)
	if e != nil {
		return
	}
	if ip, e := netip.ParseAddr(host); e == nil && ip.Is6() && !ip.Is4In6() && !c.cfg.HasIPv6 {
		reply(conn, 8, nil)
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream, e := c.open(ctx, target, "RX-PRO")
	if e != nil {
		log.Print(e)
		reply(conn, 5, nil)
		return
	}
	defer upstream.Close()
	reply(conn, 0, nil)
	conn.SetDeadline(time.Time{})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, conn); upstream.CloseWrite() }()
	go func() { defer wg.Done(); io.Copy(conn, upstream); conn.Close(); upstream.Close() }()
	wg.Wait()
}

func dnsAddress(value string) (string, error) {
	if strings.HasPrefix(value, "tcp://") {
		value = strings.TrimPrefix(value, "tcp://")
	}
	if ip, err := netip.ParseAddr(value); err == nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "", errors.New("DNS upstream must be an IP address or tcp://IP:port in this TEST")
	}
	if _, err = netip.ParseAddr(host); err != nil {
		return "", errors.New("DNS bootstrap must be an IP address")
	}
	if p, e := strconv.Atoi(port); e != nil || p < 1 || p > 65535 {
		return "", errors.New("invalid DNS port")
	}
	return value, nil
}
func (c *Client) resolve(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	dns := c.cfg.DNSUpstreams
	if len(dns) == 0 {
		dns = []string{"1.1.1.1"}
	}
	var last error = errors.New("tunneled DNS returned no addresses")
	for _, server := range dns {
		dest, e := dnsAddress(server)
		if e != nil {
			return nil, e
		}
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { return c.open(ctx, dest, "RX-PRO-DNS") }}
		family := "ip4"
		if c.cfg.HasIPv6 {
			family = "ip"
		}
		ips, e := resolver.LookupIP(ctx, family, host)
		if e == nil && len(ips) > 0 {
			return ips[0], nil
		}
		if e != nil {
			last = e
		}
	}
	return nil, last
}

// _udp2 uses IPv4 padded with twelve ZERO bytes, not IPv4-mapped ::ffff.
func paddedIP(ip net.IP) []byte {
	b := make([]byte, 16)
	if v4 := ip.To4(); v4 != nil {
		copy(b[12:], v4)
	} else {
		copy(b, ip.To16())
	}
	return b
}
func decodeIP(b []byte) net.IP {
	zero := true
	for _, v := range b[:12] {
		if v != 0 {
			zero = false
		}
	}
	if zero && !(b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 1) {
		return net.IP(append([]byte{}, b[12:16]...))
	}
	return net.IP(append([]byte{}, b...))
}
func udpFrame(source, destination *net.UDPAddr, payload []byte) []byte {
	app := []byte("RX-PRO")
	body := paddedIP(source.IP)
	body = binary.BigEndian.AppendUint16(body, uint16(source.Port))
	body = append(body, paddedIP(destination.IP)...)
	body = binary.BigEndian.AppendUint16(body, uint16(destination.Port))
	body = append(body, byte(len(app)))
	body = append(body, app...)
	body = append(body, payload...)
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}
func readUDPFrame(r io.Reader) (*net.UDPAddr, *net.UDPAddr, []byte, error) {
	size := make([]byte, 4)
	if _, e := io.ReadFull(r, size); e != nil {
		return nil, nil, nil, e
	}
	length := binary.BigEndian.Uint32(size)
	if length < 36 || length > 65571 {
		return nil, nil, nil, errors.New("invalid UDP frame length")
	}
	b := make([]byte, int(length))
	if _, e := io.ReadFull(r, b); e != nil {
		return nil, nil, nil, e
	}
	src := &net.UDPAddr{IP: decodeIP(b[:16]), Port: int(binary.BigEndian.Uint16(b[16:18]))}
	dst := &net.UDPAddr{IP: decodeIP(b[18:34]), Port: int(binary.BigEndian.Uint16(b[34:36]))}
	return src, dst, b[36:], nil
}

func (c *Client) serveUDP(control net.Conn) {
	udp, e := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		reply(control, 1, nil)
		return
	}
	defer udp.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	upstream, e := c.open(ctx, "_udp2", "_udp2")
	if e != nil {
		log.Print(e)
		reply(control, 1, nil)
		return
	}
	defer upstream.Close()
	reply(control, 0, udp.LocalAddr().(*net.UDPAddr))
	control.SetDeadline(time.Time{})
	go func() { io.Copy(io.Discard, control); cancel(); upstream.Close(); udp.Close() }()
	var mu sync.Mutex
	var peer *net.UDPAddr
	go func() {
		defer udp.Close()
		defer control.Close()
		for {
			src, dst, payload, e := readUDPFrame(upstream)
			if e != nil {
				return
			}
			mu.Lock()
			p := peer
			mu.Unlock()
			if p == nil || p.Port != dst.Port || !p.IP.Equal(dst.IP) {
				continue
			}
			packet := append([]byte{0, 0, 0}, addressBytes(src)...)
			packet = append(packet, payload...)
			udp.WriteToUDP(packet, p)
		}
	}()
	buffer := make([]byte, 65535)
	for {
		udp.SetReadDeadline(time.Now().Add(120 * time.Second))
		n, p, e := udp.ReadFromUDP(buffer)
		if e != nil {
			return
		}
		if !p.IP.IsLoopback() || n < 7 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 {
			continue
		}
		mu.Lock()
		if peer == nil {
			peer = p
		}
		match := peer.Port == p.Port && peer.IP.Equal(p.IP)
		mu.Unlock()
		if !match {
			continue
		}
		reader := bytes.NewReader(buffer[3:n])
		target, e := readAddress(reader)
		if e != nil {
			continue
		}
		host, port, e := net.SplitHostPort(target)
		if e != nil {
			continue
		}
		pn, _ := strconv.Atoi(port)
		resolveCtx, resolveCancel := context.WithTimeout(ctx, 7*time.Second)
		ip, e := c.resolve(resolveCtx, host)
		resolveCancel()
		if e != nil {
			continue
		}
		if ip.To4() == nil && !c.cfg.HasIPv6 {
			continue
		}
		payload, _ := io.ReadAll(reader)
		frame := udpFrame(p, &net.UDPAddr{IP: ip, Port: pn}, payload)
		if _, e = upstream.Write(frame); e != nil {
			return
		}
	}
}
