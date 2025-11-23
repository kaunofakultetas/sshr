package sshr

import (
	"net"

	"golang.org/x/crypto/ssh"
)

func newSSHProxyConn(conn net.Conn, proxyConf *ssh.ProxyConfig) (proxyConn *ssh.ProxyConn, err error) {
	d, err := ssh.NewDownstreamConn(conn, proxyConf.ServerConfig)
	if err != nil {
		return nil, err
	}
	defer func() {
		if proxyConn == nil {
			d.Close()
		}
	}()

	authRequestMsg, err := d.GetAuthRequestMsg()
	if err != nil {
		return nil, err
	}

	username := authRequestMsg.User
	// Force username to admin for upstream connection
	p := &ssh.ProxyConn{
		User:       "root",
		Downstream: d,
	}
	upstreamHost, err := proxyConf.FindUpstreamHook(username)
	if err != nil {
		if err := p.SendFailureMsg(err.Error()); err != nil {
			return p, err
		}
		return p, err
	}
	p.DestinationHost = upstreamHost

	upConn, err := net.Dial("tcp", upstreamHost+":"+proxyConf.DestinationPort)
	if err != nil {
		return p, err
	}

	u, err := ssh.NewUpstreamConn(upConn, &ssh.ClientConfig{
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		return p, err
	}
	defer func() {
		if proxyConn == nil {
			u.Close()
		}
	}()

	p.Upstream = u

	// Force authentication to password "root"
	// We need to modify authRequestMsg or create a new one if possible, but AuthenticateProxyConn takes the msg.
	// Let's see if we can modify the msg.
	authRequestMsg.User = "root"
	authRequestMsg.Method = "password"
	// Payload for password auth is: boolean(FALSE) + string(password)
	// FALSE is 1 byte (0x00)
	// string is 4 bytes length + bytes
	// "root" length is 4.
	// Payload: [0, 0, 0, 0, 4, 'r', 'o', 'o', 't']
	authRequestMsg.Payload = []byte{0, 0, 0, 0, 4, 'r', 'o', 'o', 't'}

	if err = p.AuthenticateProxyConn(authRequestMsg, proxyConf); err != nil {
		return p, err
	}

	return p, nil
}
