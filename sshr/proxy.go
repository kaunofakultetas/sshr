package sshr

import (
	"encoding/binary"
	"fmt"
	"net"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"github.com/tsurubee/sshr/authstore"
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

	for {
		authRequestMsg, err := d.GetAuthRequestMsg()
		if err != nil {
			return nil, err
		}

		// We only support password auth for now, and we need to intercept it to verify against backend
		// If client sends "none" (common first step), reject it locally so we don't confuse upstream
		if authRequestMsg.Method == "none" {
			logrus.Debugf("Ignoring 'none' auth method from user %s", authRequestMsg.User)
			p := &ssh.ProxyConn{Downstream: d}
			if err := p.SendFailureMsg("password"); err != nil {
				return nil, err
			}
			continue
		}
		
		if authRequestMsg.Method != "password" {
			logrus.Warnf("Unsupported auth method %s from user %s", authRequestMsg.Method, authRequestMsg.User)
			p := &ssh.ProxyConn{Downstream: d}
			if err := p.SendFailureMsg("password"); err != nil {
				return nil, err
			}
			continue
		}
		
		// Valid message (password). Proceed with logic.
		username := authRequestMsg.User
		logrus.Infof("User %s attempting to connect", username)
		
		// Call FindUpstreamHook - this queries backend and populates authstore
		upstreamHost, err := proxyConf.FindUpstreamHook(username)
		if err != nil {
			logrus.Errorf("FindUpstreamHook failed for %s: %v", username, err)
			p := &ssh.ProxyConn{User: username, Downstream: d}
			if sendErr := p.SendFailureMsg("password"); sendErr != nil {
				return nil, sendErr
			}
			continue
		}
		
		// Get full auth info from authstore (populated by FindUpstreamHook in main.go)
		authInfo := authstore.Get(username)
		
		var upstreamPort, upstreamUser, passwordHash, upstreamPass string
		if authInfo != nil {
			upstreamPort = authInfo.UpstreamPort
			upstreamUser = authInfo.UpstreamUser
			passwordHash = authInfo.PasswordHash
			upstreamPass = authInfo.UpstreamPass
			logrus.Infof("Using backend auth for user %s -> %s@%s:%s", 
				username, upstreamUser, upstreamHost, upstreamPort)
		} else {
			// Fallback if backend didn't provide full info
			upstreamPort = proxyConf.DestinationPort
			upstreamUser = "root"
			passwordHash = "root"
			upstreamPass = "root"
			logrus.Warnf("No backend auth found for %s, using defaults", username)
		}

		// Verify password LOCALLY first
		password, err := parsePasswordPayload(authRequestMsg.Payload)
		if err != nil {
			logrus.Errorf("Failed to parse password payload: %v", err)
			// If payload is bad, maybe we should close? Or just fail auth?
			// Let's fail auth.
			p := &ssh.ProxyConn{Downstream: d}
			p.SendFailureMsg("password")
			continue
		}

		if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
			logrus.Warnf("Password verification failed for user %s: %v", username, err)
			p := &ssh.ProxyConn{Downstream: d}
			if err := p.SendFailureMsg("password"); err != nil {
				return nil, err
			}
			// CRITICAL FIX: Do not return! Continue loop to allow retry.
			continue
		}

		logrus.Infof("Password verified for user %s. Connecting to upstream...", username)

		// Create proxy connection structure
		p := &ssh.ProxyConn{
			User:            upstreamUser,
			Downstream:      d,
			DestinationHost: upstreamHost,
		}

		// Connect to upstream server ONLY after successful auth
		upConn, err := net.Dial("tcp", upstreamHost+":"+upstreamPort)
		if err != nil {
			logrus.Errorf("Failed to connect to upstream %s:%s: %v", upstreamHost, upstreamPort, err)
			// If we can't connect to upstream, we can't really proceed. 
			// We could try to fail auth, but the user provided correct password.
			// Returning error closes connection, which is probably appropriate here as it's a system error.
			return p, err
		}

		u, err := ssh.NewUpstreamConn(upConn, &ssh.ClientConfig{
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
		if err != nil {
			logrus.Errorf("Failed to create upstream SSH connection: %v", err)
			return p, err
		}
		
		p.Upstream = u

		logrus.Infof("Authenticating to upstream as %s using provided upstream password", upstreamUser)
		
		// Use upstream password provided by backend
		authRequestMsg.Payload = createPasswordPayload(upstreamPass)
		authRequestMsg.User = upstreamUser
		
		if err := p.AuthenticateProxyConn(authRequestMsg, proxyConf); err != nil {
			logrus.Errorf("Upstream authentication failed: %v", err)
			u.Close()
			// If upstream auth fails (even though we verified local password), we have to fail.
			// Since we already connected, we might need to close upstream and return error or fail auth.
			// If we return error, client gets disconnected.
			return p, err
		}

		logrus.Infof("Successfully authenticated %s to upstream", username)
		return p, nil
	}
}

func createPasswordPayload(password string) []byte {
	// Password payload for SSH protocol:
	// byte      SSH_MSG_USERAUTH_REQUEST (50)
	// boolean   FALSE (for password change)
	// string    password
	//
	// We only create the payload part (after the message type)
	passwordBytes := []byte(password)
	length := len(passwordBytes)
	
	// Payload: [FALSE boolean (1 byte)] + [string length (4 bytes)] + [password bytes]
	payload := make([]byte, 5+length)
	payload[0] = 0 // FALSE boolean (no password change)
	
	// Length as 4 bytes (big-endian)
	payload[1] = byte(length >> 24)
	payload[2] = byte(length >> 16)
	payload[3] = byte(length >> 8)
	payload[4] = byte(length)
	
	// Copy password bytes
	copy(payload[5:], passwordBytes)
	
	return payload
}

func parsePasswordPayload(payload []byte) (string, error) {
	if len(payload) < 5 {
		return "", fmt.Errorf("payload too short")
	}
	// Payload[0] is boolean (FALSE)
	// Payload[1:5] is length (uint32)
	length := binary.BigEndian.Uint32(payload[1:5])
	if uint32(len(payload)) < 5+length {
		return "", fmt.Errorf("payload shorter than length prefix indicates")
	}
	return string(payload[5 : 5+length]), nil
}