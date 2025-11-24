package main

import (
	"errors"
	"github.com/Gurpartap/logrus-stack"
	"github.com/sirupsen/logrus"
	"github.com/tsurubee/sshr/sshr"
	"github.com/tsurubee/sshr/authstore"
)

var backendClient *BackendClient

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	stackLevels := []logrus.Level{logrus.PanicLevel, logrus.FatalLevel}
	logrus.AddHook(logrus_stack.NewHook(stackLevels, stackLevels))
	
	backendClient = NewBackendClient()
}

func main() {
	confFile := "./example.toml"

	sshServer, err := sshr.NewSSHServer(confFile)
	if err != nil {
		logrus.Fatal(err)
	}

	// Use only the existing FindUpstreamHook - NO modifications to sshr.crypto needed!
	sshServer.ProxyConfig.FindUpstreamHook = FindUpstreamByUsername
	
	if err := sshServer.Run(); err != nil {
		logrus.Fatal(err)
	}
}

func FindUpstreamByUsername(username string) (string, error) {
	logrus.Infof("Querying backend for user: %s", username)
	
	// Query backend API
	authResp, err := backendClient.GetUserAuth(username)
	if err != nil {
		logrus.Errorf("Failed to get auth from backend for user %s: %v", username, err)
		return "", err
	}
	
	if authResp.UpstreamHost == "" {
		return "", errors.New(username + "'s host is not found in backend!")
	}
	
	// Store full response in authstore for sshr/proxy.go to use
	authstore.Set(username, &authstore.AuthInfo{
		PasswordHash: authResp.PasswordHash,
		UpstreamHost: authResp.UpstreamHost,
		UpstreamPort: authResp.UpstreamPort,
		UpstreamUser: authResp.UpstreamUser,
		UpstreamPass: authResp.UpstreamPass,
	})
	
	logrus.Infof("Backend returned upstream: %s:%s (user: %s)", 
		authResp.UpstreamHost, authResp.UpstreamPort, authResp.UpstreamUser)
	
	// Return just the hostname (as expected by FindUpstreamHook)
	return authResp.UpstreamHost, nil
}