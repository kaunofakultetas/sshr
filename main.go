package main

import (
	"github.com/sirupsen/logrus"
	"github.com/Gurpartap/logrus-stack"
	"github.com/tsurubee/sshr/sshr"
	"errors"
	"strings"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	stackLevels := []logrus.Level{logrus.PanicLevel, logrus.FatalLevel}
	logrus.AddHook(logrus_stack.NewHook(stackLevels, stackLevels))
}

func main() {
	confFile := "./example.toml"

	sshServer, err := sshr.NewSSHServer(confFile)
	if err != nil {
		logrus.Fatal(err)
	}

	sshServer.ProxyConfig.FindUpstreamHook = FindUpstreamByUsername
	if err := sshServer.Run(); err != nil {
		logrus.Fatal(err)
	}
}

func FindUpstreamByUsername(username string) (string, error) {
	// Check if username starts with "server"
	if strings.HasPrefix(username, "server") {
		serverNum := strings.TrimPrefix(username, "server")
		if serverNum != "" {
			return "hosting-users-dind-" + serverNum, nil
		}
	}
	
	// Fallback or error
	return "", errors.New(username + "'s host is not found!")
}
