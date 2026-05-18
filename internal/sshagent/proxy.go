//go:build linux

package sshagent

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

// ProxyMode forwards SSH agent messages to an existing SSH_AUTH_SOCK.
type ProxyMode struct {
	targetSocket string
}

// NewProxyMode creates a new proxy that forwards to the existing SSH agent.
func NewProxyMode() (*ProxyMode, error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, fmt.Errorf("sshagent: SSH_AUTH_SOCK not set, cannot proxy")
	}
	return &ProxyMode{targetSocket: sock}, nil
}

// Forward forwards raw message bytes to the upstream agent and returns the response.
func (p *ProxyMode) Forward(msg []byte) ([]byte, error) {
	conn, err := net.Dial("unix", p.targetSocket)
	if err != nil {
		return nil, fmt.Errorf("sshagent: failed to connect to upstream agent: %w", err)
	}
	defer conn.Close()

	if err := writeMessage(conn, msg); err != nil {
		return nil, fmt.Errorf("sshagent: failed to send to upstream: %w", err)
	}

	resp, err := readMessage(conn)
	if err != nil {
		return nil, fmt.Errorf("sshagent: failed to read from upstream: %w", err)
	}

	return resp, nil
}

// AddKey adds a key to the upstream agent.
func (p *ProxyMode) AddKey(key agent.AddedKey) error {
	conn, err := net.Dial("unix", p.targetSocket)
	if err != nil {
		return fmt.Errorf("sshagent: failed to connect to upstream agent: %w", err)
	}
	defer conn.Close()

	extAgent := agent.NewClient(conn)
	return extAgent.Add(key)
}

// RemoveAllKeys removes all keys from the upstream agent.
func (p *ProxyMode) RemoveAllKeys() error {
	conn, err := net.Dial("unix", p.targetSocket)
	if err != nil {
		return fmt.Errorf("sshagent: failed to connect to upstream agent: %w", err)
	}
	defer conn.Close()

	extAgent := agent.NewClient(conn)
	return extAgent.RemoveAll()
}

// ListKeys lists all keys in the upstream agent.
func (p *ProxyMode) ListKeys() ([]*agent.Key, error) {
	conn, err := net.Dial("unix", p.targetSocket)
	if err != nil {
		return nil, fmt.Errorf("sshagent: failed to connect to upstream agent: %w", err)
	}
	defer conn.Close()

	extAgent := agent.NewClient(conn)
	return extAgent.List()
}
