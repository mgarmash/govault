package main

import (
	"path/filepath"
	"sync"

	"github.com/txchen/govault/internal/vaultcore/sshagent"
)

type sshAgentHost struct {
	path string

	mu  sync.Mutex
	srv *sshagent.Server
}

func newSSHAgentHost(dataDir string) *sshAgentHost {
	return &sshAgentHost{path: filepath.Join(dataDir, "ssh-agent.sock")}
}

func (h *sshAgentHost) SocketPath() string { return h.path }

func (h *sshAgentHost) Start() error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		return nil
	}
	srv, err := sshagent.Listen(h.path)
	if err != nil {
		return err
	}
	h.srv = srv
	return nil
}

func (h *sshAgentHost) Stop() {
	h.mu.Lock()
	srv := h.srv
	h.srv = nil
	h.mu.Unlock()
	if srv != nil {
		_ = srv.Close()
	}
}

func (h *sshAgentHost) SetKeys(keys []sshagent.Key) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		h.srv.SetKeys(keys)
	}
}

func (h *sshAgentHost) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.srv != nil {
		h.srv.Clear()
	}
}
