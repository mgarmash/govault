package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/totp"
)

// The contract fixtures in testdata/bw are the outputs of the official bw
// 2026.11.0 release against the fake server. Regenerate them with
//
//	BW_BINARY=/path/to/bw go test ./internal/cli -run TestCaptureBWFixtures
//
// which runs bw with a private BITWARDENCLI_APPDATA_DIR per case.

type capturedStep struct {
	Args   []string `json:"args"`
	Stdout string   `json:"stdout"`
	Stderr string   `json:"stderr"`
	Exit   int      `json:"exit"`
}

type capturedCase struct {
	Name  string         `json:"name"`
	Steps []capturedStep `json:"steps"`
}

// runner runs one client invocation for a contract case.
type runner interface {
	run(t *testing.T, step contractStep, env map[string]string) (stdout, stderr string, exit int)
	// profile prepares a fresh profile in the given state and returns the
	// environment for it and its session key ("" unless unlocked).
	profile(t *testing.T, state string) (env map[string]string, session string)
}

var sessionPattern = regexp.MustCompile(`[A-Za-z0-9+/]{86}==`)

func runCase(t *testing.T, r runner, c contractCase, srv *fakeserver.Server) capturedCase {
	env, session := r.profile(t, c.State)
	tmp := t.TempDir()
	out := capturedCase{Name: c.Name}
	for _, step := range c.Steps {
		stepEnv := map[string]string{}
		for k, v := range env {
			stepEnv[k] = v
		}
		for k, v := range step.Env {
			stepEnv[k] = v
		}
		if step.Session && session != "" {
			stepEnv["BW_SESSION"] = session
		}
		recorded := append([]string(nil), step.Args...)
		step.Args = make([]string, len(recorded))
		for i, a := range recorded {
			step.Args[i] = strings.ReplaceAll(a, "{{TMP}}", tmp)
		}
		for name, content := range step.Files {
			if err := os.WriteFile(filepath.Join(tmp, name), []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		stdout, stderr, exit := r.run(t, step, stepEnv)
		if m := sessionPattern.FindString(stdout); m != "" && exit == 0 && (step.Args[0] == "unlock" || step.Args[0] == "login") {
			session = m
		}
		out.Steps = append(out.Steps, capturedStep{
			Args:   recorded,
			Stdout: normalize(stdout, srv, tmp),
			Stderr: normalize(stderr, srv, tmp),
			Exit:   exit,
		})
	}
	return out
}

var (
	isoTime  = regexp.MustCompile(`20\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z`)
	tmpNames = regexp.MustCompile(`(/private)?/var/folders/[^"\s]+?/Test[^/"\s]*/\d+`)
)

// normalize replaces values that legitimately differ between runs: the
// server address, session keys, temp paths, sync times and TOTP codes.
func normalize(s string, srv *fakeserver.Server, tmp string) string {
	s = strings.ReplaceAll(s, srv.URL(), "{{SERVER}}")
	s = strings.ReplaceAll(s, tmp, "{{TMP}}")
	s = strings.ReplaceAll(s, "/private"+tmp, "{{TMP}}")
	s = sessionPattern.ReplaceAllString(s, "{{SESSION}}")
	s = isoTime.ReplaceAllStringFunc(s, func(m string) string {
		if strings.HasPrefix(m, "2025-") || strings.HasPrefix(m, "2026-0") {
			return m // fixture dates
		}
		return "{{TIME}}"
	})
	now := time.Now()
	cfg, _ := totp.ParseTOTP(fakeserver.TOTPSecret)
	for _, at := range []time.Time{now, now.Add(-30 * time.Second), now.Add(30 * time.Second)} {
		if code, _, _, err := totp.Generate(cfg, at); err == nil && strings.Contains(s, code) && len(strings.TrimSpace(s)) < 40 {
			s = strings.ReplaceAll(s, code, "{{TOTP}}")
		}
	}
	return s
}

const fixtureDir = "testdata/bw"

func TestCaptureBWFixtures(t *testing.T) {
	bin := os.Getenv("BW_BINARY")
	if bin == "" {
		t.Skip("set BW_BINARY to the official bw binary to regenerate contract fixtures")
	}
	if err := os.MkdirAll(fixtureDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range contractCases {
		if f := os.Getenv("BW_CASE"); f != "" && f != c.Name {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			// Each case gets a fresh server, so writes start from the
			// fixture vault and new IDs are the same for bw and gv.
			srv := fakeserver.NewTLS(fakeserver.WithKDFIterations(600000))
			defer srv.Close()
			caFile := filepath.Join(t.TempDir(), "ca.pem")
			if err := os.WriteFile(caFile, srv.CertPEM(), 0o600); err != nil {
				t.Fatal(err)
			}
			got := runCase(t, &bwRunner{bin: bin, ca: caFile, srv: srv}, c, srv)
			raw, err := json.MarshalIndent(got, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(fixtureDir, c.Name+".json"), append(raw, '\n'), 0o644); err != nil {
				t.Fatal(err)
			}
		})
	}
}

type bwRunner struct {
	bin string
	ca  string
	srv *fakeserver.Server
}

func (r *bwRunner) run(t *testing.T, step contractStep, env map[string]string) (string, string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.bin, step.Args...)
	cmd.Env = []string{"HOME=" + env["HOME"], "PATH=/usr/bin:/bin", "NODE_EXTRA_CA_CERTS=" + r.ca}
	for k, v := range env {
		if k != "HOME" {
			cmd.Env = append(cmd.Env, k+"="+v)
		}
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.Stdin = strings.NewReader(step.Stdin)
	err := cmd.Run()
	exit := 0
	if ee, ok := err.(*exec.ExitError); ok {
		exit = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("bw %v: %v", step.Args, err)
	}
	return stdout.String(), stderr.String(), exit
}

func (r *bwRunner) profile(t *testing.T, state string) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	env := map[string]string{"HOME": dir, "BITWARDENCLI_APPDATA_DIR": filepath.Join(dir, "bw")}
	if err := os.MkdirAll(env["BITWARDENCLI_APPDATA_DIR"], 0o700); err != nil {
		t.Fatal(err)
	}
	r.run(t, contractStep{Args: []string{"status"}}, env)
	if state == "loggedout" {
		return env, ""
	}
	if _, errOut, code := r.run(t, contractStep{Args: []string{"config", "server", r.srv.URL()}}, env); code != 0 {
		t.Fatalf("bw config server: %s", errOut)
	}
	if state == "configured" {
		return env, ""
	}
	loginEnv := map[string]string{"PW": fakeserver.Password}
	for k, v := range env {
		loginEnv[k] = v
	}
	out, errOut, code := r.run(t, contractStep{Args: []string{"login", fakeserver.Email, "--passwordenv", "PW", "--raw"}}, loginEnv)
	if code != 0 {
		t.Fatalf("bw login: %s", errOut)
	}
	return env, strings.TrimSpace(out)
}

func loadFixture(t *testing.T, name string) capturedCase {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(fixtureDir, name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v (regenerate with BW_BINARY, see TestCaptureBWFixtures)", name, err)
	}
	var c capturedCase
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}
