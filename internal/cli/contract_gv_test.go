package cli

import (
	"bytes"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/txchen/govault/internal/fakeserver"
	"github.com/txchen/govault/internal/vaultcore/keyring"
)

// gvRunner runs gv in process against the fake server.
type gvRunner struct {
	srv  *fakeserver.Server
	ring keyring.Store
}

func (r *gvRunner) run(t *testing.T, step contractStep, env map[string]string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(&Environment{
		Args:       append([]string(nil), step.Args...),
		Getenv:     func(k string) string { return env[k] },
		Stdin:      strings.NewReader(step.Stdin),
		Stdout:     &stdout,
		Stderr:     &stderr,
		HTTPClient: r.srv.Client(),
		Keyring: func() (keyring.Store, error) {
			if r.ring == nil {
				return nil, keyring.ErrUnavailable
			}
			return r.ring, nil
		},
		Version: "test",
		GOOS:    "linux",
	})
	return stdout.String(), stderr.String(), code
}

func (r *gvRunner) profile(t *testing.T, state string) (map[string]string, string) {
	t.Helper()
	dir := t.TempDir()
	env := map[string]string{"HOME": dir, "BITWARDENCLI_APPDATA_DIR": filepath.Join(dir, "bw")}
	if state == "loggedout" {
		return env, ""
	}
	if _, errOut, code := r.run(t, contractStep{Args: []string{"config", "server", r.srv.URL()}}, env); code != 0 {
		t.Fatalf("gv config server: %s", errOut)
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
		t.Fatalf("gv login: %s", errOut)
	}
	return env, out
}

var sdkLogLine = regexp.MustCompile(`(?m)^ERROR [^\n]*\n\n`)

// documented differences between bw and gv output, applied before
// comparing:
//   - shell examples name gv instead of bw;
//   - bw's SDK logs internal ERROR lines to stderr before a message.
func comparable(s string) string {
	s = strings.ReplaceAll(s, "$ gv ", "$ bw ")
	return sdkLogLine.ReplaceAllString(s, "")
}

func TestContractMatchesBW(t *testing.T) {
	srv := fakeserver.New()
	defer srv.Close()
	for _, c := range contractCases {
		t.Run(c.Name, func(t *testing.T) {
			want := loadFixture(t, c.Name)
			r := &gvRunner{srv: srv, ring: keyring.NewMemory()}
			got := runCase(t, r, c, srv)
			if len(got.Steps) != len(want.Steps) {
				t.Fatalf("steps = %d, fixture has %d", len(got.Steps), len(want.Steps))
			}
			if testing.Verbose() {
				for _, g := range got.Steps {
					t.Logf("%v => %d %q %q", g.Args, g.Exit, g.Stdout[:min(len(g.Stdout), 120)], g.Stderr)
				}
			}
			for i, g := range got.Steps {
				w := want.Steps[i]
				if g.Exit != w.Exit || comparable(g.Stdout) != comparable(w.Stdout) || comparable(g.Stderr) != comparable(w.Stderr) {
					t.Errorf("gv %s\n exit   %d, bw %d\n stdout %q\n bw     %q\n stderr %q\n bw     %q",
						strings.Join(g.Args, " "), g.Exit, w.Exit, g.Stdout, w.Stdout, g.Stderr, w.Stderr)
				}
			}
		})
	}
}
