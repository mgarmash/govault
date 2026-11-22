package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// ttyTerminal prompts on stderr and reads from the terminal on stdin.
type ttyTerminal struct {
	in  *os.File
	out io.Writer
	r   *bufio.Reader
}

func newTerminal(in *os.File, out io.Writer) Terminal {
	return &ttyTerminal{in: in, out: out, r: bufio.NewReader(in)}
}

func (t *ttyTerminal) ReadLine(prompt string) (string, error) {
	fmt.Fprint(t.out, "? "+prompt+" ")
	line, err := t.r.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (t *ttyTerminal) ReadSecret(prompt string) (string, error) {
	fmt.Fprint(t.out, "? "+prompt+" [input is hidden] ")
	b, err := term.ReadPassword(int(t.in.Fd()))
	fmt.Fprintln(t.out)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
