//go:build linux && !android

package keyring

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	ssName       = "org.freedesktop.secrets"
	ssPath       = dbus.ObjectPath("/org/freedesktop/secrets")
	ssDefault    = dbus.ObjectPath("/org/freedesktop/secrets/aliases/default")
	ssService    = "org.freedesktop.Secret.Service"
	ssCollection = "org.freedesktop.Secret.Collection"
	ssItem       = "org.freedesktop.Secret.Item"
	ssPrompt     = "org.freedesktop.Secret.Prompt"
	// promptWait bounds how long an unlock prompt may wait for the user.
	promptWait = 2 * time.Minute
)

// secret is the Secret Service's (oayays) secret struct.
type secret struct {
	Session     dbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// secretService keeps items in the default collection of the D-Bus
// Secret Service (GNOME Keyring, KWallet, KeePassXC), with libsecret's
// generic schema and service/account attributes. Values cross the user's
// own session bus in a plain session.
type secretService struct{}

func system() (Store, error) {
	conn, err := sessionBus()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	var owned, activatable bool
	if err := conn.BusObject().Call("org.freedesktop.DBus.NameHasOwner", 0, ssName).Store(&owned); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if !owned {
		var names []string
		if err := conn.BusObject().Call("org.freedesktop.DBus.ListActivatableNames", 0).Store(&names); err == nil {
			activatable = slices.Contains(names, ssName)
		}
	}
	if !owned && !activatable {
		return nil, fmt.Errorf("%w: no Secret Service on the session bus", ErrUnavailable)
	}
	return secretService{}, nil
}

// sessionBus connects to the user's session bus without autolaunching
// one, so a host with no session bus has no credential store.
func sessionBus() (*dbus.Conn, error) {
	addr := os.Getenv("DBUS_SESSION_BUS_ADDRESS")
	if addr == "" {
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			if _, err := os.Stat(filepath.Join(dir, "bus")); err == nil {
				addr = "unix:path=" + filepath.Join(dir, "bus")
			}
		}
	}
	if addr == "" {
		return nil, fmt.Errorf("%w: no D-Bus session bus", ErrUnavailable)
	}
	conn, err := dbus.Connect(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	return conn, nil
}

func (secretService) Name() string { return "secret-service" }

type ssConn struct {
	conn    *dbus.Conn
	session dbus.ObjectPath
}

func openSS() (*ssConn, error) {
	conn, err := sessionBus()
	if err != nil {
		return nil, err
	}
	var out dbus.Variant
	var session dbus.ObjectPath
	if err := conn.Object(ssName, ssPath).Call(ssService+".OpenSession", 0, "plain", dbus.MakeVariant("")).Store(&out, &session); err != nil {
		conn.Close()
		return nil, fmt.Errorf("keyring: Secret Service OpenSession: %w", err)
	}
	return &ssConn{conn: conn, session: session}, nil
}

func (c *ssConn) close() {
	_ = c.conn.Object(ssName, c.session).Call("org.freedesktop.Secret.Session.Close", 0).Err
	c.conn.Close()
}

func attributes(service, account string) map[string]string {
	return map[string]string{"xdg:schema": "org.freedesktop.Secret.Generic", "service": service, "account": account}
}

// search returns the matching items, unlocking any that are locked.
func (c *ssConn) search(service, account string) ([]dbus.ObjectPath, error) {
	var unlocked, locked []dbus.ObjectPath
	if err := c.conn.Object(ssName, ssPath).Call(ssService+".SearchItems", 0, attributes(service, account)).Store(&unlocked, &locked); err != nil {
		return nil, fmt.Errorf("keyring: Secret Service SearchItems: %w", err)
	}
	if len(locked) > 0 {
		opened, err := c.unlock(locked)
		if err != nil {
			return nil, err
		}
		unlocked = append(unlocked, opened...)
	}
	return unlocked, nil
}

func (c *ssConn) unlock(objects []dbus.ObjectPath) ([]dbus.ObjectPath, error) {
	var unlocked []dbus.ObjectPath
	var prompt dbus.ObjectPath
	if err := c.conn.Object(ssName, ssPath).Call(ssService+".Unlock", 0, objects).Store(&unlocked, &prompt); err != nil {
		return nil, fmt.Errorf("keyring: Secret Service Unlock: %w", err)
	}
	if prompt == "/" {
		return unlocked, nil
	}
	result, err := c.prompt(prompt)
	if err != nil {
		return nil, err
	}
	paths, _ := result.Value().([]dbus.ObjectPath)
	return append(unlocked, paths...), nil
}

// prompt shows a Secret Service prompt and waits for its answer.
func (c *ssConn) prompt(path dbus.ObjectPath) (dbus.Variant, error) {
	if err := c.conn.AddMatchSignal(dbus.WithMatchObjectPath(path), dbus.WithMatchInterface(ssPrompt), dbus.WithMatchMember("Completed")); err != nil {
		return dbus.Variant{}, err
	}
	signals := make(chan *dbus.Signal, 1)
	c.conn.Signal(signals)
	defer c.conn.RemoveSignal(signals)
	if err := c.conn.Object(ssName, path).Call(ssPrompt+".Prompt", 0, "").Err; err != nil {
		return dbus.Variant{}, fmt.Errorf("keyring: Secret Service prompt: %w", err)
	}
	timeout := time.NewTimer(promptWait)
	defer timeout.Stop()
	for {
		select {
		case sig := <-signals:
			if sig.Path != path || len(sig.Body) < 2 {
				continue
			}
			if dismissed, _ := sig.Body[0].(bool); dismissed {
				return dbus.Variant{}, errors.New("keyring: the Secret Service unlock prompt was dismissed")
			}
			result, _ := sig.Body[1].(dbus.Variant)
			return result, nil
		case <-timeout.C:
			return dbus.Variant{}, errors.New("keyring: the Secret Service unlock prompt timed out")
		}
	}
}

func (secretService) Get(service, account string) ([]byte, error) {
	c, err := openSS()
	if err != nil {
		return nil, err
	}
	defer c.close()
	items, err := c.search(service, account)
	if err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	var s secret
	if err := c.conn.Object(ssName, items[0]).Call(ssItem+".GetSecret", 0, c.session).Store(&s); err != nil {
		return nil, fmt.Errorf("keyring: Secret Service GetSecret: %w", err)
	}
	return s.Value, nil
}

func (secretService) Set(service, account string, value []byte) error {
	c, err := openSS()
	if err != nil {
		return err
	}
	defer c.close()
	if _, err := c.unlock([]dbus.ObjectPath{ssDefault}); err != nil {
		return err
	}
	props := map[string]dbus.Variant{
		ssItem + ".Label":      dbus.MakeVariant(service),
		ssItem + ".Attributes": dbus.MakeVariant(attributes(service, account)),
	}
	sec := secret{Session: c.session, Value: value, ContentType: "application/octet-stream"}
	var item, prompt dbus.ObjectPath
	if err := c.conn.Object(ssName, ssDefault).Call(ssCollection+".CreateItem", 0, props, sec, true).Store(&item, &prompt); err != nil {
		return fmt.Errorf("keyring: Secret Service CreateItem: %w", err)
	}
	if prompt != "/" {
		if _, err := c.prompt(prompt); err != nil {
			return err
		}
	}
	return nil
}

func (secretService) Delete(service, account string) error {
	c, err := openSS()
	if err != nil {
		return err
	}
	defer c.close()
	items, err := c.search(service, account)
	if err != nil {
		return err
	}
	for _, item := range items {
		var prompt dbus.ObjectPath
		if err := c.conn.Object(ssName, item).Call(ssItem+".Delete", 0).Store(&prompt); err != nil {
			return fmt.Errorf("keyring: Secret Service Delete: %w", err)
		}
		if prompt != "/" {
			if _, err := c.prompt(prompt); err != nil {
				return err
			}
		}
	}
	return nil
}
