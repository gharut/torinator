// Package app serializes UI operations and owns connection state.
package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/gharut/torinator/internal/settings"
	"sync"
)

type State string

const (
	Disconnected  State = "Disconnected"
	Connecting    State = "Connecting"
	Connected     State = "Connected"
	Protected     State = "Protected"
	Blocked       State = "Blocked"
	Degraded      State = "Tunnel unverified"
	Disconnecting State = "Disconnecting"
	Resetting     State = "Resetting"
	Failed        State = "Error"
)

type Status struct {
	State  State
	Detail string
}
type Connection interface {
	Done() <-chan struct{}
	Err() error
	Stop() error
}
type Backend interface {
	Connect(context.Context, func(string)) (Connection, error)
	Reset() error
}

type Controller struct {
	backend    Backend
	op         sync.Mutex
	mu         sync.Mutex
	status     Status
	cancel     context.CancelFunc
	connection Connection
	changed    func(Status)
	closing    bool
	pending    bool
	settings   *settings.Store
}

func New(backend Backend, changed func(Status)) *Controller {
	return &Controller{backend: backend, changed: changed, status: Status{Disconnected, "Normal Windows routing"}}
}
func NewWithSettings(backend Backend, store *settings.Store, changed func(Status)) *Controller {
	c := New(backend, changed)
	c.settings = store
	c.idle(Disconnected, "Normal Windows routing")
	return c
}
func (c *Controller) Settings() settings.Config {
	if c.settings == nil {
		return settings.Default()
	}
	return c.settings.Current()
}
func (c *Controller) SaveSettings(config settings.Config) error {
	if !c.op.TryLock() {
		return fmt.Errorf("disconnect before changing proxy settings")
	}
	defer c.op.Unlock()
	c.mu.Lock()
	busy := c.connection != nil || c.pending || c.closing
	c.mu.Unlock()
	if busy {
		return fmt.Errorf("disconnect before changing proxy settings")
	}
	if c.settings == nil {
		return fmt.Errorf("settings storage is unavailable")
	}
	if err := c.settings.Save(config); err != nil {
		return err
	}
	c.idle(Disconnected, c.settings.Current().Label()+" selected")
	return nil
}

type protectionBackend interface{ ProtectionState() (bool, error) }

func (c *Controller) idle(fallback State, detail string) {
	if backend, ok := c.backend.(protectionBackend); ok {
		active, err := backend.ProtectionState()
		if err != nil {
			c.set(Failed, detail+"; protection cannot be confirmed: "+err.Error()+". Use Reset to recover.")
			return
		}
		if active {
			c.set(Blocked, detail+"; direct access remains blocked. Connect to retry, or Disconnect/Reset to restore normal access.")
			return
		}
	}
	c.set(fallback, detail)
}
func connectionState(conn Connection) State {
	if p, ok := conn.(interface{ ProtectionVerified() bool }); ok && p.ProtectionVerified() {
		return Protected
	}
	return Connected
}

func description(conn Connection) string {
	if describer, ok := conn.(interface{ Description() string }); ok {
		return describer.Description()
	}
	return "TCP and DNS through Tor; other UDP blocked"
}
func (c *Controller) Status() Status { c.mu.Lock(); defer c.mu.Unlock(); return c.status }
func (c *Controller) set(state State, detail string) {
	c.mu.Lock()
	c.status = Status{state, detail}
	s := c.status
	c.mu.Unlock()
	if c.changed != nil {
		c.changed(s)
	}
}

func (c *Controller) progress(detail string) {
	c.mu.Lock()
	if c.status.State != Connecting {
		c.mu.Unlock()
		return
	}
	c.status.Detail = detail
	s := c.status
	c.mu.Unlock()
	if c.changed != nil {
		c.changed(s)
	}
}

func (c *Controller) Connect() {
	// Claim the operation before returning so repeated clicks cannot enqueue work.
	if !c.op.TryLock() {
		return
	}
	c.mu.Lock()
	if c.closing || c.pending || c.connection != nil {
		c.mu.Unlock()
		c.op.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	c.mu.Unlock()
	c.set(Connecting, "Preparing embedded runtimes")
	go func() {
		defer c.op.Unlock()
		conn, err := c.backend.Connect(ctx, c.progress)
		if err != nil {
			cancel()
			if errors.Is(err, context.Canceled) {
				c.mu.Lock()
				pending := c.pending || c.closing
				c.mu.Unlock()
				if !pending {
					c.idle(Disconnected, "Connection canceled")
				}
			} else {
				c.idle(Failed, err.Error())
			}
			return
		}
		c.mu.Lock()
		c.connection = conn
		c.mu.Unlock()
		c.set(connectionState(conn), description(conn))
		go func() {
			var health <-chan error
			if reporter, ok := conn.(interface{ Health() <-chan error }); ok {
				health = reporter.Health()
			}
			for {
				select {
				case healthErr := <-health:
					c.op.Lock()
					c.mu.Lock()
					current := c.connection == conn
					c.mu.Unlock()
					if current {
						if healthErr != nil {
							c.set(Degraded, "Tunnel remains active; connectivity check failed: "+healthErr.Error())
						} else {
							c.set(connectionState(conn), description(conn))
						}
					}
					c.op.Unlock()
					if !current {
						return
					}
				case <-conn.Done():
					c.op.Lock()
					defer c.op.Unlock()
					c.mu.Lock()
					current := c.connection == conn
					c.mu.Unlock()
					if !current {
						return
					}
					cause := conn.Err()
					if err := c.stop(); err != nil {
						c.idle(Failed, fmt.Sprintf("%v; cleanup failed: %v. Use Reset to retry.", cause, err))
					} else {
						c.idle(Failed, fmt.Sprintf("%v; routing process stopped", cause))
					}
					return
				}
			}
		}()
	}()
}

// Disconnect cancels startup immediately, then waits for complete rollback.
func (c *Controller) Disconnect(reset bool) {
	c.mu.Lock()
	if c.pending || c.closing {
		c.mu.Unlock()
		return
	}
	c.pending = true
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	go func() {
		c.op.Lock()
		defer c.op.Unlock()
		defer func() { c.mu.Lock(); c.pending = false; c.mu.Unlock() }()
		if reset {
			c.set(Resetting, "Removing Torinator adapter and extracted runtimes")
		} else {
			c.set(Disconnecting, "Restoring normal Windows routing")
		}
		err := c.stop()
		// Only explicit Disconnect/Reset releases persistent enforcement, and
		// only after all live tunnel resources have been stopped successfully.
		if err == nil {
			err = c.backend.Reset()
		}
		if err != nil {
			c.idle(Failed, err.Error())
			return
		}
		c.idle(Disconnected, "Normal Windows routing")
	}()
}
func (c *Controller) stop() error {
	c.mu.Lock()
	conn := c.connection
	c.connection = nil
	if c.cancel != nil {
		c.cancel()
		c.cancel = nil
	}
	c.mu.Unlock()
	if conn != nil {
		return conn.Stop()
	}
	return nil
}
func (c *Controller) Close() error {
	c.mu.Lock()
	c.closing = true
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	c.op.Lock()
	defer c.op.Unlock()
	c.set(Disconnecting, "Restoring normal Windows routing")
	err := c.stop()
	// Production backends keep protection armed across Exit/logoff. Legacy
	// non-protected test/backends retain their ordinary resource cleanup.
	if _, protected := c.backend.(protectionBackend); !protected {
		err = errors.Join(err, c.backend.Reset())
	}
	if err != nil {
		c.idle(Failed, err.Error())
	} else {
		c.idle(Disconnected, "Stopped")
	}
	return err
}
