// Package app serializes UI operations and owns connection state.
package app

import (
	"context"
	"errors"
	"fmt"
	"sync"
)

type State string

const (
	Disconnected  State = "Disconnected"
	Connecting    State = "Connecting"
	Connected     State = "Connected"
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
}

func New(backend Backend, changed func(Status)) *Controller {
	return &Controller{backend: backend, changed: changed, status: Status{Disconnected, "Normal Windows routing"}}
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
					c.set(Disconnected, "Normal Windows routing")
				}
			} else {
				c.set(Failed, err.Error())
			}
			return
		}
		c.mu.Lock()
		c.connection = conn
		c.mu.Unlock()
		c.set(Connected, "TCP and DNS through Tor; other UDP blocked")
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
							c.set(Degraded, "Tunnel remains active; Tor check failed: "+healthErr.Error())
						} else {
							c.set(Connected, "TCP and DNS through Tor; last Tor check passed")
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
						c.set(Failed, fmt.Sprintf("%v; cleanup failed: %v. Use Reset to retry.", cause, err))
					} else {
						c.set(Failed, fmt.Sprintf("%v; normal Windows routing restored", cause))
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
		c.mu.Lock()
		hadConnection := c.connection != nil
		c.mu.Unlock()
		err := c.stop()
		// Startup may have failed while rolling back. Retry backend recovery
		// before showing Disconnected even when no Connection was returned.
		if reset || !hadConnection {
			err = errors.Join(err, c.backend.Reset())
		}
		if err != nil {
			c.set(Failed, err.Error())
			return
		}
		c.set(Disconnected, "Normal Windows routing")
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
	err := errors.Join(c.stop(), c.backend.Reset())
	if err != nil {
		c.set(Failed, err.Error())
	} else {
		c.set(Disconnected, "Normal Windows routing")
	}
	return err
}
