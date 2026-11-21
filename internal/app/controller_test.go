package app

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	connect func(context.Context, func(string)) (Connection, error)
	resets  atomic.Int32
	reset   func() error
}

func (b *fakeBackend) Connect(ctx context.Context, p func(string)) (Connection, error) {
	return b.connect(ctx, p)
}
func (b *fakeBackend) Reset() error {
	b.resets.Add(1)
	if b.reset != nil {
		return b.reset()
	}
	return nil
}

type fakeConnection struct {
	done    chan struct{}
	once    sync.Once
	stops   atomic.Int32
	err     error
	stopErr error
	health  chan error
}

func (s *fakeConnection) Done() <-chan struct{} { return s.done }
func (s *fakeConnection) Health() <-chan error  { return s.health }
func (s *fakeConnection) Err() error            { return s.err }
func (s *fakeConnection) Stop() error {
	s.stops.Add(1)
	s.once.Do(func() { close(s.done) })
	return s.stopErr
}

func waitStatus(t *testing.T, c *Controller, state State) {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-deadline.C:
			t.Fatalf("wanted %s, got %+v", state, c.Status())
		case <-tick.C:
			if c.Status().State == state {
				return
			}
		}
	}
}
func TestDisconnectCancelsBootstrapAndSerializesReset(t *testing.T) {
	started := make(chan struct{})
	var calls atomic.Int32
	b := &fakeBackend{connect: func(ctx context.Context, _ func(string)) (Connection, error) {
		calls.Add(1)
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	c := New(b, nil)
	c.Connect()
	<-started
	c.Connect() // A second click must not start another session.
	c.Disconnect(true)
	waitStatus(t, c, Disconnected)
	// Wait for the operation to finish, not just its cancellation status update.
	c.op.Lock()
	c.op.Unlock()
	if calls.Load() != 1 || b.resets.Load() != 1 {
		t.Fatalf("connects=%d resets=%d", calls.Load(), b.resets.Load())
	}
}
func TestRuntimeFailureStopsTheOtherProcessAndReportsError(t *testing.T) {
	s := &fakeConnection{done: make(chan struct{}), err: errors.New("Tor crashed")}
	b := &fakeBackend{connect: func(context.Context, func(string)) (Connection, error) { return s, nil }}
	c := New(b, nil)
	c.Connect()
	waitStatus(t, c, Connected)
	s.once.Do(func() { close(s.done) })
	waitStatus(t, c, Failed)
	if s.stops.Load() != 1 || !strings.Contains(c.Status().Detail, "Tor crashed") {
		t.Fatalf("%+v stops=%d", c.Status(), s.stops.Load())
	}
}
func TestFailedRollbackNeverReportsDisconnected(t *testing.T) {
	s := &fakeConnection{done: make(chan struct{}), stopErr: errors.New("adapter removal denied")}
	b := &fakeBackend{connect: func(context.Context, func(string)) (Connection, error) { return s, nil }}
	c := New(b, nil)
	c.Connect()
	waitStatus(t, c, Connected)
	c.Disconnect(false)
	waitStatus(t, c, Failed)
	if !strings.Contains(c.Status().Detail, "adapter removal denied") {
		t.Fatal(c.Status())
	}
}
func TestExitCancelsStartupAndRejectsNewConnections(t *testing.T) {
	started := make(chan struct{})
	b := &fakeBackend{connect: func(ctx context.Context, _ func(string)) (Connection, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}}
	c := New(b, nil)
	c.Connect()
	<-started
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	c.Connect()
	if c.Status().State != Disconnected || b.resets.Load() != 1 {
		t.Fatal(c.Status())
	}
}

func TestFailedHealthCheckKeepsTunnelActive(t *testing.T) {
	s := &fakeConnection{done: make(chan struct{}), health: make(chan error, 1)}
	b := &fakeBackend{connect: func(context.Context, func(string)) (Connection, error) { return s, nil }}
	c := New(b, nil)
	c.Connect()
	waitStatus(t, c, Connected)
	s.health <- errors.New("network unavailable")
	waitStatus(t, c, Degraded)
	if s.stops.Load() != 0 {
		t.Fatal("health failure must not restore direct internet access")
	}
	s.health <- nil
	waitStatus(t, c, Connected)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCancelledStartupCannotHideRecoveryFailure(t *testing.T) {
	started := make(chan struct{})
	recovered := make(chan struct{})
	b := &fakeBackend{
		connect: func(ctx context.Context, _ func(string)) (Connection, error) {
			close(started)
			<-ctx.Done()
			return nil, errors.New("startup rollback failed")
		},
		reset: func() error { close(recovered); return errors.New("adapter recovery failed") },
	}
	c := New(b, nil)
	c.Connect()
	<-started
	c.Disconnect(false)
	select {
	case <-recovered:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery was not retried")
	}
	c.op.Lock()
	c.op.Unlock()
	if s := c.Status(); s.State != Failed || !strings.Contains(s.Detail, "adapter recovery failed") {
		t.Fatal(s)
	}
}
