//go:build windows

package settings

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Store struct {
	mu      sync.Mutex
	path    string
	current Config
}
type storedConfig struct {
	Config
	ProtectedPassword string `json:"protected_password,omitempty"`
}

// Open must be passed the application's protected state directory. A missing
// file selects Tor; invalid/unreadable saved settings are never silently reset.
func Open(dir string) (*Store, error) {
	s := &Store{path: filepath.Join(dir, "settings.json"), current: Default()}
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var saved storedConfig
	if err := json.Unmarshal(data, &saved); err != nil {
		return nil, fmt.Errorf("read settings: %w", err)
	}
	if saved.ProtectedPassword != "" {
		encoded, err := base64.StdEncoding.DecodeString(saved.ProtectedPassword)
		if err != nil {
			return nil, fmt.Errorf("invalid saved password")
		}
		plain, err := protect(encoded, false)
		if err != nil {
			return nil, fmt.Errorf("unlock saved proxy password: %w", err)
		}
		saved.Config.Proxy.Password = string(plain)
		clear(plain)
	}
	s.current = saved.Config.Normalized()
	if err := s.current.Validate(); err != nil {
		return nil, fmt.Errorf("invalid saved settings: %w", err)
	}
	return s, nil
}
func (s *Store) Current() Config { s.mu.Lock(); defer s.mu.Unlock(); return s.current }
func (s *Store) Save(c Config) error {
	c = c.Normalized()
	if err := c.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	saved := storedConfig{Config: c}
	if c.Proxy.Password != "" {
		plain := []byte(c.Proxy.Password)
		encoded, err := protect(plain, true)
		clear(plain)
		if err != nil {
			return fmt.Errorf("protect proxy password: %w", err)
		}
		saved.ProtectedPassword = base64.StdEncoding.EncodeToString(encoded)
	}
	data, err := json.MarshalIndent(saved, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), "settings-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Sync()
	}
	err = errors.Join(err, tmp.Close())
	if err != nil {
		return err
	}
	if err := windows.MoveFileEx(windows.StringToUTF16Ptr(tmp.Name()), windows.StringToUTF16Ptr(s.path), windows.MOVEFILE_REPLACE_EXISTING|windows.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	s.current = c
	return nil
}

// DPAPI binds the saved password to the current Windows user and machine.
func protect(data []byte, encrypt bool) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	in := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var out windows.DataBlob
	var err error
	if encrypt {
		err = windows.CryptProtectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&in, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...), nil
}
