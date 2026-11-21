//go:build windows && amd64

package protection

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gharut/torinator/internal/process"
	"github.com/gharut/torinator/internal/settings"
	"golang.org/x/sys/windows"
)

type isolatedPolicy struct {
	Provider, Sublayer windows.GUID
	Base, Tunnel       []rule
	Applications       [][]byte
}

var runNativeTest = flag.Bool("torinator-wfp-test", false, "run only process-scoped native WFP tests (administrator required)")
var nativeTestLog = flag.String("torinator-wfp-log", "", "optional native test output file")

func TestMain(m *testing.M) {
	flag.Parse()
	var file *os.File
	if *nativeTestLog != "" {
		var err error
		file, err = os.Create(*nativeTestLog)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Stdout = file
		os.Stderr = file
	}
	code := m.Run()
	if file != nil {
		file.Close()
	}
	os.Exit(code)
}

// Isolated kernel tests ONLY filter two temporary copies of the test binary.
// They do not install the global Manager policy, affect the developer's apps,
// touch adapters/routes, or contact the internet. Early-boot and IP-forward
// rules are deliberately omitted because they cannot be scoped to these apps.
func scopedRules(input []rule, namespace windows.GUID, apps [][]byte) []rule {
	var out []rule
	for _, r := range input {
		if r.Flags&flagBoot != 0 || r.Layer == forward4 || r.Layer == forward6 || strings.HasPrefix(r.Name, "loopback/") {
			continue
		}
		hasApp := false
		ours := false
		for _, c := range r.Conditions {
			if c.Field == appID {
				hasApp = true
				for _, app := range apps {
					if string(app) == string(c.Value.Data) {
						ours = true
					}
				}
			}
		}
		if hasApp {
			if ours {
				out = append(out, r)
			}
			continue
		}
		for i, app := range apps {
			clone := r
			clone.Name = fmt.Sprintf("%s/test-app-%d", r.Name, i)
			clone.ID = ruleID(namespace, clone.Name)
			clone.Conditions = append(append([]condition(nil), r.Conditions...), condition{Field: appID, Value: value{Kind: kindBlob, Data: app}})
			out = append(out, clone)
		}
	}
	return out
}

func TestNativePersistentEnforcementAndCrash(t *testing.T) {
	if os.Getenv("TORINATOR_PROTECTION_TEST") != "1" && !*runNativeTest {
		t.Skip("opt-in isolated WFP test requires elevation")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("administrator rights are required for the isolated WFP test")
	}
	dir := t.TempDir()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	a, b := filepath.Join(dir, "ordinary-test.exe"), filepath.Join(dir, "transport-test.exe")
	for _, path := range []string{a, b} {
		src, err := os.Open(exe)
		if err != nil {
			t.Fatal(err)
		}
		dst, err := os.Create(path)
		if err != nil {
			src.Close()
			t.Fatal(err)
		}
		_, copyErr := io.Copy(dst, src)
		closeErr := dst.Close()
		src.Close()
		if err := errors.Join(copyErr, closeErr); err != nil {
			t.Fatal(err)
		}
	}
	appA, err := nativeAppID(a)
	if err != nil {
		t.Fatal(err)
	}
	appB, err := nativeAppID(b)
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	sl, err := windows.GenerateGUID()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TORINATOR_TEST_NAMESPACE", namespace.String())
	t.Setenv("TORINATOR_TEST_SUBLAYER", sl.String())
	base, err := baseRules(Plan{Mode: settings.Tor, TorPath: b, RouterPath: b}, namespace)
	if err != nil {
		t.Fatal(err)
	}
	apps := [][]byte{appA, appB}
	policy := isolatedPolicy{Provider: namespace, Sublayer: sl, Base: scopedRules(base, namespace, apps), Tunnel: scopedRules(tunnelRules(namespace, 0x123456789), namespace, apps), Applications: apps}
	if err := validateIsolated(policy); err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "isolated-policy.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := openNative(false)
	if err != nil {
		t.Fatal(err)
	}
	s.provider = namespace
	s.sublayer = sl
	t.Cleanup(func() {
		if err := s.remove(); err != nil {
			t.Errorf("remove isolated test policy: %v", err)
		}
		s.close()
	})
	// Register the two test applications at ALE before creating the stream.
	// This makes the fixture exercise an explicit permit-to-deny ALE policy
	// transition instead of assuming that a loopback stream opened before the
	// first policy was registered is tracked identically on every Windows build.
	// Production explicitly permits loopback.
	baseline := loopbackBaseline(policy)
	if err := validateIsolated(isolatedPolicy{Provider: namespace, Sublayer: sl, Base: baseline, Applications: apps}); err != nil {
		t.Fatal(err)
	}
	if err := s.replace(baseline); err != nil {
		t.Fatal(err)
	}
	if err := s.verify(baseline); err != nil {
		t.Fatal(err)
	}
	tcp4, udp4 := echoServers(t, "tcp4", "udp4", "127.0.0.1")
	tcp6, udp6 := echoServers(t, "tcp6", "udp6", "::1")
	for _, endpoint := range []struct{ network, address string }{{"tcp4", tcp4}, {"udp4", udp4}, {"tcp6", tcp6}, {"udp6", udp6}} {
		probeHelper(t, a, endpoint.network, endpoint.address, "ALLOW")
	}
	// An established TCP stream must also be reauthorized after policy change.
	established := startHelper(t, a, "existing", "tcp4", tcp4)
	established.wait(t, "ESTABLISHED")
	installer := startHelper(t, a, "install", path)
	installer.wait(t, "ARMED")
	if err := s.verify(append(append([]rule(nil), policy.Base...), policy.Tunnel...)); err != nil {
		t.Fatal(err)
	}
	established.wait(t, "EXISTING_BLOCKED")
	for _, endpoint := range []struct{ network, address string }{{"tcp4", tcp4}, {"udp4", udp4}, {"tcp6", tcp6}, {"udp6", udp6}} {
		probeHelper(t, a, endpoint.network, endpoint.address, "DENY")
	}
	// Only the selected Tor transport executable may connect directly over TCP.
	probeHelper(t, b, "tcp4", tcp4, "ALLOW")
	probeHelper(t, b, "tcp6", tcp6, "ALLOW")
	probeHelper(t, b, "udp4", udp4, "DENY")
	if err := installer.child.Stop(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		err = s.verify(policy.Base)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dynamic tunnel permissions did not disappear after installer crash: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	probeHelper(t, a, "tcp4", tcp4, "DENY")
	probeHelper(t, a, "udp6", udp6, "DENY")
	// A new WFP session sees the persistent deny rules after the owner died.
	reopened, err := openNative(false)
	if err != nil {
		t.Fatal(err)
	}
	reopened.provider = namespace
	reopened.sublayer = sl
	if err := reopened.verify(policy.Base); err != nil {
		reopened.close()
		t.Fatal(err)
	}
	reopened.close()
	if err := s.remove(); err != nil {
		t.Fatal(err)
	}
	for _, endpoint := range []struct{ network, address string }{{"tcp4", tcp4}, {"udp4", udp4}, {"tcp6", tcp6}, {"udp6", udp6}} {
		probeHelper(t, a, endpoint.network, endpoint.address, "ALLOW")
	}
}

func loopbackBaseline(p isolatedPolicy) []rule {
	var rules []rule
	for _, r := range p.Base {
		if r.Action != actionBlock {
			continue
		}
		r.Name = "baseline/" + r.Name
		r.ID = ruleID(p.Provider, r.Name)
		r.Action = actionPermit
		rules = append(rules, r)
	}
	return rules
}

// Validate every production filter (including forwarding and early boot) in an
// UNCOMMITTED transaction. There is deliberately no commit call in this test:
// abort/session death rolls it all back without changing host enforcement.
func TestNativePolicyDefinitionsRollback(t *testing.T) {
	if os.Getenv("TORINATOR_PROTECTION_TEST") != "1" && !*runNativeTest {
		t.Skip("opt-in native SDK validation requires elevation")
	}
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Fatal("administrator rights required")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []settings.Mode{settings.Tor, settings.SOCKS5} {
		t.Run(string(mode), func(t *testing.T) {
			s, err := openNative(false)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			s.provider, err = windows.GenerateGUID()
			if err != nil {
				t.Fatal(err)
			}
			s.sublayer, err = windows.GenerateGUID()
			if err != nil {
				t.Fatal(err)
			}
			if err := call("FwpmTransactionBegin0", uintptr(s.handle), 0); err != nil {
				t.Fatal(err)
			}
			defer call("FwpmTransactionAbort0", uintptr(s.handle))
			if err := s.ensureObjects(); err != nil {
				t.Fatal(err)
			}
			rules, err := baseRules(Plan{Mode: mode, Endpoint: netip.MustParseAddr("203.0.113.8"), Port: 1080, TorPath: exe, RouterPath: exe}, s.provider)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range rules {
				if err := s.addRule(r); err != nil {
					t.Fatalf("SDK rejected production rule %s: %v", r.Name, err)
				}
			}
			if err := call("FwpmTransactionAbort0", uintptr(s.handle)); err != nil {
				t.Fatal(err)
			}
			remaining, err := s.rules()
			if err != nil && !missing(err) {
				t.Fatal(err)
			}
			if len(remaining) != 0 {
				t.Fatal("aborted definition transaction left rules behind")
			}
		})
	}
}

func validateIsolated(p isolatedPolicy) error {
	if p.Provider == providerID || p.Sublayer == sublayerID || len(p.Applications) != 2 {
		return fmt.Errorf("refusing non-isolated WFP test namespace")
	}
	for _, r := range append(append([]rule(nil), p.Base...), p.Tunnel...) {
		if r.Flags&flagBoot != 0 || r.Layer == forward4 || r.Layer == forward6 {
			return fmt.Errorf("global/boot rule is forbidden in the host test")
		}
		scoped := false
		for _, c := range r.Conditions {
			if c.Field == appID {
				for _, app := range p.Applications {
					if string(c.Value.Data) == string(app) {
						scoped = true
					}
				}
			}
		}
		if !scoped {
			return fmt.Errorf("unscoped rule is forbidden in the host test")
		}
	}
	return nil
}
func echoServers(t *testing.T, tcpNetwork, udpNetwork, ip string) (string, string) {
	t.Helper()
	listener, err := net.Listen(tcpNetwork, net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); io.Copy(conn, conn) }()
		}
	}()
	udp, err := net.ListenPacket(udpNetwork, net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { udp.Close() })
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := udp.ReadFrom(buf)
			if err != nil {
				return
			}
			udp.WriteTo(buf[:n], addr)
		}
	}()
	return listener.Addr().String(), udp.LocalAddr().String()
}

type helperProcess struct {
	child  *process.Child
	lines  chan string
	mu     sync.Mutex
	output []string
}

func startHelper(t *testing.T, exe string, args ...string) *helperProcess {
	t.Helper()
	h := &helperProcess{lines: make(chan string, 128)}
	command := append([]string{"-test.run=^TestProtectionHelper$", "--", "torinator-protection-helper"}, args...)
	child, err := process.Start(exe, command, func(line string) {
		h.mu.Lock()
		h.output = append(h.output, line)
		h.mu.Unlock()
		select {
		case h.lines <- line:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	h.child = child
	t.Cleanup(func() { child.Stop() })
	return h
}
func (h *helperProcess) wait(t *testing.T, want string) {
	t.Helper()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	for {
		select {
		case line := <-h.lines:
			if line == want {
				return
			}
		case <-h.child.Done():
			// The output scanner may close the process notification before this
			// select consumes the last already-buffered line.
			h.mu.Lock()
			out := strings.Join(h.output, "\n")
			h.mu.Unlock()
			for _, line := range strings.Split(out, "\n") {
				if line == want {
					return
				}
			}
			t.Fatalf("helper exited before %s: %v\n%s", want, h.child.Wait(), out)
		case <-timer.C:
			h.mu.Lock()
			out := strings.Join(h.output, "\n")
			h.mu.Unlock()
			t.Fatalf("helper timed out waiting for %s\n%s", want, out)
		}
	}
}
func probeHelper(t *testing.T, exe, network, address, result string) {
	t.Helper()
	h := startHelper(t, exe, "probe", network, address)
	h.wait(t, result)
	if err := h.child.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestProtectionHelper(t *testing.T) {
	index := -1
	for i, arg := range os.Args {
		if arg == "torinator-protection-helper" {
			index = i
			break
		}
	}
	if index < 0 {
		return
	}
	args := os.Args[index+1:]
	if len(args) == 0 {
		t.Fatal("missing helper operation")
	}
	switch args[0] {
	case "install":
		if len(args) != 2 {
			t.Fatal("missing isolated policy")
		}
		data, err := os.ReadFile(args[1])
		if err != nil {
			t.Fatal(err)
		}
		var p isolatedPolicy
		if err := json.Unmarshal(data, &p); err != nil {
			t.Fatal(err)
		}
		if err := validateIsolated(p); err != nil {
			t.Fatal(err)
		}
		s, err := openNative(false)
		if err != nil {
			t.Fatal(err)
		}
		s.provider = p.Provider
		s.sublayer = p.Sublayer
		if err := s.replace(p.Base); err != nil {
			t.Fatal(err)
		}
		dynamic, err := openNative(true)
		if err != nil {
			t.Fatal(err)
		}
		dynamic.provider = p.Provider
		dynamic.sublayer = p.Sublayer
		if err := dynamic.addDynamic(p.Tunnel); err != nil {
			t.Fatal(err)
		}
		fmt.Println("ARMED")
		for {
			time.Sleep(time.Hour)
		}
	case "probe", "existing":
		if len(args) != 3 {
			t.Fatal("missing probe destination")
		}
		network, address := args[1], args[2]
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			if errors.Is(err, windows.WSAEACCES) {
				fmt.Println("DENY")
				return
			}
			t.Fatal(err)
		}
		defer conn.Close()
		if args[0] == "probe" {
			conn.SetDeadline(time.Now().Add(3 * time.Second))
			_, err = conn.Write([]byte("test"))
			if errors.Is(err, windows.WSAEACCES) {
				fmt.Println("DENY")
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			buf := make([]byte, 4)
			if _, err := io.ReadFull(conn, buf); err != nil {
				// UDP filters may drop the send without returning WSAEACCES.
				// Attribute the fresh probe to a WFP block from an isolated test
				// namespace; never infer enforcement from a timeout by itself.
				if strings.HasPrefix(network, "udp") {
					exe, _ := os.Executable()
					app, appErr := nativeAppID(exe)
					if appErr != nil {
						t.Fatal(appErr)
					}
					local := conn.LocalAddr().(*net.UDPAddr).Port
					probe, probeErr := openNative(false)
					if probeErr != nil {
						t.Fatal(probeErr)
					}
					defer probe.close()
					// The parent supplies its isolated namespace on probe launches.
					if encoded := os.Getenv("TORINATOR_TEST_NAMESPACE"); encoded != "" {
						probe.provider = guid(encoded)
						probe.sublayer = guid(os.Getenv("TORINATOR_TEST_SUBLAYER"))
					}
					if dropErr := probe.waitForDrop(context.Background(), app, uint16(local), time.Now().Add(-4*time.Second)); dropErr == nil {
						fmt.Println("DENY")
						return
					} else {
						t.Fatalf("UDP timeout was not a confirmed policy drop: %v", dropErr)
					}
				}
				t.Fatal(err)
			}
			if string(buf) != "test" {
				t.Fatal("unexpected echo")
			}
			fmt.Println("ALLOW")
			return
		}
		buf := make([]byte, 4)
		for i := 0; ; i++ {
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			_, err := conn.Write([]byte("test"))
			if err == nil {
				_, err = io.ReadFull(conn, buf)
			}
			if err != nil {
				if i == 0 {
					t.Fatal(err)
				}
				fmt.Println("EXISTING_BLOCKED")
				return
			}
			if i == 0 {
				fmt.Println("ESTABLISHED")
			}
			time.Sleep(20 * time.Millisecond)
		}
	default:
		t.Fatal("unknown helper operation")
	}
}
