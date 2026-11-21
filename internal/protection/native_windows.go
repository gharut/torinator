//go:build windows && amd64

package protection

// Minimal x64 bindings for the public FWPM_*0 SDK structures. Keeping the
// session handle here lets all policy changes use native WFP transactions.
import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var wfp = windows.NewLazySystemDLL("fwpuclnt.dll")

type displayData struct{ Name, Description *uint16 }
type blob struct {
	Size uint32
	Data *byte
}
type nativeValue struct {
	Kind uint32
	Data uintptr
}

// The SDK value is a union: small integers are inline, while other kinds hold
// native pointers. Read the pointer member directly from its storage instead
// of converting a saved integer address back into a Go pointer.
func (v *nativeValue) pointer() unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&v.Data))
}

type nativeCondition struct {
	Field windows.GUID
	Op    uint32
	Value nativeValue
}
type nativeAction struct {
	Type    uint32
	Callout windows.GUID
}
type nativeFilter struct {
	ID              windows.GUID
	Display         displayData
	Flags           uint32
	Provider        *windows.GUID
	ProviderData    blob
	Layer, Sublayer windows.GUID
	Weight          nativeValue
	Count           uint32
	Conditions      *nativeCondition
	Action          nativeAction
	Context         [2]uint64 // union { UINT64 rawContext; GUID providerContextKey; }
	Reserved        *windows.GUID
	KernelID        uint64
	EffectiveWeight nativeValue
}
type nativeProvider struct {
	ID      windows.GUID
	Display displayData
	Flags   uint32
	Data    blob
	Service *uint16
}
type nativeSublayer struct {
	ID       windows.GUID
	Display  displayData
	Flags    uint32
	Provider *windows.GUID
	Data     blob
	Weight   uint16
}
type nativeSessionOptions struct {
	ID                  windows.GUID
	Display             displayData
	Flags, Timeout, PID uint32
	SID                 *windows.SID
	Username            *uint16
	KernelMode          uint8
}
type enumTemplate struct {
	Provider        *windows.GUID
	Layer           windows.GUID
	EnumType, Flags uint32
	ProviderContext uintptr
	Count           uint32
	Conditions      *nativeCondition
	ActionMask      uint32
	Callout         *windows.GUID
}
type nativeSession struct {
	handle             windows.Handle
	provider, sublayer windows.GUID
}

//go:uintptrescapes
func call(name string, args ...uintptr) error {
	r, _, _ := wfp.NewProc(name).Call(args...)
	if r != 0 {
		return fmt.Errorf("%s: %w (0x%08x)", name, windows.Errno(r), r)
	}
	return nil
}
func free(ptr unsafe.Pointer) { wfp.NewProc("FwpmFreeMemory0").Call(uintptr(ptr)) }
func openNative(dynamic bool) (*nativeSession, error) {
	s := &nativeSession{provider: providerID, sublayer: sublayerID}
	opts := nativeSessionOptions{Display: displayData{Name: windows.StringToUTF16Ptr("Torinator protection")}, Timeout: 10000}
	if dynamic {
		opts.Flags = 1
	}
	if err := call("FwpmEngineOpen0", 0, 0xffffffff, 0, uintptr(unsafe.Pointer(&opts)), uintptr(unsafe.Pointer(&s.handle))); err != nil {
		return nil, err
	}
	return s, nil
}
func (s *nativeSession) close() error {
	if s.handle == 0 {
		return nil
	}
	err := call("FwpmEngineClose0", uintptr(s.handle))
	if err == nil {
		s.handle = 0
	}
	return err
}
func (s *nativeSession) transaction(fn func() error) error {
	if err := call("FwpmTransactionBegin0", uintptr(s.handle), 0); err != nil {
		return err
	}
	defer call("FwpmTransactionAbort0", uintptr(s.handle))
	if err := fn(); err != nil {
		return err
	}
	return call("FwpmTransactionCommit0", uintptr(s.handle))
}
func missing(err error) bool {
	return errors.Is(err, windows.Errno(windows.FWP_E_FILTER_NOT_FOUND)) || errors.Is(err, windows.Errno(windows.FWP_E_PROVIDER_NOT_FOUND)) || errors.Is(err, windows.Errno(windows.FWP_E_SUBLAYER_NOT_FOUND))
}

func (s *nativeSession) ensureObjects() error {
	p := nativeProvider{ID: s.provider, Display: displayData{Name: windows.StringToUTF16Ptr("Torinator kill switch")}, Flags: flagPersistent, Service: windows.StringToUTF16Ptr("BFE")}
	if err := call("FwpmProviderAdd0", uintptr(s.handle), uintptr(unsafe.Pointer(&p)), 0); err != nil && !errors.Is(err, windows.Errno(windows.FWP_E_ALREADY_EXISTS)) {
		return err
	}
	sl := nativeSublayer{ID: s.sublayer, Display: displayData{Name: windows.StringToUTF16Ptr("Torinator fail-closed policy")}, Flags: flagPersistent, Provider: &s.provider, Weight: 65535}
	if err := call("FwpmSubLayerAdd0", uintptr(s.handle), uintptr(unsafe.Pointer(&sl)), 0); err != nil && !errors.Is(err, windows.Errno(windows.FWP_E_ALREADY_EXISTS)) {
		return err
	}
	return nil
}
func (s *nativeSession) checkObjects() error {
	var p *nativeProvider
	if err := call("FwpmProviderGetByKey0", uintptr(s.handle), uintptr(unsafe.Pointer(&s.provider)), uintptr(unsafe.Pointer(&p))); err != nil {
		return err
	}
	defer free(unsafe.Pointer(&p))
	if p.Flags&flagPersistent == 0 || p.Flags&0x10 != 0 || p.Service == nil || windows.UTF16PtrToString(p.Service) != "BFE" {
		return fmt.Errorf("protection provider is not persistent and enabled")
	}
	var sl *nativeSublayer
	if err := call("FwpmSubLayerGetByKey0", uintptr(s.handle), uintptr(unsafe.Pointer(&s.sublayer)), uintptr(unsafe.Pointer(&sl))); err != nil {
		return err
	}
	defer free(unsafe.Pointer(&sl))
	if sl.Provider == nil || *sl.Provider != s.provider || sl.Flags&flagPersistent == 0 || sl.Weight < 32768 {
		return fmt.Errorf("protection sublayer mismatch: provider=%v expected=%s flags=0x%x weight=%d", sl.Provider, s.provider.String(), sl.Flags, sl.Weight)
	}
	return nil
}
func (s *nativeSession) replace(rules []rule) error {
	return s.transaction(func() error {
		if err := s.checkConflicts(); err != nil {
			return err
		}
		if err := s.ensureObjects(); err != nil {
			return err
		}
		old, err := s.rules()
		if err != nil {
			return err
		}
		for _, r := range old {
			if r.Flags&(flagPersistent|flagBoot) == 0 {
				return fmt.Errorf("an existing tunnel permission is still active; Disconnect or Reset first")
			}
			if r.Flags&flagPersistent != 0 || r.Flags&flagBoot != 0 {
				if err := s.deleteRule(r.ID); err != nil {
					return err
				}
			}
		}
		for _, r := range rules {
			if err := s.addRule(r); err != nil {
				return fmt.Errorf("install %s: %w", r.Name, err)
			}
		}
		if err := s.checkObjects(); err != nil {
			return err
		}
		return s.checkConflicts()
	})
}
func (s *nativeSession) addDynamic(rules []rule) error {
	return s.transaction(func() error {
		for _, r := range rules {
			if err := s.addRule(r); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *nativeSession) remove() error {
	return s.transaction(func() error {
		rules, err := s.rules()
		if err != nil && !missing(err) {
			return err
		}
		for _, r := range rules {
			if err := s.deleteRule(r.ID); err != nil {
				return err
			}
		}
		if err := call("FwpmSubLayerDeleteByKey0", uintptr(s.handle), uintptr(unsafe.Pointer(&s.sublayer))); err != nil && !missing(err) {
			return err
		}
		if err := call("FwpmProviderDeleteByKey0", uintptr(s.handle), uintptr(unsafe.Pointer(&s.provider))); err != nil && !missing(err) {
			return err
		}
		return nil
	})
}
func (s *nativeSession) deleteRule(id windows.GUID) error {
	err := call("FwpmFilterDeleteByKey0", uintptr(s.handle), uintptr(unsafe.Pointer(&id)))
	if missing(err) {
		return nil
	}
	return err
}

func nativeAppID(path string) ([]byte, error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// The filename API does not resolve filesystem aliases. In particular, CI's
	// TEMP may contain an 8.3 name such as RUNNER~1 while ALE reports the long
	// executable path. Resolve through a handle before generating the app ID so
	// deny rules and transport exceptions match the identity Windows classifies.
	handle, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return nil, fmt.Errorf("open application identity: %w", err)
	}
	defer windows.CloseHandle(handle)
	buf := make([]uint16, 512)
	for {
		n, err := windows.GetFinalPathNameByHandle(handle, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return nil, fmt.Errorf("resolve application identity: %w", err)
		}
		if n >= uint32(len(buf)) {
			buf = make([]uint16, n+1)
			continue
		}
		resolved := windows.UTF16ToString(buf[:n])
		if strings.HasPrefix(resolved, `\\?\UNC\`) {
			resolved = `\\` + strings.TrimPrefix(resolved, `\\?\UNC\`)
		} else {
			resolved = strings.TrimPrefix(resolved, `\\?\`)
		}
		name, err = windows.UTF16PtrFromString(resolved)
		if err != nil {
			return nil, err
		}
		break
	}
	var b *blob
	if err := call("FwpmGetAppIdFromFileName0", uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&b))); err != nil {
		return nil, err
	}
	defer free(unsafe.Pointer(&b))
	return append([]byte(nil), unsafe.Slice(b.Data, int(b.Size))...), nil
}

// Values point into keep, which remains alive until FwpmFilterAdd0 returns.
func marshalValue(v value, keep *[]any) nativeValue {
	r := nativeValue{Kind: v.Kind}
	switch v.Kind {
	case kind8, kind16, kind32:
		r.Data = uintptr(v.Number)
	case kind64:
		n := new(uint64)
		*n = v.Number
		*keep = append(*keep, n)
		r.Data = uintptr(unsafe.Pointer(n))
	case kindBlob:
		b := &blob{Size: uint32(len(v.Data))}
		if len(v.Data) > 0 {
			b.Data = &v.Data[0]
		}
		*keep = append(*keep, b, v.Data)
		r.Data = uintptr(unsafe.Pointer(b))
	default:
		if len(v.Data) > 0 {
			r.Data = uintptr(unsafe.Pointer(&v.Data[0]))
			*keep = append(*keep, v.Data)
		}
	}
	return r
}
func (s *nativeSession) addRule(r rule) error {
	var keep []any
	f := nativeFilter{ID: r.ID, Display: displayData{Name: windows.StringToUTF16Ptr("Torinator " + r.Name)}, Provider: &s.provider, Sublayer: s.sublayer, Layer: r.Layer, Flags: r.Flags, Action: nativeAction{Type: r.Action}}
	f.Weight = marshalValue(value{Kind: kind64, Number: r.Weight}, &keep)
	conds := make([]nativeCondition, len(r.Conditions))
	for i, c := range r.Conditions {
		conds[i] = nativeCondition{Field: c.Field, Op: c.Op, Value: marshalValue(c.Value, &keep)}
	}
	f.Count = uint32(len(conds))
	if len(conds) > 0 {
		f.Conditions = &conds[0]
	}
	var id uint64
	err := call("FwpmFilterAdd0", uintptr(s.handle), uintptr(unsafe.Pointer(&f)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(keep)
	runtime.KeepAlive(conds)
	runtime.KeepAlive(f)
	return err
}
func readValue(v nativeValue) (value, error) {
	r := value{Kind: v.Kind}
	switch v.Kind {
	case kind8:
		r.Number = uint64(uint8(v.Data))
	case kind16:
		r.Number = uint64(uint16(v.Data))
	case kind32:
		r.Number = uint64(uint32(v.Data))
	case kind64:
		if v.Data == 0 {
			return r, fmt.Errorf("missing 64-bit condition")
		}
		r.Number = *(*uint64)(v.pointer())
	case kindBlob:
		b := (*blob)(v.pointer())
		if b == nil || b.Size > 1<<20 {
			return r, fmt.Errorf("invalid app ID")
		}
		if b.Size > 0 {
			r.Data = append([]byte(nil), unsafe.Slice(b.Data, int(b.Size))...)
		}
	case kindV4, kindV6, kindArray16:
		n := 8
		if v.Kind == kindV6 {
			n = 17
		}
		if v.Kind == kindArray16 {
			n = 16
		}
		if v.Data == 0 {
			return r, fmt.Errorf("missing address condition")
		}
		r.Data = append([]byte(nil), unsafe.Slice((*byte)(v.pointer()), n)...)
	default:
		return r, fmt.Errorf("unexpected WFP data type %d", v.Kind)
	}
	return r, nil
}
func readRule(f *nativeFilter) (rule, error) {
	r := rule{ID: f.ID, Layer: f.Layer, Flags: f.Flags, Action: f.Action.Type}
	w, err := readValue(f.Weight)
	if err != nil {
		return r, err
	}
	r.Weight = w.Number
	if f.Count > 512 {
		return r, fmt.Errorf("too many filter conditions")
	}
	if f.Count > 0 {
		for _, c := range unsafe.Slice(f.Conditions, int(f.Count)) {
			v, err := readValue(c.Value)
			if err != nil {
				return r, err
			}
			r.Conditions = append(r.Conditions, condition{Field: c.Field, Op: c.Op, Value: v})
		}
	}
	return r, nil
}

func (s *nativeSession) enumerate(owned bool, visit func(*nativeFilter) error) error {
	for _, layer := range []windows.GUID{connect4, connect6, receive4, receive6, forward4, forward6} {
		if err := s.enumerateLayer(owned, layer, visit); err != nil {
			return fmt.Errorf("enumerate WFP layer %s: %w", layer.String(), err)
		}
	}
	return nil
}
func (s *nativeSession) enumerateLayer(owned bool, layer windows.GUID, visit func(*nativeFilter) error) error {
	// INCLUDE_BOOTTIME (0x8) and INCLUDE_DISABLED (0x10); boot-time filters
	// otherwise do not appear in default enumeration, including during Reset.
	tpl := enumTemplate{Layer: layer, Flags: 0x8 | 0x10, ActionMask: 0xffffffff}
	if owned {
		tpl.Provider = &s.provider
	}
	var enum windows.Handle
	if err := call("FwpmFilterCreateEnumHandle0", uintptr(s.handle), uintptr(unsafe.Pointer(&tpl)), uintptr(unsafe.Pointer(&enum))); err != nil {
		return err
	}
	defer call("FwpmFilterDestroyEnumHandle0", uintptr(s.handle), uintptr(enum))
	for {
		var entries **nativeFilter
		var count uint32
		if err := call("FwpmFilterEnum0", uintptr(s.handle), uintptr(enum), 256, uintptr(unsafe.Pointer(&entries)), uintptr(unsafe.Pointer(&count))); err != nil {
			return err
		}
		if count == 0 {
			return nil
		}
		err := func() error {
			defer free(unsafe.Pointer(&entries))
			for _, f := range unsafe.Slice(entries, int(count)) {
				if owned && (f.Provider == nil || *f.Provider != s.provider || f.Sublayer != s.sublayer) {
					return fmt.Errorf("unexpected object in Torinator's WFP namespace")
				}
				if err := visit(f); err != nil {
					return err
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
}
func (s *nativeSession) rules() ([]rule, error) {
	var ret []rule
	err := s.enumerate(true, func(f *nativeFilter) error {
		r, err := readRule(f)
		if err == nil {
			ret = append(ret, r)
		}
		return err
	})
	return ret, err
}
func (s *nativeSession) verify(expected []rule) error {
	if err := s.checkObjects(); err != nil {
		return err
	}
	actual, err := s.rules()
	if err != nil {
		return err
	}
	if len(actual) != len(expected) {
		return fmt.Errorf("protection rule count mismatch: expected %d, found %d", len(expected), len(actual))
	}
	byID := make(map[windows.GUID]rule, len(actual))
	for _, r := range actual {
		byID[r.ID] = r
	}
	for _, want := range expected {
		got, ok := byID[want.ID]
		if !ok || got.Flags&flagDisabled != 0 || !sameRule(got, want) {
			return fmt.Errorf("protection rule %s is missing, disabled, or changed", want.Name)
		}
	}
	return s.checkConflicts()
}
func (s *nativeSession) checkConflicts() error {
	// Windows/security providers may assign a slightly lower effective
	// sublayer weight. Compare against the value actually registered, rather
	// than assuming that our requested 65535 was retained.
	ours := uint16(65535)
	var own *nativeSublayer
	if err := call("FwpmSubLayerGetByKey0", uintptr(s.handle), uintptr(unsafe.Pointer(&s.sublayer)), uintptr(unsafe.Pointer(&own))); err == nil {
		ours = own.Weight
		free(unsafe.Pointer(&own))
	} else if !missing(err) {
		return err
	}
	cache := map[windows.GUID]uint16{}
	return s.enumerate(false, func(f *nativeFilter) error {
		if f.Sublayer == s.sublayer || f.Flags&flagDisabled != 0 || f.Flags&flagBoot != 0 || f.Flags&flagHard == 0 || f.Action.Type != actionPermit {
			return nil
		}
		if f.Layer != connect4 && f.Layer != connect6 && f.Layer != receive4 && f.Layer != receive6 && f.Layer != forward4 && f.Layer != forward6 {
			return nil
		}
		weight, ok := cache[f.Sublayer]
		if !ok {
			var sl *nativeSublayer
			if err := call("FwpmSubLayerGetByKey0", uintptr(s.handle), uintptr(unsafe.Pointer(&f.Sublayer)), uintptr(unsafe.Pointer(&sl))); err != nil {
				return err
			}
			weight = sl.Weight
			free(unsafe.Pointer(&sl))
			cache[f.Sublayer] = weight
		}
		if weight >= ours {
			return fmt.Errorf("another highest-priority WFP hard-permit policy conflicts with protection; disable the conflicting VPN/security tunnel first")
		}
		return nil
	})
}

// Schema checks are deliberately tied to the SDK's x64 offsets. Unsupported
// architectures must not silently apply malformed firewall structures.
func init() {
	if unsafe.Sizeof(nativeFilter{}) != 200 || unsafe.Offsetof(nativeFilter{}.Context) != 152 || unsafe.Offsetof(nativeFilter{}.KernelID) != 176 || unsafe.Sizeof(nativeCondition{}) != 40 {
		panic("unsupported WFP structure layout")
	}
}
