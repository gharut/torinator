//go:build windows

// Package platform contains Windows privileges, storage and adapter cleanup.
package platform

import (
	"crypto/md5"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/gharut/torinator/internal/routing"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func Elevate() (bool, error) {
	if windows.GetCurrentProcessToken().IsElevated() {
		return false, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return false, err
	}
	args := windows.ComposeCommandLine(os.Args[1:])
	err = windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(exe), windows.StringToUTF16Ptr(args), windows.StringToUTF16Ptr(filepath.Dir(exe)), 0)
	return true, err
}

func SingleInstance() (func(), error) {
	h, err := windows.CreateMutex(nil, false, windows.StringToUTF16Ptr(`Global\Torinator.SystemRouting.v1`))
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		if h != 0 {
			windows.CloseHandle(h)
		}
		return nil, fmt.Errorf("Torinator is already running (check the tray's hidden icons)")
	}
	if err != nil {
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}

// Store uses an administrators-only directory: elevated code must never load
// executable/DLL payloads from an unelevated user's writable cache.
func Store() (string, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	base, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	dir := filepath.Join(base, "Torinator-"+user.User.Sid.String())
	sd, err := windows.SecurityDescriptorFromString("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return "", err
	}
	sa := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(windows.StringToUTF16Ptr(dir), &sa)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return "", err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", err
	}
	attr, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(dir))
	if err != nil {
		return "", err
	}
	if !info.IsDir() || attr&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return "", fmt.Errorf("unsafe state directory %s", dir)
	}
	actual, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "", err
	}
	// Compare the protected DACL and owner, rather than accepting a pre-created
	// user-writable directory with the expected name.
	if actual.String() != sd.String() {
		return "", fmt.Errorf("state directory has unexpected permissions: %s", dir)
	}
	return dir, nil
}

// AdapterGUID matches the pinned sing-tun name-derived GUID, not an arbitrary
// adapter with a similar display name. MD5 here is an upstream identifier only.
func AdapterGUID() windows.GUID {
	sum := md5.Sum([]byte("wintun" + routing.AdapterName))
	return *(*windows.GUID)(unsafe.Pointer(&sum[0]))
}

func RemoveAdapter() error {
	netClass := windows.GUID{Data1: 0x4d36e972, Data2: 0xe325, Data3: 0x11ce, Data4: [8]byte{0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18}}
	set, err := windows.SetupDiGetClassDevsEx(&netClass, "", 0, 0, 0, "")
	if err != nil {
		return err
	}
	defer set.Close()
	for i := 0; ; i++ {
		dev, err := set.EnumDeviceInfo(i)
		if errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
			return nil
		}
		if err != nil {
			return err
		}
		h, err := set.OpenDevRegKey(dev, windows.DICS_FLAG_GLOBAL, 0, windows.DIREG_DRV, windows.KEY_READ)
		if err != nil {
			continue
		}
		key := registry.Key(h)
		id, _, readErr := key.GetStringValue("NetCfgInstanceId")
		key.Close()
		if readErr != nil || !strings.EqualFold(id, AdapterGUID().String()) {
			continue
		}
		hardware, err := set.DeviceRegistryProperty(dev, windows.SPDRP_HARDWAREID)
		if err != nil {
			return err
		}
		ids, ok := hardware.([]string)
		wintun := false
		for _, id := range ids {
			if strings.EqualFold(id, "Wintun") {
				wintun = true
			}
		}
		if !ok || !wintun {
			return fmt.Errorf("refusing to remove a non-Wintun device with Torinator's GUID")
		}
		params := windows.RemoveDeviceParams{ClassInstallHeader: *windows.MakeClassInstallHeader(windows.DIF_REMOVE), Scope: windows.DI_REMOVEDEVICE_GLOBAL}
		if err := set.SetClassInstallParams(dev, &params.ClassInstallHeader, uint32(unsafe.Sizeof(params))); err != nil {
			return err
		}
		if err := set.CallClassInstaller(windows.DIF_REMOVE, dev); err != nil {
			return err
		}
		return nil
	}
}

func FlushDNS() error {
	r, _, err := windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache").Call()
	if r == 0 {
		return fmt.Errorf("flush DNS: %w", err)
	}
	return nil
}

func OpenFile(path string) error {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return err
	}
	// A medium-integrity file-association handler cannot read our protected log.
	return windows.ShellExecute(0, windows.StringToUTF16Ptr("runas"), windows.StringToUTF16Ptr(filepath.Join(system, "notepad.exe")), windows.StringToUTF16Ptr(windows.ComposeCommandLine([]string{path})), nil, 1)
}
