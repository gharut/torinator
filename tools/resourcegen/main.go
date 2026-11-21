// resourcegen produces the Explorer icon and Windows VERSIONINFO at build time.
package main

import (
	"flag"
	"fmt"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"

	"github.com/gharut/torinator/internal/branding"
	"github.com/gharut/torinator/internal/versioning"
	"github.com/tc-hib/winres"
	"github.com/tc-hib/winres/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	tag := flag.String("version", "v0.0.0-dev", "application version")
	output := flag.String("output", "cmd/torinator/resource_windows_amd64.syso", "COFF resource object")
	assetDir := flag.String("assets", "assets", "icon preview directory")
	flag.Parse()
	stable := strings.TrimSuffix(*tag, "-dev")
	v, err := versioning.Parse(stable)
	if err != nil {
		return err
	}
	var images []image.Image
	for _, size := range []int{16, 20, 24, 32, 40, 48, 64, 128, 256} {
		images = append(images, branding.Icon(size))
	}
	icon, err := winres.NewIconFromImages(images)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*assetDir, 0755); err != nil {
		return err
	}
	if err := write(filepath.Join(*assetDir, "torinator.ico"), func(f *os.File) error { return icon.SaveICO(f) }); err != nil {
		return err
	}
	if err := write(filepath.Join(*assetDir, "torinator.png"), func(f *os.File) error { return png.Encode(f, images[len(images)-1]) }); err != nil {
		return err
	}
	rs := winres.ResourceSet{}
	if err := rs.SetIcon(winres.ID(1), icon); err != nil {
		return err
	}
	info := version.Info{FileVersion: [4]uint16{v[0], v[1], v[2], 0}, ProductVersion: [4]uint16{v[0], v[1], v[2], 0}, Type: version.App}
	for key, value := range map[string]string{
		version.ProductName: "Torinator", version.FileDescription: "Torinator — Tor routing and tray control",
		version.InternalName: "torinator", version.OriginalFilename: "torinator.exe",
		version.FileVersion: strings.TrimPrefix(*tag, "v"), version.ProductVersion: *tag,
	} {
		if err := info.Set(version.LangDefault, key, value); err != nil {
			return err
		}
	}
	rs.SetVersionInfo(info)
	return write(*output, func(f *os.File) error { return rs.WriteObject(f, winres.ArchAMD64) })
}

func write(path string, fn func(*os.File) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	err = fn(f)
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}
