// Package versioning handles release tags and Windows-compatible version fields.
package versioning

import (
	"fmt"
	"regexp"
	"strconv"
)

var pattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

type Version [3]uint16

func Parse(tag string) (Version, error) {
	var v Version
	m := pattern.FindStringSubmatch(tag)
	if m == nil {
		return v, fmt.Errorf("expected a stable vMAJOR.MINOR.PATCH version: %q", tag)
	}
	for i := range v {
		n, err := strconv.ParseUint(m[i+1], 10, 16)
		if err != nil {
			return v, fmt.Errorf("version component exceeds Windows' 65535 limit: %q", tag)
		}
		v[i] = uint16(n)
	}
	return v, nil
}
func (v Version) String() string { return fmt.Sprintf("v%d.%d.%d", v[0], v[1], v[2]) }

func Next(tags []string, bump string) (string, error) {
	index := map[string]int{"major": 0, "minor": 1, "patch": 2}
	part, ok := index[bump]
	if !ok {
		return "", fmt.Errorf("invalid version bump %q", bump)
	}
	var latest Version
	found := false
	for _, tag := range tags {
		// Ignore unrelated tags and prereleases, but do not silently ignore a
		// stable version that cannot be represented in Windows file metadata.
		if !pattern.MatchString(tag) {
			continue
		}
		v, err := Parse(tag)
		if err != nil {
			return "", err
		}
		if !found || greater(v, latest) {
			latest = v
			found = true
		}
	}
	if !found {
		return "v0.1.0", nil
	}
	if latest[part] == 65535 {
		return "", fmt.Errorf("version component overflow; select a larger version bump")
	}
	latest[part]++
	for i := part + 1; i < 3; i++ {
		latest[i] = 0
	}
	return latest.String(), nil
}
func greater(a, b Version) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return false
}
