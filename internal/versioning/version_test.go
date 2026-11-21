package versioning

import "testing"

func TestNextRelease(t *testing.T) {
	for _, tc := range []struct {
		name       string
		tags       []string
		bump, want string
	}{
		{"first", nil, "patch", "v0.1.0"},
		{"numeric order", []string{"v0.9.9", "v0.10.0", "v0.2.0"}, "patch", "v0.10.1"},
		{"minor", []string{"v1.4.9"}, "minor", "v1.5.0"},
		{"major", []string{"v1.4.9"}, "major", "v2.0.0"},
		{"skip unrelated and prerelease", []string{"other", "v02.0.0", "v2.0.0-rc.1", "v1.9.2"}, "patch", "v1.9.3"},
		{"stable zero", []string{"v0.0.0"}, "patch", "v0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Next(tc.tags, tc.bump)
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}
func TestRejectInvalidAndOverflowingRelease(t *testing.T) {
	for _, tc := range []struct {
		tags []string
		bump string
	}{
		{nil, "unknown"}, {[]string{"v1.2.65535"}, "patch"}, {[]string{"v65536.0.0"}, "patch"},
	} {
		if _, err := Next(tc.tags, tc.bump); err == nil {
			t.Fatalf("accepted %+v", tc)
		}
	}
}
