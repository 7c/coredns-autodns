package autodns

import "testing"

func TestUniformZone(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "lowercase with trailing dot", in: "Example.COM.", want: "example.com."},
		{name: "without trailing dot", in: "example.com", want: "example.com."},
		{name: "trim whitespace", in: "  example.com  ", want: "example.com."},
		{name: "already uniform", in: "example.net.", want: "example.net."},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := UniformZone(tc.in); got != tc.want {
				t.Fatalf("UniformZone(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
