package helpers

import (
	"testing"
)

func FuzzUntrustedInput(f *testing.F) {
	for _, seed := range []string{
		"127.0.0.1:80",
		"[2001:db8::1]:443",
		"[::]:65536",
		"[fe80::1%eth0]:53",
		"not-an-address",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, value string) {
		addrPort, err := AddrPortFromString(value)
		again, againErr := AddrPortFromString(value)
		if (err == nil) != (againErr == nil) || addrPort != again {
			t.Fatalf(
				"AddrPortFromString(%q) is not deterministic: (%v, %v), then (%v, %v)",
				value, addrPort, err, again, againErr,
			)
		}
	})
}
