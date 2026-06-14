package autodns

import (
	"strings"
	"testing"
)

func TestLoad(t *testing.T) {
	a, mr := newTestAutodns(t)
	seedExampleZone(t, mr, a)

	z := a.load(exampleZone)
	if z == nil {
		t.Fatal("load returned nil")
	}
	if z.Name != exampleZone {
		t.Fatalf("zone name = %q, want %q", z.Name, exampleZone)
	}
	for _, key := range []string{"@", "host1", "*", "sub.*"} {
		if _, ok := z.Locations[key]; !ok {
			t.Fatalf("missing location %q", key)
		}
	}
}

func TestGet(t *testing.T) {
	a, mr := newTestAutodns(t)
	seedExampleZone(t, mr, a)
	z := a.load(exampleZone)

	t.Run("apex", func(t *testing.T) {
		rec := a.get(exampleZone, z)
		if rec == nil || rec.SOA.Ns != "ns1.example.net." {
			t.Fatalf("apex SOA: %+v", rec)
		}
	})

	t.Run("host1 A", func(t *testing.T) {
		rec := a.get("host1", z)
		if rec == nil || len(rec.A) != 1 || rec.A[0].Ip.String() != "5.5.5.5" {
			t.Fatalf("host1 A: %+v", rec)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		zoneKey := a.keyPrefix + exampleZone + a.keySuffix
		mr.HSet(zoneKey, "bad", "not-json")
		z.Locations["bad"] = struct{}{}
		if rec := a.get("bad", z); rec != nil {
			t.Fatalf("expected nil for invalid JSON, got %+v", rec)
		}
	})
}

func TestLoadZones(t *testing.T) {
	t.Run("keys with prefix suffix", func(t *testing.T) {
		a, mr := newTestAutodns(t, func(a *Autodns) {
			a.keyPrefix = "dns:"
			a.keySuffix = ":zone"
		})
		zoneKey := "dns:" + exampleZone + ":zone"
		mr.HSet(zoneKey, "host1", `{"a":[{"ttl":300,"ip":"1.2.3.4"}]}`)

		a.LoadZones()
		if len(a.Zones) != 1 || a.Zones[0] != exampleZone {
			t.Fatalf("zones = %v, want [%q]", a.Zones, exampleZone)
		}
	})

	t.Run("autocreate", func(t *testing.T) {
		a, _ := newTestAutodns(t, func(a *Autodns) {
			a.AutoCreate = []string{"newzone.example."}
		})
		a.LoadZones()

		found := false
		for _, z := range a.Zones {
			if z == "newzone.example." {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("autocreate zone missing from %v", a.Zones)
		}

		z := a.load("newzone.example.")
		if z == nil {
			t.Fatal("autocreated zone load returned nil")
		}
		if _, ok := z.Locations["@"]; !ok {
			t.Fatal("autocreated zone missing @ SOA")
		}
	})
}

func TestCreateZone(t *testing.T) {
	a, mr := newTestAutodns(t)
	if err := a.CreateZone("test.com"); err != nil {
		t.Fatal(err)
	}

	zoneKey := a.keyPrefix + "test.com." + a.keySuffix
	val := mr.HGet(zoneKey, "@")
	if val == "" || !strings.Contains(val, `"soa"`) {
		t.Fatalf("expected SOA JSON, got %q", val)
	}
}

func TestAddRegisteredRecord(t *testing.T) {
	a, mr := newTestAutodns(t)
	a.Ttl = 300
	zoneKey := a.keyPrefix + exampleZone + a.keySuffix

	t.Run("IPv4 A record", func(t *testing.T) {
		if err := a.AddRegisteredRecord(exampleZone, "v4host", "100.64.0.5"); err != nil {
			t.Fatal(err)
		}
		want := `{"a": [{"ip": "100.64.0.5", "ttl": 300}]}`
		if got := mr.HGet(zoneKey, "v4host"); got != want {
			t.Fatalf("HGET v4host = %q, want %q", got, want)
		}
	})

	t.Run("IPv6 AAAA record", func(t *testing.T) {
		if err := a.AddRegisteredRecord(exampleZone, "v6host", "fd00::10"); err != nil {
			t.Fatal(err)
		}
		want := `{"aaaa": [{"ip": "fd00::10", "ttl": 300}]}`
		if got := mr.HGet(zoneKey, "v6host"); got != want {
			t.Fatalf("HGET v6host = %q, want %q", got, want)
		}
	})
}

func TestAddARecord(t *testing.T) {
	a, mr := newTestAutodns(t)
	a.Ttl = 300

	if err := a.AddARecord(exampleZone, "newhost", "100.64.0.5"); err != nil {
		t.Fatal(err)
	}

	zoneKey := a.keyPrefix + exampleZone + a.keySuffix
	want := `{"a": [{"ip": "100.64.0.5", "ttl": 300}]}`
	val := mr.HGet(zoneKey, "newhost")
	if val != want {
		t.Fatalf("HGET newhost = %q, want %q", val, want)
	}
}
