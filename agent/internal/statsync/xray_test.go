package statsync

import "testing"

func TestParseUserTrafficStat(t *testing.T) {
	email, dir, ok := parseUserTrafficStat("user>>>abc+vless_reality@kosiro.local>>>traffic>>>downlink")
	if !ok || email != "abc+vless_reality@kosiro.local" || dir != "downlink" {
		t.Fatalf("unexpected parse: ok=%v email=%q dir=%q", ok, email, dir)
	}
	_, _, ok = parseUserTrafficStat("inbound>>>vless_reality>>>traffic>>>uplink")
	if ok {
		t.Fatal("expected inbound stat to be ignored")
	}
}

func TestResolveUserAndProtocol(t *testing.T) {
	uuidToID := map[string]string{"user-uuid": "user-id"}
	legacy := map[string]string{"user-uuid@kosiro.local": "user-id"}

	id, proto := resolveUserAndProtocol("user-uuid+vless_reality@kosiro.local", uuidToID, legacy)
	if id != "user-id" || proto != "vless_reality" {
		t.Fatalf("got id=%q proto=%q", id, proto)
	}

	id, proto = resolveUserAndProtocol("user-uuid@kosiro.local", uuidToID, legacy)
	if id != "user-id" || proto != "vless_reality" {
		t.Fatalf("legacy got id=%q proto=%q", id, proto)
	}
}
