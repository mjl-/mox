package autotls

import (
	"context"
	"crypto"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/mjl-/autocert"

	"github.com/mjl-/mox/dns"
	"github.com/mjl-/mox/mlog"
)

func TestAutotls(t *testing.T) {
	log := mlog.New("autotls", nil)
	os.RemoveAll("../testdata/autotls")
	os.MkdirAll("../testdata/autotls", 0770)

	shutdown := make(chan struct{})

	getPrivateKey := func(host string, keyType autocert.KeyType) (crypto.Signer, error) {
		return nil, fmt.Errorf("not used")
	}
	m, err := Load("test", "../testdata/autotls", "mox@localhost", "https://localhost/", "", nil, getPrivateKey, shutdown)
	if err != nil {
		t.Fatalf("load manager: %v", err)
	}
	l := m.Hostnames()
	if len(l) != 0 {
		t.Fatalf("hostnames, got %v, expected empty list", l)
	}
	if err := m.HostPolicy(context.Background(), "mox.example"); err == nil || !errors.Is(err, errHostNotAllowed) {
		t.Fatalf("hostpolicy, got err %v, expected errHostNotAllowed", err)
	}
	m.SetAllowedHostnames(log, dns.MockResolver{}, map[dns.Domain]struct{}{{ASCII: "mox.example"}: {}}, nil, false)
	l = m.Hostnames()
	if !reflect.DeepEqual(l, []dns.Domain{{ASCII: "mox.example"}}) {
		t.Fatalf("hostnames, got %v, expected single mox.example", l)
	}
	if err := m.HostPolicy(context.Background(), "mox.example"); err != nil {
		t.Fatalf("hostpolicy, got err %v, expected no error", err)
	}
	if err := m.HostPolicy(context.Background(), "mox.example:80"); err != nil {
		t.Fatalf("hostpolicy, got err %v, expected no error", err)
	}
	if err := m.HostPolicy(context.Background(), "other.mox.example"); err == nil || !errors.Is(err, errHostNotAllowed) {
		t.Fatalf("hostpolicy, got err %v, expected errHostNotAllowed", err)
	}

	ctx := context.Background()
	cache := m.Manager.Cache
	if _, err := cache.Get(ctx, "mox.example"); err == nil || !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("cache get for absent entry: got err %v, expected autocert.ErrCacheMiss", err)
	}
	if err := cache.Put(ctx, "mox.example", []byte("test")); err != nil {
		t.Fatalf("cache put for absent entry: got err %v, expected error", err)
	}
	if data, err := cache.Get(ctx, "mox.example"); err != nil || string(data) != "test" {
		t.Fatalf("cache get: got err %v data %q, expected nil, 'test'", err, data)
	}
	if err := cache.Put(ctx, "mox.example", []byte("test2")); err != nil {
		t.Fatalf("cache put for absent entry: got err %v, expected error", err)
	}
	if data, err := cache.Get(ctx, "mox.example"); err != nil || string(data) != "test2" {
		t.Fatalf("cache get: got err %v data %q, expected nil, 'test2'", err, data)
	}
	if err := cache.Delete(ctx, "mox.example"); err != nil {
		t.Fatalf("cache delete: got err %v, expected no error", err)
	}
	if _, err := cache.Get(ctx, "mox.example"); err == nil || !errors.Is(err, autocert.ErrCacheMiss) {
		t.Fatalf("cache get for absent entry: got err %v, expected autocert.ErrCacheMiss", err)
	}

	close(shutdown)
	if err := m.HostPolicy(context.Background(), "mox.example"); err == nil {
		t.Fatalf("hostpolicy, got err %v, expected error due to shutdown", err)
	}

	key0 := m.Manager.Client.Key

	m, err = Load("test", "../testdata/autotls", "mox@localhost", "https://localhost/", "", nil, getPrivateKey, shutdown)
	if err != nil {
		t.Fatalf("load manager again: %v", err)
	}
	if !reflect.DeepEqual(m.Manager.Client.Key, key0) {
		t.Fatalf("private key changed after reload")
	}
	m.shutdown = make(chan struct{})
	m.SetAllowedHostnames(log, dns.MockResolver{}, map[dns.Domain]struct{}{{ASCII: "mox.example"}: {}}, nil, false)
	if err := m.HostPolicy(context.Background(), "mox.example"); err != nil {
		t.Fatalf("hostpolicy, got err %v, expected no error", err)
	}

	m2, err := Load("test2", "../testdata/autotls", "mox@localhost", "https://localhost/", "", nil, nil, shutdown)
	if err != nil {
		t.Fatalf("load another manager: %v", err)
	}
	if reflect.DeepEqual(m.Manager.Client.Key, m2.Manager.Client.Key) {
		t.Fatalf("private key reused between managers")
	}

	// Only remove in case of success.
	os.RemoveAll("../testdata/autotls")
}
