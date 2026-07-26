package controlplane

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStoreEnrollmentPersistenceRotationAndRevocation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.db")
	master := []byte("0123456789abcdef0123456789abcdef")
	pool := netip.MustParsePrefix("10.77.0.0/29")
	store, err := OpenStore(path, master, pool, []netip.Addr{
		netip.MustParseAddr("10.77.0.1"),
		netip.MustParseAddr("10.77.0.2"),
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 26, 12, 0, 0, 0, time.UTC)
	code, activation, err := store.CreateActivation("user-1", "laptop", 15*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if code == "" || activation.UserID != "user-1" {
		t.Fatalf("unexpected activation: %q %#v", code, activation)
	}
	device, psk, err := store.Enroll(code, "", "linux", now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if device.TunnelAddress != "10.77.0.3/29" || len(device.ClientID) != 32 || psk == "" {
		t.Fatalf("unexpected enrollment: %#v", device)
	}
	if _, _, err := store.Enroll(code, "", "linux", now.Add(2*time.Minute)); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("activation reuse returned %v", err)
	}
	credentials, err := store.ActiveCredentials()
	if err != nil {
		t.Fatal(err)
	}
	if len(credentials) != 1 || credentials[0].PSK != psk {
		t.Fatalf("credential was not decrypted: %#v", credentials)
	}
	rotated, rotatedPSK, err := store.Rotate(device.ClientID, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if rotatedPSK == psk || rotated.ClientID != device.ClientID {
		t.Fatal("rotation did not preserve identity and replace the key")
	}
	if err := store.Touch(device.ClientID, now.Add(4*time.Minute)); err != nil {
		t.Fatal(err)
	}
	revoked, err := store.Revoke(device.ClientID, now.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if revoked.RevokedAt == nil || revoked.LastSeenAt == nil {
		t.Fatalf("device record was not updated: %#v", revoked)
	}
	credentials, err = store.ActiveCredentials()
	if err != nil || len(credentials) != 0 {
		t.Fatalf("revoked credential remains active: %#v %v", credentials, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("database permissions are too broad: %o", info.Mode().Perm())
	}

	reopened, err := OpenStore(path, master, pool, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	devices, err := reopened.ListDevices()
	if err != nil || len(devices) != 1 || devices[0].RevokedAt == nil {
		t.Fatalf("device did not persist: %#v %v", devices, err)
	}
}

func TestStoreRejectsExpiredActivationAndExhaustedPool(t *testing.T) {
	store, err := OpenStore(
		filepath.Join(t.TempDir(), "control.db"),
		[]byte("0123456789abcdef0123456789abcdef"),
		netip.MustParsePrefix("10.88.0.0/30"),
		[]netip.Addr{netip.MustParseAddr("10.88.0.1")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	expired, _, err := store.CreateActivation("user", "expired", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Enroll(expired, "", "linux", now.Add(time.Minute)); !errors.Is(err, ErrInvalidActivation) {
		t.Fatalf("expired activation returned %v", err)
	}
	first, _, _ := store.CreateActivation("user", "one", time.Minute, now)
	if _, _, err := store.Enroll(first, "", "linux", now); err != nil {
		t.Fatal(err)
	}
	second, _, _ := store.CreateActivation("user", "two", time.Minute, now)
	if _, _, err := store.Enroll(second, "", "linux", now); !errors.Is(err, ErrPoolExhausted) {
		t.Fatalf("exhausted pool returned %v", err)
	}
}
