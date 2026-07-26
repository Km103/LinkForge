package controlplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Km103/LinkForge/internal/config"
	"github.com/Km103/LinkForge/internal/protocol"
	bolt "go.etcd.io/bbolt"
)

var (
	ErrInvalidActivation = errors.New("invalid or expired activation code")
	ErrDeviceNotFound    = errors.New("device not found")
	ErrPoolExhausted     = errors.New("tunnel address pool is exhausted")
)

var (
	bucketMeta        = []byte("meta")
	bucketActivations = []byte("activations")
	bucketDevices     = []byte("devices")
	bucketAudit       = []byte("audit")
	keySchemaVersion  = []byte("schema_version")
)

const schemaVersion = "1"

type Store struct {
	db       *bolt.DB
	aead     cipher.AEAD
	pool     netip.Prefix
	reserved map[netip.Addr]bool
}

type Activation struct {
	UserID     string     `json:"user_id"`
	DeviceName string     `json:"device_name"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
	UsedBy     string     `json:"used_by,omitempty"`
}

type Device struct {
	ClientID      string     `json:"client_id"`
	UserID        string     `json:"user_id"`
	Name          string     `json:"name"`
	Platform      string     `json:"platform"`
	TunnelAddress string     `json:"tunnel_address"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	LastSeenAt    *time.Time `json:"last_seen_at,omitempty"`
	RevokedAt     *time.Time `json:"revoked_at,omitempty"`
	EncryptedPSK  string     `json:"-"`
}

type storedDevice struct {
	Device
	EncryptedPSK string `json:"encrypted_psk"`
}

type AuditEvent struct {
	Type      string    `json:"type"`
	SubjectID string    `json:"subject_id"`
	UserID    string    `json:"user_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

func OpenStore(path string, masterKey []byte, pool netip.Prefix, reserved []netip.Addr) (*Store, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("control-plane master key must be 32 bytes")
	}
	if !pool.Addr().Is4() || pool.Bits() < 16 || pool.Bits() > 30 {
		return nil, errors.New("control-plane tunnel pool must be IPv4 between /16 and /30")
	}
	block, err := aes.NewCipher(masterKey)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create control database directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open control database: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("protect control database: %w", err)
	}
	store := &Store{
		db:       db,
		aead:     aead,
		pool:     pool.Masked(),
		reserved: make(map[netip.Addr]bool),
	}
	for _, address := range reserved {
		if address.IsValid() {
			store.reserved[address] = true
		}
	}
	if err := store.initialize(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) initialize() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		meta, err := tx.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return err
		}
		for _, name := range [][]byte{bucketActivations, bucketDevices, bucketAudit} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		version := meta.Get(keySchemaVersion)
		if version == nil {
			return meta.Put(keySchemaVersion, []byte(schemaVersion))
		}
		if string(version) != schemaVersion {
			return fmt.Errorf("unsupported control database schema %q", version)
		}
		return nil
	})
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) CreateActivation(userID, deviceName string, ttl time.Duration, now time.Time) (string, Activation, error) {
	userID = strings.TrimSpace(userID)
	deviceName = strings.TrimSpace(deviceName)
	if userID == "" || len(userID) > 128 {
		return "", Activation{}, errors.New("user_id is required and cannot exceed 128 bytes")
	}
	if deviceName == "" || len(deviceName) > 128 {
		return "", Activation{}, errors.New("device_name is required and cannot exceed 128 bytes")
	}
	if ttl < time.Minute || ttl > 24*time.Hour {
		return "", Activation{}, errors.New("activation TTL must be between 1 minute and 24 hours")
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", Activation{}, err
	}
	code := "lf_" + base64.RawURLEncoding.EncodeToString(raw)
	hash := sha256.Sum256([]byte(code))
	activation := Activation{
		UserID:     userID,
		DeviceName: deviceName,
		CreatedAt:  now.UTC(),
		ExpiresAt:  now.Add(ttl).UTC(),
	}
	err := s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(bucketActivations)
		if err := pruneActivations(bucket, now.Add(-24*time.Hour)); err != nil {
			return err
		}
		if bucket.Get(hash[:]) != nil {
			return errors.New("activation collision")
		}
		encoded, err := json.Marshal(activation)
		if err != nil {
			return err
		}
		if err := bucket.Put(hash[:], encoded); err != nil {
			return err
		}
		return appendAudit(tx, AuditEvent{
			Type: "activation.created", UserID: userID, Timestamp: now.UTC(),
		})
	})
	return code, activation, err
}

func pruneActivations(bucket *bolt.Bucket, cutoff time.Time) error {
	cursor := bucket.Cursor()
	for key, value := cursor.First(); key != nil; key, value = cursor.Next() {
		var activation Activation
		if err := json.Unmarshal(value, &activation); err != nil {
			return err
		}
		finished := activation.ExpiresAt
		if activation.UsedAt != nil {
			finished = *activation.UsedAt
		}
		if finished.Before(cutoff) {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) Enroll(code, requestedName, platform string, now time.Time) (Device, string, error) {
	if !strings.HasPrefix(code, "lf_") || len(code) < 20 {
		return Device{}, "", ErrInvalidActivation
	}
	requestedName = strings.TrimSpace(requestedName)
	platform = strings.ToLower(strings.TrimSpace(platform))
	if len(requestedName) > 128 {
		return Device{}, "", errors.New("device_name cannot exceed 128 bytes")
	}
	if platform == "" || len(platform) > 32 {
		return Device{}, "", errors.New("platform is required and cannot exceed 32 bytes")
	}
	hash := sha256.Sum256([]byte(code))
	var result Device
	var psk string
	err := s.db.Update(func(tx *bolt.Tx) error {
		activationBucket := tx.Bucket(bucketActivations)
		encodedActivation := activationBucket.Get(hash[:])
		if encodedActivation == nil {
			return ErrInvalidActivation
		}
		var activation Activation
		if err := json.Unmarshal(encodedActivation, &activation); err != nil {
			return err
		}
		if activation.UsedAt != nil || !now.Before(activation.ExpiresAt) {
			return ErrInvalidActivation
		}
		name := requestedName
		if name == "" {
			name = activation.DeviceName
		}
		clientID, err := protocol.GenerateClientID()
		if err != nil {
			return err
		}
		psk, err = protocol.GenerateKey()
		if err != nil {
			return err
		}
		address, err := s.allocateAddress(tx)
		if err != nil {
			return err
		}
		encrypted, err := s.encryptPSK(clientID, psk)
		if err != nil {
			return err
		}
		timestamp := now.UTC()
		result = Device{
			ClientID:      clientID,
			UserID:        activation.UserID,
			Name:          name,
			Platform:      platform,
			TunnelAddress: fmt.Sprintf("%s/%d", address, s.pool.Bits()),
			CreatedAt:     timestamp,
			UpdatedAt:     timestamp,
		}
		stored := storedDevice{Device: result, EncryptedPSK: encrypted}
		encodedDevice, err := json.Marshal(stored)
		if err != nil {
			return err
		}
		if err := tx.Bucket(bucketDevices).Put([]byte(clientID), encodedDevice); err != nil {
			return err
		}
		activation.UsedAt = &timestamp
		activation.UsedBy = clientID
		encodedActivation, err = json.Marshal(activation)
		if err != nil {
			return err
		}
		if err := activationBucket.Put(hash[:], encodedActivation); err != nil {
			return err
		}
		return appendAudit(tx, AuditEvent{
			Type: "device.enrolled", SubjectID: clientID, UserID: activation.UserID, Timestamp: timestamp,
		})
	})
	if errors.Is(err, ErrInvalidActivation) {
		return Device{}, "", ErrInvalidActivation
	}
	return result, psk, err
}

func (s *Store) ActiveCredentials() ([]config.ClientCredential, error) {
	var credentials []config.ClientCredential
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).ForEach(func(_, value []byte) error {
			var stored storedDevice
			if err := json.Unmarshal(value, &stored); err != nil {
				return err
			}
			if stored.RevokedAt != nil {
				return nil
			}
			psk, err := s.decryptPSK(stored.ClientID, stored.EncryptedPSK)
			if err != nil {
				return err
			}
			credentials = append(credentials, config.ClientCredential{
				Name:          stored.Name,
				ClientID:      stored.ClientID,
				PSK:           psk,
				TunnelAddress: stored.TunnelAddress,
			})
			return nil
		})
	})
	return credentials, err
}

func (s *Store) ListDevices() ([]Device, error) {
	var devices []Device
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketDevices).ForEach(func(_, value []byte) error {
			var stored storedDevice
			if err := json.Unmarshal(value, &stored); err != nil {
				return err
			}
			stored.Device.EncryptedPSK = ""
			devices = append(devices, stored.Device)
			return nil
		})
	})
	return devices, err
}

func (s *Store) Revoke(clientID string, now time.Time) (Device, error) {
	var result Device
	err := s.db.Update(func(tx *bolt.Tx) error {
		stored, err := loadDevice(tx, clientID)
		if err != nil {
			return err
		}
		if stored.RevokedAt == nil {
			timestamp := now.UTC()
			stored.RevokedAt = &timestamp
			stored.UpdatedAt = timestamp
			if err := putDevice(tx, stored); err != nil {
				return err
			}
			if err := appendAudit(tx, AuditEvent{
				Type: "device.revoked", SubjectID: clientID, UserID: stored.UserID, Timestamp: timestamp,
			}); err != nil {
				return err
			}
		}
		result = stored.Device
		return nil
	})
	return result, err
}

func (s *Store) Rotate(clientID string, now time.Time) (Device, string, error) {
	var result Device
	var psk string
	err := s.db.Update(func(tx *bolt.Tx) error {
		stored, err := loadDevice(tx, clientID)
		if err != nil {
			return err
		}
		if stored.RevokedAt != nil {
			return errors.New("cannot rotate a revoked device")
		}
		psk, err = protocol.GenerateKey()
		if err != nil {
			return err
		}
		stored.EncryptedPSK, err = s.encryptPSK(clientID, psk)
		if err != nil {
			return err
		}
		stored.UpdatedAt = now.UTC()
		if err := putDevice(tx, stored); err != nil {
			return err
		}
		if err := appendAudit(tx, AuditEvent{
			Type: "device.key_rotated", SubjectID: clientID, UserID: stored.UserID, Timestamp: now.UTC(),
		}); err != nil {
			return err
		}
		result = stored.Device
		return nil
	})
	return result, psk, err
}

func (s *Store) Touch(clientID string, now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		stored, err := loadDevice(tx, clientID)
		if errors.Is(err, ErrDeviceNotFound) {
			return nil // static config credentials are not management records.
		}
		if err != nil {
			return err
		}
		timestamp := now.UTC()
		stored.LastSeenAt = &timestamp
		return putDevice(tx, stored)
	})
}

func (s *Store) allocateAddress(tx *bolt.Tx) (netip.Addr, error) {
	used := make(map[netip.Addr]bool, len(s.reserved))
	for address := range s.reserved {
		used[address] = true
	}
	if err := tx.Bucket(bucketDevices).ForEach(func(_, value []byte) error {
		var stored storedDevice
		if err := json.Unmarshal(value, &stored); err != nil {
			return err
		}
		prefix, err := netip.ParsePrefix(stored.TunnelAddress)
		if err != nil {
			return err
		}
		used[prefix.Addr()] = true // Never silently reuse a revoked address.
		return nil
	}); err != nil {
		return netip.Addr{}, err
	}
	for address := s.pool.Addr().Next(); address.IsValid() && s.pool.Contains(address); address = address.Next() {
		next := address.Next()
		if !next.IsValid() || !s.pool.Contains(next) { // IPv4 broadcast address.
			break
		}
		if !used[address] {
			return address, nil
		}
	}
	return netip.Addr{}, ErrPoolExhausted
}

func (s *Store) encryptPSK(clientID, psk string) (string, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(psk), []byte(clientID))
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

func (s *Store) decryptPSK(clientID, encrypted string) (string, error) {
	sealed, err := base64.RawStdEncoding.DecodeString(encrypted)
	if err != nil || len(sealed) < s.aead.NonceSize() {
		return "", errors.New("invalid encrypted device key")
	}
	nonce := sealed[:s.aead.NonceSize()]
	plaintext, err := s.aead.Open(nil, nonce, sealed[s.aead.NonceSize():], []byte(clientID))
	if err != nil {
		return "", errors.New("decrypt device key: authentication failed")
	}
	if _, err := protocol.ParseKey(string(plaintext)); err != nil {
		return "", errors.New("decrypted device key is invalid")
	}
	return string(plaintext), nil
}

func loadDevice(tx *bolt.Tx, clientID string) (storedDevice, error) {
	value := tx.Bucket(bucketDevices).Get([]byte(clientID))
	if value == nil {
		return storedDevice{}, ErrDeviceNotFound
	}
	var stored storedDevice
	if err := json.Unmarshal(value, &stored); err != nil {
		return storedDevice{}, err
	}
	return stored, nil
}

func putDevice(tx *bolt.Tx, stored storedDevice) error {
	encoded, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	return tx.Bucket(bucketDevices).Put([]byte(stored.ClientID), encoded)
}

func appendAudit(tx *bolt.Tx, event AuditEvent) error {
	bucket := tx.Bucket(bucketAudit)
	sequence, err := bucket.NextSequence()
	if err != nil {
		return err
	}
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], sequence)
	encoded, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return bucket.Put(key[:], encoded)
}
