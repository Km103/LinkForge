// Package protocol implements the LinkForge encrypted multipath wire protocol.
//
// The protocol intentionally keeps routing metadata in a small authenticated
// header and encrypts every post-handshake payload with AES-256-GCM. It is not
// wire compatible with any commercial VPN.
package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	Version          = 1
	HeaderSize       = 28
	TagSize          = 16
	MaxDatagram      = 64 * 1024
	MaxPayload       = MaxDatagram - HeaderSize - TagSize
	MaxDataPayload   = MaxPayload - 8
	HandshakeSkew    = 2 * time.Minute
	helloV1FixedSize = 16 + 16 + 8 + 2 + 1 + 32
	helloV2FixedSize = 16 + 16 + 16 + 8 + 2 + 1 + 32
	welcomeSize      = 16 + 16 + 8 + 32
)

var (
	magic            = [4]byte{'L', 'F', 'M', 'P'}
	ErrBadPacket     = errors.New("invalid LinkForge packet")
	ErrAuth          = errors.New("packet authentication failed")
	ErrReplay        = errors.New("replayed or stale packet")
	ErrClockSkew     = errors.New("handshake clock outside allowed skew")
	ErrVersion       = errors.New("unsupported protocol version")
	ErrPayloadTooBig = errors.New("payload exceeds protocol maximum")
)

type Type uint8

const (
	TypeHello Type = iota + 1
	TypeWelcome
	TypeData
	TypePing
	TypePong
	TypeProbe
	TypeProbeReply
	TypeClose
)

type Direction uint32

const (
	ClientToServer Direction = 0
	ServerToClient Direction = 1
)

// Header is authenticated as AEAD additional data after the handshake.
type Header struct {
	Type      Type
	Flags     uint16
	SessionID uint64
	PathID    uint32
	Sequence  uint64
}

func (h Header) MarshalBinary() []byte {
	b := make([]byte, HeaderSize)
	copy(b[0:4], magic[:])
	b[4] = Version
	b[5] = byte(h.Type)
	binary.BigEndian.PutUint16(b[6:8], h.Flags)
	binary.BigEndian.PutUint64(b[8:16], h.SessionID)
	binary.BigEndian.PutUint32(b[16:20], h.PathID)
	binary.BigEndian.PutUint64(b[20:28], h.Sequence)
	return b
}

func ParseHeader(packet []byte) (Header, error) {
	if len(packet) < HeaderSize || subtle.ConstantTimeCompare(packet[0:4], magic[:]) != 1 {
		return Header{}, ErrBadPacket
	}
	if packet[4] != Version {
		return Header{}, ErrVersion
	}
	return Header{
		Type:      Type(packet[5]),
		Flags:     binary.BigEndian.Uint16(packet[6:8]),
		SessionID: binary.BigEndian.Uint64(packet[8:16]),
		PathID:    binary.BigEndian.Uint32(packet[16:20]),
		Sequence:  binary.BigEndian.Uint64(packet[20:28]),
	}, nil
}

func IsHandshake(t Type) bool {
	return t == TypeHello || t == TypeWelcome
}

type Hello struct {
	ClientID      [16]byte
	InstanceNonce [16]byte
	Nonce         [16]byte
	Time          time.Time
	PathName      string
	Weight        uint16
	WireVersion   uint8
}

func NewHello(clientID, instanceNonce [16]byte, pathName string, weight float64) (Hello, error) {
	if len(pathName) > 63 {
		return Hello{}, fmt.Errorf("path name must be at most 63 bytes")
	}
	if instanceNonce == ([16]byte{}) {
		return Hello{}, errors.New("client instance nonce must not be empty")
	}
	wireWeight := uint16(weight*100 + 0.5)
	if wireWeight == 0 {
		wireWeight = 100
	}
	h := Hello{
		ClientID:      clientID,
		InstanceNonce: instanceNonce,
		Time:          time.Now().UTC(),
		PathName:      pathName,
		Weight:        wireWeight,
		WireVersion:   2,
	}
	if _, err := rand.Read(h.Nonce[:]); err != nil {
		return Hello{}, fmt.Errorf("create handshake nonce: %w", err)
	}
	return h, nil
}

func (h Hello) Marshal(key []byte) ([]byte, error) {
	if len(h.PathName) > 63 {
		return nil, fmt.Errorf("path name must be at most 63 bytes")
	}
	if h.InstanceNonce == ([16]byte{}) {
		return nil, errors.New("client instance nonce must not be empty")
	}
	b := make([]byte, helloV2FixedSize+len(h.PathName))
	copy(b[0:16], h.ClientID[:])
	copy(b[16:32], h.InstanceNonce[:])
	copy(b[32:48], h.Nonce[:])
	binary.BigEndian.PutUint64(b[48:56], uint64(h.Time.Unix()))
	binary.BigEndian.PutUint16(b[56:58], h.Weight)
	b[58] = byte(len(h.PathName))
	copy(b[59:59+len(h.PathName)], h.PathName)
	macAt := len(b) - sha256.Size
	copy(b[macAt:], sign(key, []byte("linkforge/hello/v2"), b[:macAt]))
	return b, nil
}

func ParseHello(b, key []byte, now time.Time) (Hello, error) {
	if len(b) >= helloV2FixedSize {
		nameLen := int(b[58])
		if len(b) == helloV2FixedSize+nameLen {
			macAt := len(b) - sha256.Size
			expected := sign(key, []byte("linkforge/hello/v2"), b[:macAt])
			if !hmac.Equal(expected, b[macAt:]) {
				return Hello{}, ErrAuth
			}
			var h Hello
			copy(h.ClientID[:], b[0:16])
			copy(h.InstanceNonce[:], b[16:32])
			copy(h.Nonce[:], b[32:48])
			h.Time = time.Unix(int64(binary.BigEndian.Uint64(b[48:56])), 0).UTC()
			h.Weight = binary.BigEndian.Uint16(b[56:58])
			h.PathName = string(b[59:macAt])
			h.WireVersion = 2
			if h.InstanceNonce == ([16]byte{}) || h.Weight == 0 {
				return Hello{}, ErrBadPacket
			}
			if delta := now.Sub(h.Time); delta > HandshakeSkew || delta < -HandshakeSkew {
				return Hello{}, ErrClockSkew
			}
			return h, nil
		}
	}
	if len(b) < helloV1FixedSize {
		return Hello{}, ErrBadPacket
	}
	nameLen := int(b[42])
	if len(b) != helloV1FixedSize+nameLen {
		return Hello{}, ErrBadPacket
	}
	macAt := len(b) - sha256.Size
	expected := sign(key, []byte("linkforge/hello/v1"), b[:macAt])
	if !hmac.Equal(expected, b[macAt:]) {
		return Hello{}, ErrAuth
	}
	var h Hello
	copy(h.ClientID[:], b[0:16])
	copy(h.Nonce[:], b[16:32])
	h.Time = time.Unix(int64(binary.BigEndian.Uint64(b[32:40])), 0).UTC()
	h.Weight = binary.BigEndian.Uint16(b[40:42])
	if h.Weight == 0 {
		return Hello{}, ErrBadPacket
	}
	h.PathName = string(b[43:macAt])
	h.WireVersion = 1
	if delta := now.Sub(h.Time); delta > HandshakeSkew || delta < -HandshakeSkew {
		return Hello{}, ErrClockSkew
	}
	return h, nil
}

type Welcome struct {
	ClientNonce [16]byte
	ServerNonce [16]byte
	Time        time.Time
}

func NewWelcome(clientNonce [16]byte) (Welcome, error) {
	w := Welcome{ClientNonce: clientNonce, Time: time.Now().UTC()}
	if _, err := rand.Read(w.ServerNonce[:]); err != nil {
		return Welcome{}, fmt.Errorf("create server nonce: %w", err)
	}
	return w, nil
}

func (w Welcome) Marshal(key []byte, header Header) []byte {
	b := make([]byte, welcomeSize)
	copy(b[0:16], w.ClientNonce[:])
	copy(b[16:32], w.ServerNonce[:])
	binary.BigEndian.PutUint64(b[32:40], uint64(w.Time.Unix()))
	authenticated := append(header.MarshalBinary(), b[:40]...)
	copy(b[40:], sign(key, []byte("linkforge/welcome/v1"), authenticated))
	return b
}

func ParseWelcome(b, key []byte, header Header, expectedNonce [16]byte, now time.Time) (Welcome, error) {
	if len(b) != welcomeSize {
		return Welcome{}, ErrBadPacket
	}
	authenticated := append(header.MarshalBinary(), b[:40]...)
	if !hmac.Equal(sign(key, []byte("linkforge/welcome/v1"), authenticated), b[40:]) {
		return Welcome{}, ErrAuth
	}
	var w Welcome
	copy(w.ClientNonce[:], b[0:16])
	copy(w.ServerNonce[:], b[16:32])
	w.Time = time.Unix(int64(binary.BigEndian.Uint64(b[32:40])), 0).UTC()
	if subtle.ConstantTimeCompare(w.ClientNonce[:], expectedNonce[:]) != 1 {
		return Welcome{}, ErrAuth
	}
	if delta := now.Sub(w.Time); delta > HandshakeSkew || delta < -HandshakeSkew {
		return Welcome{}, ErrClockSkew
	}
	return w, nil
}

func MarshalPlain(header Header, payload []byte) ([]byte, error) {
	if len(payload) > MaxPayload {
		return nil, ErrPayloadTooBig
	}
	return append(header.MarshalBinary(), payload...), nil
}

func PlainPayload(packet []byte) ([]byte, error) {
	if len(packet) < HeaderSize {
		return nil, ErrBadPacket
	}
	return packet[HeaderSize:], nil
}

func MarshalData(sequence uint64, ipPacket []byte) ([]byte, error) {
	if len(ipPacket) > MaxDataPayload {
		return nil, ErrPayloadTooBig
	}
	payload := make([]byte, 8+len(ipPacket))
	binary.BigEndian.PutUint64(payload[:8], sequence)
	copy(payload[8:], ipPacket)
	return payload, nil
}

func ParseData(payload []byte) (uint64, []byte, error) {
	if len(payload) < 9 {
		return 0, nil, ErrBadPacket
	}
	sequence := binary.BigEndian.Uint64(payload[:8])
	if sequence == 0 {
		return 0, nil, ErrBadPacket
	}
	return sequence, payload[8:], nil
}

func NewAEAD(psk []byte, clientNonce, serverNonce [16]byte, sessionID uint64, pathID uint32) (cipher.AEAD, error) {
	salt := make([]byte, 32)
	copy(salt[0:16], clientNonce[:])
	copy(salt[16:32], serverNonce[:])
	info := make([]byte, 8+4+24)
	copy(info, "linkforge/path-key/v1")
	binary.BigEndian.PutUint64(info[24:32], sessionID)
	binary.BigEndian.PutUint32(info[32:36], pathID)
	key := hkdfSHA256(psk, salt, info, 32)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func Seal(aead cipher.AEAD, header Header, direction Direction, plaintext []byte) ([]byte, error) {
	if len(plaintext) > MaxPayload {
		return nil, ErrPayloadTooBig
	}
	aad := header.MarshalBinary()
	nonce := packetNonce(header.PathID, header.Sequence, direction)
	return aead.Seal(aad, nonce, plaintext, aad), nil
}

func Open(aead cipher.AEAD, header Header, direction Direction, packet []byte) ([]byte, error) {
	if len(packet) < HeaderSize+TagSize {
		return nil, ErrBadPacket
	}
	nonce := packetNonce(header.PathID, header.Sequence, direction)
	plaintext, err := aead.Open(nil, nonce, packet[HeaderSize:], packet[:HeaderSize])
	if err != nil {
		return nil, ErrAuth
	}
	return plaintext, nil
}

func packetNonce(pathID uint32, sequence uint64, direction Direction) []byte {
	b := make([]byte, 12)
	if direction == ServerToClient {
		pathID |= 1 << 31
	} else {
		pathID &^= 1 << 31
	}
	binary.BigEndian.PutUint32(b[0:4], pathID)
	binary.BigEndian.PutUint64(b[4:12], sequence)
	return b
}

func sign(key []byte, parts ...[]byte) []byte {
	m := hmac.New(sha256.New, key)
	for _, part := range parts {
		_, _ = m.Write(part)
	}
	return m.Sum(nil)
}

// hkdfSHA256 implements RFC 5869 to avoid coupling the wire format to an
// external crypto package.
func hkdfSHA256(secret, salt, info []byte, length int) []byte {
	extract := hmac.New(sha256.New, salt)
	_, _ = extract.Write(secret)
	prk := extract.Sum(nil)

	var result, previous []byte
	for counter := byte(1); len(result) < length; counter++ {
		expand := hmac.New(sha256.New, prk)
		_, _ = expand.Write(previous)
		_, _ = expand.Write(info)
		_, _ = expand.Write([]byte{counter})
		previous = expand.Sum(nil)
		result = append(result, previous...)
	}
	return result[:length]
}

func ParseKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("empty key")
	}
	if b, err := base64.StdEncoding.DecodeString(value); err == nil && len(b) == 32 {
		return b, nil
	}
	if b, err := hex.DecodeString(value); err == nil && len(b) == 32 {
		return b, nil
	}
	return nil, errors.New("key must be 32 bytes encoded as base64 or 64 hexadecimal characters")
}

func GenerateKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func GenerateClientID() (string, error) {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return "", err
	}
	// Set UUID v4/variant bits while accepting the compact representation in config.
	id[6] = (id[6] & 0x0f) | 0x40
	id[8] = (id[8] & 0x3f) | 0x80
	return hex.EncodeToString(id[:]), nil
}

func ParseClientID(value string) ([16]byte, error) {
	var id [16]byte
	value = strings.ReplaceAll(strings.TrimSpace(value), "-", "")
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != len(id) {
		return id, errors.New("client_id must be a 16-byte UUID or 32 hexadecimal characters")
	}
	copy(id[:], b)
	return id, nil
}

func ClientIDString(id [16]byte) string {
	return hex.EncodeToString(id[:])
}

// ReplayWindow is a 64-packet sliding anti-replay window. It accepts normal
// UDP reordering while rejecting duplicate authenticated packets.
type ReplayWindow struct {
	mu      sync.Mutex
	highest uint64
	bitmap  uint64
	started bool
}

func (w *ReplayWindow) Accept(sequence uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.started {
		w.started = true
		w.highest = sequence
		w.bitmap = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= 64 {
			w.bitmap = 0
		} else {
			w.bitmap <<= shift
		}
		w.highest = sequence
		w.bitmap |= 1
		return true
	}
	delta := w.highest - sequence
	if delta >= 64 || w.bitmap&(uint64(1)<<delta) != 0 {
		return false
	}
	w.bitmap |= uint64(1) << delta
	return true
}
