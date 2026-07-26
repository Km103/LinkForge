package protocol

import (
	"bytes"
	"testing"
	"time"
)

func TestHandshakeAndEncryptedPacket(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	id, err := ParseClientID("67c42c03753048d285b2e7437299235d")
	if err != nil {
		t.Fatal(err)
	}
	hello, err := NewHello(id, "usb-tether", 3)
	if err != nil {
		t.Fatal(err)
	}
	helloPayload, err := hello.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	parsedHello, err := ParseHello(helloPayload, key, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if parsedHello.PathName != hello.PathName || parsedHello.ClientID != hello.ClientID {
		t.Fatalf("hello mismatch: %#v", parsedHello)
	}

	header := Header{Type: TypeWelcome, SessionID: 99, PathID: 3}
	welcome, err := NewWelcome(hello.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	welcomePayload := welcome.Marshal(key, header)
	parsedWelcome, err := ParseWelcome(welcomePayload, key, header, hello.Nonce, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	clientAEAD, err := NewAEAD(key, hello.Nonce, parsedWelcome.ServerNonce, 99, 3)
	if err != nil {
		t.Fatal(err)
	}
	serverAEAD, err := NewAEAD(key, hello.Nonce, welcome.ServerNonce, 99, 3)
	if err != nil {
		t.Fatal(err)
	}
	dataHeader := Header{Type: TypeData, SessionID: 99, PathID: 3, Sequence: 1}
	plaintext := []byte("an IP packet")
	packet, err := Seal(clientAEAD, dataHeader, ClientToServer, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(serverAEAD, dataHeader, ClientToServer, packet)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("got %q, want %q", got, plaintext)
	}
	if _, err := Open(serverAEAD, dataHeader, ServerToClient, packet); err == nil {
		t.Fatal("packet encrypted for the opposite direction was accepted")
	}
	packet[len(packet)-1] ^= 1
	if _, err := Open(serverAEAD, dataHeader, ClientToServer, packet); err == nil {
		t.Fatal("tampered ciphertext was accepted")
	}
}

func TestHelloRejectsTamperingAndClockSkew(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, 32)
	var id [16]byte
	hello, err := NewHello(id, "wifi", 1)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := hello.Marshal(key)
	if err != nil {
		t.Fatal(err)
	}
	payload[20] ^= 1
	if _, err := ParseHello(payload, key, time.Now()); err != ErrAuth {
		t.Fatalf("tamper error = %v, want %v", err, ErrAuth)
	}
	hello.Time = time.Now().Add(-HandshakeSkew - time.Second)
	payload, _ = hello.Marshal(key)
	if _, err := ParseHello(payload, key, time.Now()); err != ErrClockSkew {
		t.Fatalf("clock error = %v, want %v", err, ErrClockSkew)
	}
}

func TestReplayWindow(t *testing.T) {
	var window ReplayWindow
	for _, sequence := range []uint64{1, 3, 2, 70, 69} {
		if !window.Accept(sequence) {
			t.Fatalf("sequence %d unexpectedly rejected", sequence)
		}
	}
	for _, sequence := range []uint64{69, 3, 1} {
		if window.Accept(sequence) {
			t.Fatalf("sequence %d unexpectedly accepted", sequence)
		}
	}
}

func TestDataEnvelope(t *testing.T) {
	packet := []byte{0x45, 0, 0, 20}
	payload, err := MarshalData(44, packet)
	if err != nil {
		t.Fatal(err)
	}
	sequence, got, err := ParseData(payload)
	if err != nil {
		t.Fatal(err)
	}
	if sequence != 44 || !bytes.Equal(got, packet) {
		t.Fatalf("got sequence=%d packet=%x", sequence, got)
	}
}
