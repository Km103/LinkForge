package tun

import (
	"bytes"
	"os"
	"testing"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

type recordingDevice struct {
	readPacket  []byte
	readOffset  int
	writePacket []byte
	writeOffset int
	events      chan wgtun.Event
}

func (d *recordingDevice) File() *os.File             { return nil }
func (d *recordingDevice) MTU() (int, error)          { return 1280, nil }
func (d *recordingDevice) Name() (string, error)      { return "test0", nil }
func (d *recordingDevice) Events() <-chan wgtun.Event { return d.events }
func (d *recordingDevice) Close() error               { return nil }
func (d *recordingDevice) BatchSize() int             { return 1 }
func (d *recordingDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	d.readOffset = offset
	sizes[0] = copy(bufs[0][offset:], d.readPacket)
	return 1, nil
}
func (d *recordingDevice) Write(bufs [][]byte, offset int) (int, error) {
	d.writeOffset = offset
	d.writePacket = append([]byte(nil), bufs[0][offset:]...)
	return 1, nil
}

func TestNativeUsesPlatformSafePacketOffset(t *testing.T) {
	packet := []byte{0x45, 0, 0, 20}
	device := &recordingDevice{readPacket: packet, events: make(chan wgtun.Event)}
	native := &Native{device: device, name: "test0", mtu: 1280}

	read, err := native.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if device.readOffset != packetOffset || !bytes.Equal(read, packet) {
		t.Fatalf("read offset=%d packet=%x", device.readOffset, read)
	}
	if err := native.WritePacket(packet); err != nil {
		t.Fatal(err)
	}
	if device.writeOffset != packetOffset || !bytes.Equal(device.writePacket, packet) {
		t.Fatalf("write offset=%d packet=%x", device.writeOffset, device.writePacket)
	}
}
