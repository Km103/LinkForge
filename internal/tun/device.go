// Package tun adapts WireGuard's actively maintained cross-platform TUN
// implementation. On Windows it uses Wintun; on Linux it uses /dev/net/tun.
package tun

import (
	"errors"
	"fmt"
	"io"
	"sync"

	wgtun "golang.zx2c4.com/wireguard/tun"
)

// packetOffset provides the headroom required by Linux virtio-net headers and
// the BSD address-family prefix. Sixteen bytes matches WireGuard's own caller.
const packetOffset = 16

type Device interface {
	ReadPacket() ([]byte, error)
	WritePacket([]byte) error
	Name() string
	Close() error
}

type Native struct {
	device  wgtun.Device
	name    string
	mtu     int
	readMu  sync.Mutex
	writeMu sync.Mutex
	pending [][]byte
}

func Open(name string, mtu int) (*Native, error) {
	device, err := wgtun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create TUN %q: %w", name, err)
	}
	actualName, err := device.Name()
	if err != nil {
		_ = device.Close()
		return nil, fmt.Errorf("read TUN name: %w", err)
	}
	return &Native{device: device, name: actualName, mtu: mtu}, nil
}

func (d *Native) Name() string { return d.name }

func (d *Native) ReadPacket() ([]byte, error) {
	d.readMu.Lock()
	defer d.readMu.Unlock()

	if len(d.pending) > 0 {
		packet := d.pending[0]
		d.pending = d.pending[1:]
		return packet, nil
	}

	batchSize := d.device.BatchSize()
	if batchSize < 1 {
		batchSize = 1
	}
	buffers := make([][]byte, batchSize)
	sizes := make([]int, batchSize)
	for i := range buffers {
		buffers[i] = make([]byte, d.mtu+packetOffset)
	}
	count, err := d.device.Read(buffers, sizes, packetOffset)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	if count < 1 {
		return nil, errors.New("TUN returned an empty batch")
	}
	for i := 0; i < count; i++ {
		if sizes[i] <= 0 || sizes[i] > len(buffers[i])-packetOffset {
			continue
		}
		packet := make([]byte, sizes[i])
		copy(packet, buffers[i][packetOffset:packetOffset+sizes[i]])
		d.pending = append(d.pending, packet)
	}
	if len(d.pending) == 0 {
		return nil, errors.New("TUN returned a malformed batch")
	}
	packet := d.pending[0]
	d.pending = d.pending[1:]
	return packet, nil
}

func (d *Native) WritePacket(packet []byte) error {
	d.writeMu.Lock()
	defer d.writeMu.Unlock()
	buffer := make([]byte, packetOffset+len(packet))
	copy(buffer[packetOffset:], packet)
	_, err := d.device.Write([][]byte{buffer}, packetOffset)
	return err
}

func (d *Native) Close() error {
	return d.device.Close()
}

// Memory is a deterministic in-memory TUN used by tests and embeddings.
type Memory struct {
	name     string
	outbound chan []byte
	inbound  chan []byte
	closed   chan struct{}
	once     sync.Once
}

func NewMemory(name string, capacity int) *Memory {
	return &Memory{
		name:     name,
		outbound: make(chan []byte, capacity),
		inbound:  make(chan []byte, capacity),
		closed:   make(chan struct{}),
	}
}

func (m *Memory) Name() string { return m.name }

func (m *Memory) ReadPacket() ([]byte, error) {
	select {
	case packet := <-m.outbound:
		return packet, nil
	case <-m.closed:
		return nil, io.EOF
	}
}

func (m *Memory) WritePacket(packet []byte) error {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case m.inbound <- copyOfPacket:
		return nil
	case <-m.closed:
		return io.EOF
	}
}

func (m *Memory) Close() error {
	m.once.Do(func() { close(m.closed) })
	return nil
}

func (m *Memory) Inject(packet []byte) error {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case m.outbound <- copyOfPacket:
		return nil
	case <-m.closed:
		return io.EOF
	}
}

func (m *Memory) Receive() <-chan []byte { return m.inbound }
