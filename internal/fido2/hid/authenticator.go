//go:build linux

package hid

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/psanford/uhid"
)

// gateTimeout bounds one user-presence wait; keepaliveTick tells the host
// the authenticator is still processing while the gate is pending.
const (
	gateTimeout   = 180 * time.Second
	keepaliveTick = 100 * time.Millisecond
)

// reportWriter is the device→host report sink. The uhid transport and the
// test fake both satisfy it.
type reportWriter interface {
	writeReport(report []byte) error
}

// event is one inbound kernel event: a host report (Output) or a signal.
type event struct {
	isHostReport bool
	report       []byte
}

// Authenticator drives the virtual CTAP2 device: one event loop, one
// in-flight operation per channel, keepalives while a gate is pending.
type Authenticator struct {
	store CredentialStore
	gate  Gate
	log   *slog.Logger

	writer  reportWriter
	events  <-chan event
	dev     *uhid.Device // nil in tests
	closing sync.Once

	mu         sync.Mutex
	channels   map[uint32]bool             // allocated channel IDs
	reassembly map[uint32]*reassemblyState // cid → partial inbound message
	inflight   map[uint32]*inflightOp      // cid → running operation
	nextCID    uint32
}

// inflightOp is a running CTAP command awaiting a gate or the store.
type inflightOp struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// NewAuthenticator builds an authenticator. A nil gate denies everything.
func NewAuthenticator(store CredentialStore, gate Gate, log *slog.Logger) *Authenticator {
	if gate == nil {
		gate = denyAllGate{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Authenticator{
		store:      store,
		gate:       gate,
		log:        log,
		channels:   make(map[uint32]bool),
		reassembly: make(map[uint32]*reassemblyState),
		inflight:   make(map[uint32]*inflightOp),
		nextCID:    1,
	}
}

// Start creates the virtual HID device and runs the event loop until ctx
// is canceled. Errors opening /dev/uhid are returned; callers disable the
// fido2 service when this fails (fail closed, no partial device).
func (a *Authenticator) Start(ctx context.Context) error {
	dev, err := uhid.NewDevice(DeviceName, reportDescriptor())
	if err != nil {
		return fmt.Errorf("hid: build device: %w", err)
	}
	dev.Data.Bus = BusUSB
	dev.Data.VendorID = VendorID
	dev.Data.ProductID = ProductID

	eventCh, err := dev.Open(ctx)
	if err != nil {
		return fmt.Errorf("hid: open /dev/uhid: %w", err)
	}
	a.dev = dev
	a.writer = uhidWriter{dev: dev}
	a.log.Info("hid: virtual FIDO device created", "vendor", fmt.Sprintf("%#04x", VendorID), "product", fmt.Sprintf("%#04x", ProductID))

	// Bridge kernel events onto the internal channel: Output carries the
	// 64-byte host report; everything else is lifecycle noise.
	internal := make(chan event)
	go func() {
		defer close(internal)
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-eventCh:
				if !ok {
					return
				}
				if evt.Err != nil {
					if errors.Is(evt.Err, context.Canceled) {
						return
					}
					a.log.Error("hid: kernel event error", "err", evt.Err)
					return
				}
				if evt.Type == uhid.Output {
					// Chromium prefixes hidraw writes with a 0x00 report-ID
					// byte for devices that declare no report IDs; strip it
					// before framing. Non-prefixed 64-byte hosts are untouched.
					data := evt.Data
					if len(data) > reportSize && data[0] == 0x00 {
						data = data[1:]
					}
					report := make([]byte, reportSize)
					copy(report, data)
					internal <- event{isHostReport: true, report: report}
				}
			}
		}
	}()
	a.events = internal

	go a.run(ctx)
	return nil
}

// Close destroys the virtual device.
func (a *Authenticator) Close() {
	a.closing.Do(func() {
		if a.dev != nil {
			_ = a.dev.Close()
		}
	})
}

// run processes host reports until ctx is canceled.
func (a *Authenticator) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			a.cancelAll()
			return
		case evt, ok := <-a.events:
			if !ok {
				a.cancelAll()
				return
			}
			if !evt.isHostReport {
				continue
			}
			a.handleReport(ctx, evt.report)
		}
	}
}

// cancelAll aborts every in-flight operation.
func (a *Authenticator) cancelAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for cid, op := range a.inflight {
		op.cancel()
		delete(a.inflight, cid)
	}
}

// handleReport reassembles one report and dispatches complete messages.
func (a *Authenticator) handleReport(ctx context.Context, report []byte) {
	msg, err := a.decodeReport(report)
	if err != nil {
		// Kernel drivers (hid-generic bind-time probes) and misbehaving
		// hosts both end up here; keep the bytes for diagnosis.
		a.log.Warn("hid: dropped malformed report",
			"err", err,
			"len", len(report),
			"head", fmt.Sprintf("% x", report[:min(len(report), 16)]))
		return
	}
	if msg == nil {
		return // reassembly in progress
	}
	a.handleMessage(ctx, msg)
}

// handleMessage routes one complete CTAPHID command.
func (a *Authenticator) handleMessage(ctx context.Context, msg *hostMessage) {
	a.mu.Lock()
	// A new command on a channel with an in-flight operation cancels that
	// operation first (the host protocol treats it as an abort).
	if op, busy := a.inflight[msg.channelID]; busy {
		op.cancel()
		delete(a.inflight, msg.channelID)
	}
	a.mu.Unlock()

	switch msg.command {
	case cmdInit:
		a.handleInit(msg)
	case cmdPing:
		a.send(msg.channelID, cmdPing, msg.payload)
	case cmdWink:
		// Not advertised in capabilities; ignore.
	case cmdCancel:
		// Already handled by the cancel above; nothing in flight now.
	case cmdCBOR:
		a.handleCBOR(ctx, msg)
	case cmdMsg:
		a.sendError(msg.channelID, errInvalidCmd)
	default:
		a.sendError(msg.channelID, errInvalidCmd)
	}
}

// handleInit allocates a channel (broadcast) or resynchronizes one.
func (a *Authenticator) handleInit(msg *hostMessage) {
	if len(msg.payload) != 8 {
		a.sendError(msg.channelID, errInvalidCmd)
		return
	}
	slog.Info("hid: CTAPHID handshake from host", "channel", fmt.Sprintf("%#08x", msg.channelID))
	newCID := msg.channelID
	if newCID == broadcastChannel {
		a.mu.Lock()
		newCID = a.nextCID
		a.nextCID++
		a.channels[newCID] = true
		a.mu.Unlock()
	}
	a.send(msg.channelID, cmdInit, encodeInitResponse(msg.payload, newCID))
}

// handleCBOR parses the CTAP2 command byte and runs the operation.
func (a *Authenticator) handleCBOR(ctx context.Context, msg *hostMessage) {
	if len(msg.payload) == 0 {
		a.sendCBORStatus(msg.channelID, statusMissingParam)
		return
	}
	command := msg.payload[0]
	data := msg.payload[1:]
	slog.Info(fmt.Sprintf("hid: CTAP2 command 0x%02x from channel %#08x", command, msg.channelID))

	// Run the operation on its own goroutine so the event loop keeps
	// reading (cancels, new commands) while the gate is pending.
	cid := msg.channelID
	opCtx, cancel := context.WithCancel(ctx)
	op := &inflightOp{cancel: cancel, done: make(chan struct{})}
	a.mu.Lock()
	a.inflight[cid] = op
	a.mu.Unlock()

	go func() {
		defer close(op.done)
		status, response := a.runCommand(opCtx, command, data, cid)
		select {
		case <-opCtx.Done():
			return // canceled; the host moved on
		default:
		}
		a.mu.Lock()
		if a.inflight[cid] == op {
			delete(a.inflight, cid)
		}
		a.mu.Unlock()

		if status == statusOK && response != nil {
			a.send(cid, cmdCBOR, append([]byte{statusOK}, response...))
			return
		}
		a.sendCBORStatus(cid, status)
	}()
}

// runCommand executes one CTAP2 command body. The cid is for keepalives.
func (a *Authenticator) runCommand(ctx context.Context, command byte, data []byte, cid uint32) (byte, []byte) {
	switch command {
	case cmdGetInfo:
		return a.getInfo()
	case cmdMakeCredential:
		return a.makeCredential(ctx, data, cid)
	case cmdGetAssertion:
		return a.getAssertion(ctx, data, cid)
	default:
		return statusUnsupportedCommand, nil
	}
}

// getInfo answers the static CTAP2.0 capability map.
func (a *Authenticator) getInfo() (byte, []byte) {
	encoded, err := cbor.Marshal(getInfoResponse{
		Versions:   []string{"FIDO_2_0"},
		Extensions: []string{},
		AAGUID:     aaguid[:],
		Options:    map[string]bool{"rk": true, "up": true, "clientPin": false},
		MaxMsgSize: maxMessageLen,
	})
	if err != nil {
		return statusInvalidCBOR, nil
	}
	return statusOK, encoded
}
