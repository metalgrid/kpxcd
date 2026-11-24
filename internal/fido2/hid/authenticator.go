//go:build linux

package hid

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/psanford/uhid"
)

// gateTimeout bounds one user-presence wait; keepaliveTick tells the host
// the authenticator is still processing while the gate is pending.
const (
	gateTimeout    = 180 * time.Second
	keepaliveTick  = 100 * time.Millisecond
	receiveTimeout = 500 * time.Millisecond
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

// Authenticator drives one device-wide transaction from reception through the
// final response write. The operation pointer is its generation identity.
type Authenticator struct {
	store CredentialStore
	gate  Gate
	log   *slog.Logger

	writer  reportWriter
	events  <-chan event
	dev     *uhid.Device // nil in tests
	closing sync.Once

	output      []outboundMessage // Bounded pending messages; one writer drains complete messages.
	writing     bool
	owner       *inflightOp
	stopped     bool
	receiveWait time.Duration
	mu          sync.Mutex
	channels    map[uint32]bool             // allocated channel IDs
	reassembly  map[uint32]*reassemblyState // cid → partial inbound message
	inflight    map[uint32]*inflightOp      // cid → running operation
	nextCID     uint32
	pending     *pendingAssertions
}

// inflightOp is a running CTAP command awaiting a gate or the store.
type inflightOp struct {
	cancel     context.CancelFunc
	ctx        context.Context
	cid        uint32
	command    byte
	timer      *time.Timer
	receipt    uint64
	responding bool
	done       chan struct{}

	// cancelRequested records that CTAPHID_CANCEL aborted this
	// operation; the aborted transaction must then reply
	// CTAP2_ERR_KEEPALIVE_CANCEL. Aborts by other means stay silent.
	cancelRequested bool
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
		store:       store,
		gate:        gate,
		log:         log,
		channels:    make(map[uint32]bool),
		reassembly:  make(map[uint32]*reassemblyState),
		inflight:    make(map[uint32]*inflightOp),
		nextCID:     1,
		receiveWait: receiveTimeout,
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
	if err := dev.SetUniq("kpxcd"); err != nil {
		return fmt.Errorf("hid: set uniq: %w", err)
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

	// Bridge kernel Output envelopes onto the internal report channel;
	// everything else is lifecycle noise.
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
					report, err := parseUHIDOutput(evt.Data)
					if err != nil {
						// No trustworthy report/CID exists; never answer from padding.
						a.log.Warn("hid: discarded kernel output", "err", err)
						continue
					}
					select {
					case internal <- event{isHostReport: true, report: report}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()
	a.events = internal

	go a.run(ctx)
	return nil
}

// parseUHIDOutput decodes the packed Linux uhid_output_req union member,
// not a CTAPHID packet. The pinned uhid library removes the four-byte event
// type but retains union padding. Match its little-endian ABI convention.
func parseUHIDOutput(data []byte) ([]byte, error) {
	const dataMax = 4096
	if len(data) < dataMax+3 {
		return nil, errors.New("hid: truncated UHID output envelope")
	}
	size := int(binary.LittleEndian.Uint16(data[dataMax : dataMax+2]))
	if size == 0 || size > dataMax {
		return nil, errors.New("hid: invalid UHID output size")
	}
	if data[dataMax+2] != 1 { // UHID_OUTPUT_REPORT, not FEATURE or INPUT.
		return nil, errors.New("hid: unexpected UHID report type")
	}
	report := data[:size]
	// The descriptor has no report IDs. Accept the optional hidraw zero ID
	// only at exactly 65 bytes; never trim other short/long actual reports.
	if size == reportSize+1 {
		if report[0] != 0 {
			return nil, errors.New("hid: unexpected UHID report ID")
		}
		report = report[1:]
	}
	return bytes.Clone(report), nil
}

// Close destroys the virtual device.
func (a *Authenticator) Close() {
	a.closing.Do(func() {
		a.cancelAll()
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

// cancelAll invalidates output before canceling work. Persistence already completed
// by a store cannot be rolled back by transport cancellation.
func (a *Authenticator) cancelAll() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.stopped = true
	a.pending = nil
	a.output = nil
	a.abortLocked()
}

func (a *Authenticator) abortLocked() {
	if a.owner != nil {
		a.owner.cancel()
		if a.owner.timer != nil {
			a.owner.timer.Stop()
		}
	}
	a.owner = nil
	clear(a.reassembly)
	clear(a.inflight)
}

func (a *Authenticator) beginLocked(ctx context.Context, cid uint32, command byte) *inflightOp {
	opCtx, cancel := context.WithCancel(ctx)
	op := &inflightOp{ctx: opCtx, cancel: cancel, cid: cid, command: command, done: make(chan struct{})}
	a.owner = op
	return op
}

// handleReport arbitrates before allocating any receive state.
func (a *Authenticator) handleReport(ctx context.Context, report []byte) {
	if len(report) < 4 {
		return // No CID can be addressed.
	}
	cid := uint32(report[0])<<24 | uint32(report[1])<<16 | uint32(report[2])<<8 | uint32(report[3])
	a.mu.Lock()
	if a.stopped {
		a.mu.Unlock()
		return
	}
	if len(report) != reportSize {
		op := a.owner
		if op != nil && op.cid == cid && a.reassembly[cid] != nil {
			a.pending = nil
			delete(a.reassembly, cid)
			if op.timer != nil {
				op.timer.Stop()
			}
			op.responding = true
			a.mu.Unlock()
			a.finish(op, cmdError, []byte{errInvalidLen})
		} else {
			a.mu.Unlock()
			a.sendError(cid, errInvalidLen)
		}
		return
	}
	initial := report[4]&typeInit != 0
	command := report[4] &^ typeInit
	length := int(report[5])<<8 | int(report[6])
	// Spurious continuations have no transaction and are ignored (§8.1.5.4).
	if !initial && a.reassembly[cid] == nil {
		a.mu.Unlock()
		return
	}
	if initial && command == cmdCancel {
		// CANCEL is never itself answered, including on an inactive CID.
		if length == 0 && a.owner != nil && a.owner.cid == cid &&
			a.owner.command == cmdCBOR && a.inflight[cid] == a.owner && !a.owner.responding {
			a.pending = nil
			a.owner.cancelRequested = true
			a.owner.cancel()
		}
		a.mu.Unlock()
		return
	}
	if cid == 0 || (cid == broadcastChannel && (!initial || command != cmdInit)) ||
		(cid != broadcastChannel && !a.channels[cid]) {
		a.mu.Unlock()
		a.sendError(cid, errInvalidChannel)
		return
	}
	if initial && command == cmdInit && length == 8 && (a.owner == nil || cid == a.owner.cid) {
		// Buffered replies and errors on this channel belong to its old session.
		kept := a.output[:0]
		for _, pending := range a.output {
			if pending.cid != cid {
				kept = append(kept, pending)
			}
		}
		clear(a.output[len(kept):])
		a.output = kept
	}
	if a.owner != nil {
		if initial && command == cmdInit && cid == a.owner.cid && length == 8 {
			a.abortLocked()
		} else if cid != a.owner.cid || initial {
			a.mu.Unlock()
			a.sendError(cid, errChanBusy)
			return
		}
	}
	if initial {
		if command != cmdCBOR || length == 0 || report[7] != cmdGetNextAssertion {
			a.pending = nil
		}
		code := byte(0)
		switch command {
		case cmdInit:
			if length != 8 {
				code = errInvalidLen
			}
		case cmdCBOR:
			if length == 0 {
				code = errInvalidLen
			}
		case cmdPing:
		default:
			code = errInvalidCmd
		}
		if length > maxTransportLen {
			code = errInvalidLen
		}
		if code != 0 {
			a.mu.Unlock()
			a.sendError(cid, code)
			return
		}
		a.beginLocked(ctx, cid, command)
	}
	op := a.owner
	msg, err := a.decodeReport(report)
	if err != nil {
		a.pending = nil
		delete(a.reassembly, cid)
		if op.timer != nil {
			op.timer.Stop()
		}
		op.responding = true
		a.mu.Unlock()
		a.finish(op, cmdError, []byte{errInvalidSeq})
		return
	}
	if msg == nil {
		// A fresh timer per received packet avoids a reset/callback race.
		if op.timer != nil {
			op.timer.Stop()
		}
		op.receipt++
		receipt := op.receipt
		wait := a.receiveWait
		op.timer = time.AfterFunc(wait, func() { a.expireReceive(op, receipt) })
		a.mu.Unlock()
		return
	}
	if op.timer != nil {
		op.timer.Stop()
	}
	a.mu.Unlock()
	a.dispatch(op, msg)
}

func (a *Authenticator) expireReceive(op *inflightOp, receipt uint64) {
	a.mu.Lock()
	if a.owner != op || op.receipt != receipt || a.reassembly[op.cid] == nil {
		a.mu.Unlock()
		return
	}
	a.pending = nil
	delete(a.reassembly, op.cid)
	op.responding = true
	a.mu.Unlock()
	a.finish(op, cmdError, []byte{errMsgTimeout})
}

// handleMessage is also used by command tests; wire traffic always arbitrates
// at the first packet in handleReport.
func (a *Authenticator) handleMessage(ctx context.Context, msg *hostMessage) {
	for _, report := range encodeInitReply(msg.channelID, msg.command, msg.payload) {
		a.handleReport(ctx, report)
	}
}

func (a *Authenticator) dispatch(op *inflightOp, msg *hostMessage) {
	switch msg.command {
	case cmdInit:
		a.mu.Lock()
		if a.owner != op {
			a.mu.Unlock()
			return
		}
		newCID := msg.channelID
		if newCID == broadcastChannel {
			if a.nextCID == 0 || a.nextCID == broadcastChannel {
				a.mu.Unlock()
				a.finish(op, cmdError, []byte{errOther})
				return
			}
			newCID = a.nextCID
			a.nextCID++
			a.channels[newCID] = true
		}
		a.mu.Unlock()
		a.finish(op, cmdInit, encodeInitResponse(msg.payload, newCID))
	case cmdPing:
		a.finish(op, cmdPing, msg.payload)
	case cmdCBOR:
		a.mu.Lock()
		if a.owner != op {
			a.mu.Unlock()
			return
		}
		a.inflight[op.cid] = op
		a.mu.Unlock()
		go func() {
			defer close(op.done)
			ctx := context.WithValue(op.ctx, operationKey{}, op)
			status, response := a.runCommand(ctx, msg.payload[0], msg.payload[1:], op.cid)
			a.mu.Lock()
			if a.owner != op {
				a.mu.Unlock()
				return
			}
			if op.cancelRequested {
				a.pending = nil
				status, response = statusKeepaliveCancel, nil
			} else if op.ctx.Err() != nil {
				a.pending = nil
				a.abortLocked()
				a.mu.Unlock()
				return
			}
			op.responding = true
			a.mu.Unlock()
			if status != statusOK {
				response = nil
			}
			a.finish(op, cmdCBOR, append([]byte{status}, response...))
		}()
	}
}

// finish queues the final response while retaining ownership. Only the writer
// releases it, after the final report succeeds or a write fails.
func (a *Authenticator) finish(op *inflightOp, command byte, payload []byte) {
	a.queueOutput(outboundMessage{op: op, cid: op.cid, command: command, payload: payload, final: true})
}

type operationKey struct{}

// outboundMessage is a single HID message. Owned messages are discarded when
// INIT changes the operation identity; errors address the rejected request.
type outboundMessage struct {
	op      *inflightOp
	cid     uint32
	command byte
	payload []byte
	final   bool
}

const maxPendingOutput = 16

func (a *Authenticator) queueOutput(message outboundMessage) {
	a.mu.Lock()
	if a.stopped || (message.op != nil && a.owner != message.op) {
		a.mu.Unlock()
		return
	}
	// Repeated INIT must not retain obsolete replies behind a blocked sink.
	kept := a.output[:0]
	for _, pending := range a.output {
		if pending.op == nil || pending.op == a.owner {
			kept = append(kept, pending)
		}
	}
	clear(a.output[len(kept):])
	a.output = kept
	for _, pending := range a.output {
		if message.command == cmdKeepalive && pending.command == cmdKeepalive && pending.op == message.op {
			a.mu.Unlock()
			return
		}
	}
	if len(a.output) == maxPendingOutput {
		// A stalled sink plus a flooding host is a failed transport, not an
		// excuse for an unbounded queue or concurrent writes.
		a.mu.Unlock()
		a.Close()
		return
	}
	a.output = append(a.output, message)
	if !a.writing {
		a.writing = true
		go a.writeOutput()
	}
	a.mu.Unlock()
}

func (a *Authenticator) writeOutput() {
	for {
		a.mu.Lock()
		if a.stopped || len(a.output) == 0 {
			a.output = nil
			a.writing = false
			a.mu.Unlock()
			return
		}
		message := a.output[0]
		a.output[0] = outboundMessage{}
		a.output = a.output[1:]
		a.mu.Unlock()
		failed := false
		for _, report := range encodeInitReply(message.cid, message.command, message.payload) {
			a.mu.Lock()
			valid := !a.stopped && (message.op == nil || a.owner == message.op)
			if message.command == cmdKeepalive {
				valid = valid && !message.op.responding && message.op.ctx.Err() == nil
			}
			a.mu.Unlock()
			if !valid {
				break
			}
			if err := a.writer.writeReport(report); err != nil {
				a.log.Warn("hid: failed writing report", "err", err)
				failed = true
				break
			}
		}
		a.mu.Lock()
		if message.op != nil && a.owner == message.op && (message.final || failed) {
			if failed {
				a.pending = nil
			}
			a.abortLocked()
		}
		a.mu.Unlock()
	}
}

// runCommand executes one CTAP2 command body. The cid is for keepalives.
func (a *Authenticator) runCommand(ctx context.Context, command byte, data []byte, cid uint32) (byte, []byte) {
	a.mu.Lock()
	if ctx.Err() != nil || a.stopped {
		a.mu.Unlock()
		return statusKeepaliveCancel, nil
	}
	if op, ok := ctx.Value(operationKey{}).(*inflightOp); ok && a.owner != op {
		a.mu.Unlock()
		return statusKeepaliveCancel, nil
	}
	if command != cmdGetNextAssertion || len(data)+1 > maxMessageLen {
		a.pending = nil
	}
	a.mu.Unlock()
	if len(data)+1 > maxMessageLen {
		return statusRequestTooLarge, nil
	}
	switch command {
	case cmdGetNextAssertion:
		return a.getNextAssertion(ctx, data, cid)
	case cmdGetInfo:
		if len(data) != 0 {
			return statusInvalidLength, nil
		}
		return a.getInfo()
	case cmdMakeCredential:
		return a.makeCredential(ctx, data, cid)
	case cmdGetAssertion:
		return a.getAssertion(ctx, data, cid)
	default:
		return statusInvalidCommand, nil
	}
}

// getInfo answers the static CTAP2 capability map. The algorithms field
// (CTAP 2.1) is present because Chrome refuses candidate devices without
// it; creation itself stays ES256 per D4.
func (a *Authenticator) getInfo() (byte, []byte) {
	encoded, err := ctapEncoder.Marshal(getInfoResponse{
		Versions:   []string{"FIDO_2_0"},
		Extensions: []string{},
		AAGUID:     []byte(productAAGUID),
		Options:    getInfoOptions{Rk: true, Up: true, UV: true},
		MaxMsgSize: maxMessageLen,
		Algorithms: getInfoAlgorithms,
	})
	if err != nil {
		return statusInvalidCBOR, nil
	}
	return statusOK, encoded
}
