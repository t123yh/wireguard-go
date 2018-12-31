/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2017-2018 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type QueueHandshakeElement struct {
	msgType  uint32
	packet   []byte
	endpoint Endpoint
	buffer   *[MaxMessageSize]byte
}

type QueueInboundElement struct {
	dropped          int32
	mutex            sync.Mutex
	buffer           *[MaxMessageSize]byte
	decryptedContent []byte
	counter          uint64
	keypair          *Keypair
	endpoint         Endpoint
}

func (elem *QueueInboundElement) Drop() {
	atomic.StoreInt32(&elem.dropped, AtomicTrue)
}

func (elem *QueueInboundElement) IsDropped() bool {
	return atomic.LoadInt32(&elem.dropped) == AtomicTrue
}

func (device *Device) addToInboundAndDecryptionQueues(inboundQueue chan *QueueInboundElement, decryptionQueue chan *QueueInboundElement, element *QueueInboundElement) bool {
	select {
	case inboundQueue <- element:
		select {
		case decryptionQueue <- element:
			return true
		default:
			fmt.Println("RecvInbound: Dropping packet because queue is full")
			element.Drop()
			element.mutex.Unlock()
			return false
		}
	default:
		fmt.Println("RecvInbound: Dropping packet because queue is full")
		device.PutInboundElement(element)
		return false
	}
}

func (device *Device) addToSequentialQueue(inboundQueue chan *QueueInboundElement, element *QueueInboundElement) bool {
	select {
	case inboundQueue <- element:
		return true
	default:
		fmt.Println("RecvSeq: Dropping packet because queue is full")
		element.Drop()
		return false
	}
}

func (device *Device) addToHandshakeQueue(queue chan QueueHandshakeElement, element QueueHandshakeElement) bool {
	select {
	case queue <- element:
		return true
	default:
		return false
	}
}

/* Called when a new authenticated message has been received
 *
 * NOTE: Not thread safe, but called by sequential receiver!
 */
func (peer *Peer) keepKeyFreshReceiving() {
	if peer.timers.sentLastMinuteHandshake.Get() {
		return
	}
	keypair := peer.keypairs.Current()
	if keypair != nil && keypair.isInitiator && time.Now().Sub(keypair.created) > (RejectAfterTime-KeepaliveTimeout-RekeyTimeout) {
		peer.timers.sentLastMinuteHandshake.Set(true)
		peer.SendHandshakeInitiation(false)
	}
}

/* Receives incoming datagrams for the device
 *
 * Every time the bind is updated a new routine is started for
 * IPv4 and IPv6 (separately)
 */
func (device *Device) RoutineReceiveIncoming(IP int, bind Bind) {

	logDebug := device.log.Debug
	defer func() {
		logDebug.Println("Routine: receive incoming IPv" + strconv.Itoa(IP) + " - stopped")
		device.net.stopping.Done()
	}()

	logDebug.Println("Routine: receive incoming IPv" + strconv.Itoa(IP) + " - started")
	device.net.starting.Done()

	// receive datagrams until conn is closed

	buffer := device.GetMessageBuffer()

	var (
		err      error
		size     int
		endpoint Endpoint
	)

	for {

		// read next datagram

		switch IP {
		case ipv4.Version:
			size, endpoint, err = bind.ReceiveIPv4(buffer[:])
		case ipv6.Version:
			size, endpoint, err = bind.ReceiveIPv6(buffer[:])
		default:
			panic("invalid IP version")
		}

		if err != nil {
			device.PutMessageBuffer(buffer)
			return
		}

		if size < MinMessageSize {
			continue
		}

		// check size of packet

		packet := buffer[:size]
		msgType := binary.LittleEndian.Uint32(packet[:4])

		var okay bool

		switch msgType {

		// check if transport

		case MessageTransportType:

			// check size

			if len(packet) < MessageTransportSize {
				continue
			}

			// lookup key pair

			receiver := binary.LittleEndian.Uint32(
				packet[MessageTransportOffsetReceiver:MessageTransportOffsetCounter],
			)
			value := device.indexTable.Lookup(receiver)
			keypair := value.keypair
			if keypair == nil {
				continue
			}

			// check keypair expiry

			if keypair.created.Add(RejectAfterTime).Before(time.Now()) {
				continue
			}

			// create work element
			peer := value.peer
			atomic.AddUint64(&peer.stats.rxPackets, 1)
			elem := device.GetInboundElement()
			elem.decryptedContent = packet
			elem.buffer = buffer
			elem.keypair = keypair
			elem.dropped = AtomicFalse
			elem.endpoint = endpoint
			elem.counter = 0
			elem.mutex = sync.Mutex{}
			elem.mutex.Lock()

			// add to decryption queues

			if peer.isRunning.Get() {
				if device.addToInboundAndDecryptionQueues(peer.queue.inboundFEC, device.queue.decryption, elem) {
					buffer = device.GetMessageBuffer()
				}
			}

			continue

		// otherwise it is a fixed size & handshake related packet

		case MessageInitiationType:
			okay = len(packet) == MessageInitiationSize

		case MessageResponseType:
			okay = len(packet) == MessageResponseSize

		case MessageCookieReplyType:
			okay = len(packet) == MessageCookieReplySize

		default:
			logDebug.Println("Received message with unknown type")
		}

		if okay {
			if (device.addToHandshakeQueue(
				device.queue.handshake,
				QueueHandshakeElement{
					msgType:  msgType,
					buffer:   buffer,
					packet:   packet,
					endpoint: endpoint,
				},
			)) {
				buffer = device.GetMessageBuffer()
			}
		}
	}
}

func (device *Device) RoutineDecryption() {

	var nonce [chacha20poly1305.NonceSize]byte

	logDebug := device.log.Debug
	defer func() {
		logDebug.Println("Routine: decryption worker - stopped")
		device.state.stopping.Done()
	}()
	logDebug.Println("Routine: decryption worker - started")
	device.state.starting.Done()

	for {
		select {
		case <-device.signals.stop:
			return

		case elem, ok := <-device.queue.decryption:

			if !ok {
				return
			}

			// check if dropped

			if elem.IsDropped() {
				continue
			}

			// split message into fields

			counter := elem.decryptedContent[MessageTransportOffsetCounter:MessageTransportOffsetContent]
			content := elem.decryptedContent[MessageTransportOffsetContent:]

			// expand nonce

			nonce[0x4] = counter[0x0]
			nonce[0x5] = counter[0x1]
			nonce[0x6] = counter[0x2]
			nonce[0x7] = counter[0x3]

			nonce[0x8] = counter[0x4]
			nonce[0x9] = counter[0x5]
			nonce[0xa] = counter[0x6]
			nonce[0xb] = counter[0x7]

			// decrypt and release to consumer

			var err error
			elem.counter = binary.LittleEndian.Uint64(counter)
			elem.decryptedContent, err = elem.keypair.receive.Open(
				content[:0],
				nonce[:],
				content,
				nil,
			)
			if err != nil {
				elem.Drop()
				device.PutMessageBuffer(elem.buffer)
			} else {
				logDebug.Printf("Opened length: %d", len(elem.decryptedContent))
			}
			elem.mutex.Unlock()
		}
	}
}

/* Handles incoming packets related to handshake
 */
func (device *Device) RoutineHandshake() {

	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug

	var elem QueueHandshakeElement
	var ok bool

	defer func() {
		logDebug.Println("Routine: handshake worker - stopped")
		device.state.stopping.Done()
		if elem.buffer != nil {
			device.PutMessageBuffer(elem.buffer)
		}
	}()

	logDebug.Println("Routine: handshake worker - started")
	device.state.starting.Done()

	for {
		if elem.buffer != nil {
			device.PutMessageBuffer(elem.buffer)
			elem.buffer = nil
		}

		select {
		case elem, ok = <-device.queue.handshake:
		case <-device.signals.stop:
			return
		}

		if !ok {
			return
		}

		// handle cookie fields and ratelimiting

		switch elem.msgType {

		case MessageCookieReplyType:

			// unmarshal packet

			var reply MessageCookieReply
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &reply)
			if err != nil {
				logDebug.Println("Failed to decode cookie reply")
				return
			}

			// lookup peer from index

			entry := device.indexTable.Lookup(reply.Receiver)

			if entry.peer == nil {
				continue
			}

			// consume reply

			if peer := entry.peer; peer.isRunning.Get() {
				logDebug.Println("Receiving cookie response from ", elem.endpoint.DstToString())
				if !peer.cookieGenerator.ConsumeReply(&reply) {
					logDebug.Println("Could not decrypt invalid cookie response")
				}
			}

			continue

		case MessageInitiationType, MessageResponseType:

			// check mac fields and maybe ratelimit

			if !device.cookieChecker.CheckMAC1(elem.packet) {
				logDebug.Println("Received packet with invalid mac1")
				continue
			}

			// endpoints destination address is the source of the datagram

			if device.IsUnderLoad() {

				// verify MAC2 field

				if !device.cookieChecker.CheckMAC2(elem.packet, elem.endpoint.DstToBytes()) {
					device.SendHandshakeCookie(&elem)
					continue
				}

				// check ratelimiter

				if !device.rate.limiter.Allow(elem.endpoint.DstIP()) {
					continue
				}
			}

		default:
			logError.Println("Invalid packet ended up in the handshake queue")
			continue
		}

		// handle handshake initiation/response content

		switch elem.msgType {
		case MessageInitiationType:

			// unmarshal

			var msg MessageInitiation
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				logError.Println("Failed to decode initiation message")
				continue
			}

			// consume initiation

			peer := device.ConsumeMessageInitiation(&msg)
			if peer == nil {
				logInfo.Println(
					"Received invalid initiation message from",
					elem.endpoint.DstToString(),
				)
				continue
			}

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			logDebug.Println(peer, "- Received handshake initiation")

			peer.SendHandshakeResponse()

		case MessageResponseType:

			// unmarshal

			var msg MessageResponse
			reader := bytes.NewReader(elem.packet)
			err := binary.Read(reader, binary.LittleEndian, &msg)
			if err != nil {
				logError.Println("Failed to decode response message")
				continue
			}

			// consume response

			peer := device.ConsumeMessageResponse(&msg)
			if peer == nil {
				logInfo.Println(
					"Received invalid response message from",
					elem.endpoint.DstToString(),
				)
				continue
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			logDebug.Println(peer, "- Received handshake response")

			// update timers

			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// derive keypair

			err = peer.BeginSymmetricSession()

			if err != nil {
				logError.Println(peer, "- Failed to derive keypair:", err)
				continue
			}

			peer.timersSessionDerived()
			peer.timersHandshakeComplete()
			peer.SendKeepalive()
			select {
			case peer.signals.newKeypairArrived <- struct{}{}:
			default:
			}
		}
	}
}

func (peer *Peer) RoutineSequentialReceiver() {

	device := peer.device
	logInfo := device.log.Info
	logError := device.log.Error
	logDebug := device.log.Debug

	var elem *QueueInboundElement
	var ok bool

	defer func() {
		logDebug.Println(peer, "- Routine: sequential receiver - stopped")
		peer.routines.stopping.Done()
		if elem != nil {
			if !elem.IsDropped() {
				device.PutMessageBuffer(elem.buffer)
			}
			device.PutInboundElement(elem)
		}
	}()

	logDebug.Println(peer, "- Routine: sequential receiver - started")

	peer.routines.starting.Done()

	for {
		if elem != nil {
			if !elem.IsDropped() {
				device.PutMessageBuffer(elem.buffer)
			}
			device.PutInboundElement(elem)
			elem = nil
		}

		select {

		case <-peer.routines.stop:
			return

		case elem, ok = <-peer.queue.inbound:

			if !ok {
				return
			}

			if elem.IsDropped() {
				continue
			}

			packet := elem.decryptedContent[MessageMetadataSize:]

			// verify source and strip padding

			switch packet[0] >> 4 {
			case ipv4.Version:

				// strip padding

				if len(packet) < ipv4.HeaderLen {
					continue
				}

				field := packet[IPv4offsetTotalLength : IPv4offsetTotalLength+2]
				length := binary.BigEndian.Uint16(field)
				if int(length) > len(packet) || int(length) < ipv4.HeaderLen {
					continue
				}

				packet = packet[:length]

				// verify IPv4 source

				src := packet[IPv4offsetSrc : IPv4offsetSrc+net.IPv4len]
				if device.allowedips.LookupIPv4(src) != peer {
					logInfo.Println(
						"IPv4 packet with disallowed source address from",
						peer,
					)
					continue
				}

			case ipv6.Version:

				// strip padding

				if len(packet) < ipv6.HeaderLen {
					continue
				}

				field := packet[IPv6offsetPayloadLength : IPv6offsetPayloadLength+2]
				length := binary.BigEndian.Uint16(field)
				length += ipv6.HeaderLen
				if int(length) > len(packet) {
					continue
				}

				packet = packet[:length]

				// verify IPv6 source

				src := packet[IPv6offsetSrc : IPv6offsetSrc+net.IPv6len]
				if device.allowedips.LookupIPv6(src) != peer {
					logInfo.Println(
						peer,
						"sent packet with disallowed IPv6 source",
					)
					continue
				}

			default:
				logInfo.Println("Packet with invalid IP version from", peer)
				continue
			}

			// write to tun device

			offset := MessageTransportOffsetContent + MessageMetadataSize
			atomic.AddUint64(&peer.stats.rxBytes, uint64(len(packet)))
			atomic.AddUint64(&peer.stats.rxDelivered, 1)
			_, err := device.tun.device.Write(elem.buffer[:offset+len(packet)], offset)
			if err != nil {
				logError.Println("Failed to write packet to TUN device:", err)
			}
		}
	}
}

func (peer *Peer) RoutineInboundFEC() {

	device := peer.device
	logDebug := device.log.Debug
	logInfo := device.log.Info

	var elem *QueueInboundElement
	var ok bool

	defer func() {
		logDebug.Println(peer, "- Routine: inbound FEC - stopped")
		peer.routines.stopping.Done()
		if elem != nil {
			if !elem.IsDropped() {
				device.PutMessageBuffer(elem.buffer)
			}
			device.PutInboundElement(elem)
		}
	}()

	logDebug.Println(peer, "- Routine: inbound FEC - started")

	peer.routines.starting.Done()

	for {
		if elem != nil {
			if !elem.IsDropped() {
				device.PutMessageBuffer(elem.buffer)
			}
			device.PutInboundElement(elem)
			elem = nil
		}

		select {

		case <-peer.routines.stop:
			return

		case elem, ok = <-peer.queue.inboundFEC:

			if !ok {
				return
			}

			// wait for decryption

			elem.mutex.Lock()

			if elem.IsDropped() {
				logDebug.Println("FEC inbound: dropped: ", elem.counter)
				continue
			}

			// check for replay

			if !elem.keypair.replayFilter.ValidateCounter(elem.counter, RejectAfterMessages) {
				continue
			}

			// update endpoint
			peer.SetEndpointFromPacket(elem.endpoint)

			// check if using new keypair
			if peer.ReceivedWithKeypair(elem.keypair) {
				peer.timersHandshakeComplete()
				select {
				case peer.signals.newKeypairArrived <- struct{}{}:
				default:
				}
			}

			peer.keepKeyFreshReceiving()
			peer.timersAnyAuthenticatedPacketTraversal()
			peer.timersAnyAuthenticatedPacketReceived()

			// check for keepalive

			if len(elem.decryptedContent) == 0 {
				logDebug.Println(peer, "- Receiving keepalive packet")
				continue
			}
			peer.timersDataReceived()

			// do fec processing job

			// TODO: make sure packetPos is not out of bound
			packetPos := elem.decryptedContent[0]

			logDebug.Println("FEC inbound: processing: ", elem.counter, ", packetPos = ", packetPos)

			packetGroupId := binary.LittleEndian.Uint16(elem.decryptedContent[1:3])
			actualData := elem.decryptedContent[MessageMetadataSize:]
			// bufferId := packetGroupId % ReceiveFECWindowSize
			currentBuffer := &peer.recvBuffers[packetGroupId%ReceiveFECWindowSize]

			logDebug.Printf("currentBuffer.groupId is %d, packetGroupId is %d", currentBuffer.groupId, packetGroupId)
			// Make sure the current group is the group we want
			// (we might be receiving N - 16 or N + 16)
			if currentBuffer.groupId != packetGroupId {
				logDebug.Printf("elem.counter is %d, minimumCounter is %d", elem.counter, currentBuffer.minimumCounter)
				if elem.counter > currentBuffer.minimumCounter {
					x1 := 0
					for i := 0; i < peer.recvDataShards; i++ {
						if !currentBuffer.delivered[i] {
							x1++
						}
					}
					if x1 > 0 {
						x2 := 0
						for i := 0; i < peer.recvDataShards+peer.recvParityShards; i++ {
							if len(currentBuffer.buffers[i]) == 0 {
								x2++
							}
						}
						logInfo.Printf("%d undelivered (total unreceived = %d), groupId = %d", x1, x2, currentBuffer.groupId)
					}
					// the packet is newer
					currentBuffer.reset()
					logDebug.Printf("Resetting buffer")
				} else {
					// the packet is older (maybe Group N-16), just ignore the packet
					if packetPos < uint8(peer.recvDataShards) {
						logDebug.Println("FEC inbound: add to sequential queue (old): ", elem.counter)
						device.addToSequentialQueue(peer.queue.inbound, elem)
						elem = nil
					} else {
						elem.Drop()
					}
					continue
				}
				currentBuffer.groupId = packetGroupId
			}

			if currentBuffer.recovered {
				logDebug.Println("Skipping already recovered packet")
				// the packet group has already been fec'ed
				elem.Drop()
				continue
			}

			currentBuffer.buffers[packetPos] = currentBuffer.buffers[packetPos][:len(actualData)]
			// TODO: Detect if the buffer here is really unused.
			copy(currentBuffer.buffers[packetPos], actualData)

			if currentBuffer.minimumCounter == 0 {
				currentBuffer.minimumCounter = elem.counter
			} else {
				currentBuffer.minimumCounter = min64(elem.counter, currentBuffer.minimumCounter)
			}

			if packetPos < uint8(peer.recvDataShards) {
				// is a data shard
				currentBuffer.delivered[packetPos] = true
				logDebug.Println("FEC inbound: add to sequential queue: ", elem.counter)
				device.addToSequentialQueue(peer.queue.inbound, elem)
				elem = nil
			} else {
				// is a parity shard, shouldn't be processed later
				elem.Drop()
			}

			deliveredCount := 0
			receivedCount := 0
			for i := 0; i < peer.recvDataShards; i++ {
				if currentBuffer.delivered[i] {
					deliveredCount++
				}
			}

			for i := 0; i < len(currentBuffer.buffers); i++ {
				if len(currentBuffer.buffers[i]) != 0 {
					receivedCount++
				}
			}

			if deliveredCount != peer.recvDataShards && receivedCount >= peer.recvDataShards {
				// Time to do FEC
				blockSize := 0
				for i := peer.recvDataShards; i < peer.recvDataShards+peer.recvParityShards; i++ {
					if len(currentBuffer.buffers[i]) != 0 {
						blockSize = len(currentBuffer.buffers[i])
					}
				}

				var err error
				x := 0
				if blockSize == 0 {
					goto fail
				}

				for i := 0; i < len(currentBuffer.buffers); i++ {
					if len(currentBuffer.buffers[i]) != 0 {
						logDebug.Printf("ReceivedCount = %d, delivered = %d, Correct [%d] First byte is %d", receivedCount, deliveredCount, i, currentBuffer.buffers[i][0])
						originalLen := len(currentBuffer.buffers[i])
						if originalLen != blockSize {
							currentBuffer.buffers[i] = currentBuffer.buffers[i][:blockSize]
							for j := originalLen; j < blockSize; j++ {
								currentBuffer.buffers[i][j] = 0
							}
						}
					}
				}

				err = peer.recvEncoder.ReconstructData(currentBuffer.buffers)
				if err != nil {
					logInfo.Println("Recover fail", err)
					goto fail
				}

				for i := 0; i < peer.recvDataShards; i++ {
					if !currentBuffer.delivered[i] {
						x++

						recoveredElem := device.GetInboundElement()
						recoveredElem.buffer = device.GetMessageBuffer()
						recoveredElem.decryptedContent = recoveredElem.buffer[MessageTransportOffsetContent:]
						binary.LittleEndian.PutUint16(recoveredElem.decryptedContent[1:3], packetGroupId)
						recoveredElem.decryptedContent[0] = uint8(i)
						copy(recoveredElem.decryptedContent[MessageMetadataSize:], currentBuffer.buffers[i])
						recoveredElem.dropped = AtomicFalse
						if !device.addToSequentialQueue(peer.queue.inbound, recoveredElem) {
							device.PutMessageBuffer(recoveredElem.buffer)
							device.PutInboundElement(recoveredElem)
						}
					}
					currentBuffer.delivered[i] = true
				}
				// logInfo.Printf("Recovered %d lost packet", x)

				currentBuffer.recovered = true
			fail:
			}

			continue
		}
	}
}
