/*
  Copyright (c) 2019 Star Brilliant

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang/groupcache/lru"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type rule struct {
	Src, Dst net.IPNet
	MTU      uint
	Trigger  uint
}

func (r *rule) Match(src, dst net.IP) bool {
	return r.Src.Contains(src) && r.Dst.Contains(dst)
}

type mtuUpperBound struct {
	MTUValid     bool
	TriggerValid bool
	MTU          uint
	Trigger      uint
}

func (m *mtuUpperBound) MTUUpperbound(src, dst net.IP, r *rule) {
	if r.Src.Contains(src) && r.Dst.Contains(dst) {
		if !m.MTUValid {
			m.MTUValid = true
			m.MTU = r.MTU
		} else if r.MTU < m.MTU {
			m.MTU = r.MTU
		}
		if !m.TriggerValid {
			m.TriggerValid = true
			m.Trigger = r.Trigger
		} else if r.Trigger < m.Trigger {
			m.Trigger = r.Trigger
		}
	}
}

func cacheContains(cache *lru.Cache, cacheSeconds uint, key lru.Key) bool {
	value, ok := cache.Get(key)
	if !ok {
		return false
	}
	if time.Now().Sub(value.(time.Time)) < time.Duration(cacheSeconds)*time.Second {
		return true
	}
	cache.Remove(key)
	return false
}

func generateReplyLinkLayer(iface string, rawPacket []byte, linkType layers.LinkType) []byte {
	switch linkType {
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		buf := make([]byte, 4)
		copy(buf, rawPacket)
		return buf
	case layers.LinkTypeEthernet:
		buf := make([]byte, 14)
		copy(buf, rawPacket)
		buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11] = buf[6], buf[7], buf[8], buf[9], buf[10], buf[11], buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]
		return buf
	case layers.LinkTypeRaw, layers.LinkTypeIPv4, layers.LinkTypeIPv6:
		return nil
	case layers.LinkTypeLinuxSLL:
		linkLayerAddressLength := uint16(0)
		if len(rawPacket) >= 4 {
			linkLayerAddressLength = binary.BigEndian.Uint16(rawPacket[2:4])
		}
		buf := make([]byte, 14)
		buf[1] = 4
		if len(rawPacket) >= 4+(int(linkLayerAddressLength)|0x7)+3 {
			buf[12], buf[13] = rawPacket[12], rawPacket[13]
		} else {
			buf[12] = 0x08
		}
		return buf
	default:
		panic(fmt.Sprintf("Unsupported link layer protocol on device %s: %s", iface, linkType))
	}
}

func main() {
	if len(os.Args) != 2 {
		printUsage(os.Args[0])
		os.Exit(0)
	}

	cacheItems, cacheSeconds := uint(1024), uint(10)
	ifaces := make([]string, 0)
	bpf := new(string)
	rules := make([]*rule, 0)

	configFile, err := os.Open(os.Args[1])
	if err != nil {
		log.Fatalf("failed to open configuration file: %s\n", err)
	}
	defer configFile.Close()
	configFileReader := bufio.NewReader(configFile)
	for lineno := 1; ; lineno++ {
		if line, err := configFileReader.ReadString('\n'); err != io.EOF {
			if err != nil {
				log.Fatalf("failed to read configuration file: %s\n", err)
			}
			line = strings.SplitN(line, "#", 2)[0]
			fields := strings.Fields(line)
			if len(fields) == 0 {
				continue
			}
			switch fields[0] {
			case "iface":
				if len(fields) != 2 {
					log.Fatalf("syntax error in line %d: %d arguments required\n", lineno, 2)
				}
				ifaces = append(ifaces, fields[1])
			case "filter":
				bpf = new(string)
				*bpf = strings.Join(fields[1:], " ")
			case "cache":
				if len(fields) != 3 {
					log.Fatalf("syntax error in line %d: %d, arguments required\n", lineno, 3)
				}
				cacheItems, err = parseUintNative(fields[1], 0, strconv.IntSize-1)
				if err != nil || cacheItems == 0 {
					log.Fatalf("syntax error in line %d: invalid cache items: %s\n", lineno, fields[1])
				}
				cacheSeconds, err = parseUintNative(fields[2], 0, 0)
				if err != nil || cacheSeconds == 0 {
					log.Fatalf("syntax error in line %d: invalid cache seconds: %s\n", lineno, fields[1])
				}
			default:
				if len(fields) != 3 && len(fields) != 4 {
					log.Fatalf("syntax error in line %d: 3 or 4 arguments required\n", lineno)
				}
				_, src, err := net.ParseCIDR(fields[0])
				if err != nil {
					log.Fatalf("syntax error in line %d: invalid source CIDR: %s\n", lineno, fields[0])
				}
				_, dest, err := net.ParseCIDR(fields[1])
				if err != nil {
					log.Fatalf("syntax error in line %d: invalid destination CIDR: %s\n", lineno, fields[1])
				}
				mtu, err := parseUintNative(fields[2], 0, 0)
				if err != nil || mtu == 0 {
					log.Fatalf("syntax error in line %d: invalid MTU: %s\n", lineno, fields[2])
				}
				trigger := mtu
				if len(fields) >= 4 {
					trigger, err = parseUintNative(fields[3], 0, 0)
					if err != nil {
						log.Fatalf("syntax error in line %d: invalid trigger size: %s\n", lineno, fields[3])
					}
				}
				rules = append(rules, &rule{
					Src:     *src,
					Dst:     *dest,
					MTU:     mtu,
					Trigger: trigger,
				})
			}
		} else {
			break
		}
	}
	if len(ifaces) == 0 {
		ifaces = []string{"any"}
	}

	quitChan := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(len(ifaces))
	for _, iface := range ifaces {
		go sniff(&wg, quitChan, iface, cacheItems, cacheSeconds, bpf, rules)
	}
	wg.Wait()
	<-quitChan
}

func parseUintNative(s string, base int, bitSize int) (uint, error) {
	if bitSize == 0 || bitSize > strconv.IntSize {
		bitSize = strconv.IntSize
	}
	res, err := strconv.ParseUint(s, base, bitSize)
	return uint(res), err
}

func printUsage(programName string) {
	fmt.Printf("Usage: %s config_file", programName)
	fmt.Println()
	fmt.Println("Configuration file format:")
	fmt.Println("    iface  <INTERFACE NAME>")
	fmt.Println("    filter <PCAP FILTER>")
	fmt.Println("    cache  <CACHE ITEMS> <CACHE SECONDS>")
	fmt.Println("    <SRC CIDR 1> <DST CIDR 1> <MTU 1> [ <TRIGGER LENGTH 1> ]")
	fmt.Println("    <SRC CIDR 2> <DST CIDR 2> <MTU 2> [ <TRIGGER LENGTH 2> ]")
	fmt.Println("    ...")
	fmt.Println()
}

func sniff(wg *sync.WaitGroup, quitChan chan<- struct{}, iface string, cacheItems uint, cacheSeconds uint, bpf *string, rules []*rule) {
	defer close(quitChan)

	pmtudCache := lru.New(int(cacheItems))

	inactiveHandle, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		log.Printf("failed to prepare sniffing on device %s: %s\n", iface, err)
		wg.Done()
		return
	}
	defer inactiveHandle.CleanUp()

	err = inactiveHandle.SetImmediateMode(true)
	if err != nil {
		log.Printf("failed to set immediate mode on device %s: %s\n", iface, err)
		wg.Done()
		return
	}

	handle, err := inactiveHandle.Activate()
	if err != nil {
		log.Printf("failed to sniff on device %s: %s\n", iface, err)
		wg.Done()
		return
	}
	defer handle.Close()

	if bpf != nil {
		err = handle.SetBPFFilter(*bpf)
		if err != nil {
			log.Printf("failed to set BPF filter on device %s: %s\n", iface, err)
			wg.Done()
			return
		}
	}

	wg.Done()

	linkType := handle.LinkType()

	for {
		rawPacket, captureInfo, err := handle.ZeroCopyReadPacketData()
		if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
			continue
		}
		if err == syscall.EAGAIN {
			continue
		}
		if err != nil {
			log.Printf("failed to read packet from device %s: %s\n", iface, err)
			return
		}

		packet := gopacket.NewPacket(rawPacket, linkType,
			gopacket.DecodeOptions{
				Lazy:   true,
				NoCopy: true,
			})
		packetMetadata := packet.Metadata()
		packetMetadata.CaptureInfo = captureInfo
		packetMetadata.Truncated = packetMetadata.Truncated || captureInfo.CaptureLength < captureInfo.Length

		switch networkLayer := packet.NetworkLayer().(type) {
		case *layers.IPv4:
			src := networkLayer.SrcIP
			dst := networkLayer.DstIP
			rawHeader := networkLayer.Contents
			rawPayload := networkLayer.Payload
			flowSrc := networkLayer.NetworkFlow().Src()

			if networkLayer.Protocol == layers.IPProtocolICMPv4 {
				if len(rawPayload) != 0 && rawPayload[0] != layers.ICMPv4TypeEchoReply && rawPayload[0] != layers.ICMPv4TypeEchoRequest {
					continue
				}
			}

			if src.IsMulticast() || src.Equal(net.IPv4bcast) || dst.IsMulticast() || dst.Equal(net.IPv4bcast) {
				continue
			}
			if cacheContains(pmtudCache, cacheSeconds, flowSrc) {
				continue
			}

			var mtu mtuUpperBound
			for _, r := range rules {
				mtu.MTUUpperbound(src, dst, r)
			}

			if mtu.MTUValid && mtu.TriggerValid && mtu.Trigger < uint(len(rawHeader)+len(rawPayload)) {
				log.Printf("%s -%s\u2192 %s MTU %d\n", src, iface, dst, mtu.MTU)

				if len(rawPayload) > 8 {
					rawPayload = rawPayload[:8]
				}

				replyBuffer := gopacket.NewSerializeBuffer()
				replyPayload := make(gopacket.Payload, len(rawHeader)+len(rawPayload))
				copy(replyPayload[:len(rawHeader)], rawHeader)
				copy(replyPayload[len(rawHeader):], rawPayload)
				err = gopacket.SerializeLayers(replyBuffer,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					&layers.IPv4{
						Version:  4,
						Id:       networkLayer.Id,
						TTL:      64,
						Protocol: layers.IPProtocolICMPv4,
						SrcIP:    dst,
						DstIP:    src,
					},
					&layers.ICMPv4{
						TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeFragmentationNeeded),
						Id:       uint16(mtu.MTU >> 16),
						Seq:      uint16(mtu.MTU),
					},
					replyPayload,
				)
				if err != nil {
					log.Printf("failed to create reply packet for %s: %s\n", iface, err)
					continue
				}

				if replyLinkLayer := generateReplyLinkLayer(iface, rawPacket, linkType); len(replyLinkLayer) != 0 {
					linkLayerBuffer, err := replyBuffer.PrependBytes(len(replyLinkLayer))
					if err != nil {
						panic(err)
					}
					copy(linkLayerBuffer, replyLinkLayer)
				}

				err = handle.WritePacketData(replyBuffer.Bytes())
				if err != nil {
					log.Printf("failed to write reply packet to %s: %s\n", iface, err)
					continue
				}

				pmtudCache.Add(flowSrc, time.Now())
			}

		case *layers.IPv6:
			src := networkLayer.SrcIP
			dst := networkLayer.DstIP
			rawHeader := networkLayer.Contents
			rawPayload := networkLayer.Payload
			flowSrc := networkLayer.NetworkFlow().Src()

			if networkLayer.NextHeader == layers.IPProtocolICMPv6 {
				if len(rawPayload) != 0 && rawPayload[0] < 128 {
					continue
				}
			}

			if src.IsMulticast() || dst.IsMulticast() {
				continue
			}
			if cacheContains(pmtudCache, cacheSeconds, flowSrc) {
				continue
			}

			var mtu mtuUpperBound
			for _, r := range rules {
				mtu.MTUUpperbound(src, dst, r)
			}

			if mtu.MTUValid && mtu.TriggerValid && mtu.Trigger < uint(len(rawHeader)+len(rawPayload)) {
				log.Printf("%s -%s\u2192 %s MTU %d\n", src, iface, dst, mtu.MTU)

				if len(rawPayload) > 1232 {
					rawPayload = rawPayload[:1232]
				}
				if uint(len(rawPayload)+48) > mtu.MTU {
					rawHeader = rawPayload[:mtu.MTU-48]
				}

				replyBuffer := gopacket.NewSerializeBuffer()
				replyNetworkLayer := &layers.IPv6{
					Version:    6,
					FlowLabel:  networkLayer.FlowLabel,
					NextHeader: layers.IPProtocolICMPv6,
					HopLimit:   64,
					SrcIP:      dst,
					DstIP:      src,
				}
				replyApplicationLayer := &layers.ICMPv6{
					TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0),
				}
				replyApplicationLayer.SetNetworkLayerForChecksum(replyNetworkLayer)
				replyPayload := make(gopacket.Payload, len(rawHeader)+len(rawPayload))
				copy(replyPayload[:len(rawHeader)], rawHeader)
				copy(replyPayload[len(rawHeader):], rawPayload)
				err = gopacket.SerializeLayers(replyBuffer,
					gopacket.SerializeOptions{
						FixLengths:       true,
						ComputeChecksums: true,
					},
					replyNetworkLayer,
					replyApplicationLayer,
					gopacket.Payload{
						uint8(mtu.MTU >> 24), uint8(mtu.MTU >> 16), uint8(mtu.MTU >> 8), uint8(mtu.MTU),
					},
					replyPayload,
				)
				if err != nil {
					log.Printf("failed to create reply packet for %s: %s\n", iface, err)
					continue
				}

				if replyLinkLayer := generateReplyLinkLayer(iface, rawPacket, linkType); len(replyLinkLayer) != 0 {
					linkLayerBuffer, err := replyBuffer.PrependBytes(len(replyLinkLayer))
					if err != nil {
						panic(err)
					}
					copy(linkLayerBuffer, replyLinkLayer)
				}

				err = handle.WritePacketData(replyBuffer.Bytes())
				if err != nil {
					log.Printf("failed to write reply packet to %s: %s\n", iface, err)
					continue
				}

				pmtudCache.Add(flowSrc, time.Now())
			}
		}
	}
}
