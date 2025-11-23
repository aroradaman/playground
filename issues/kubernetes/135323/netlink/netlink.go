package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type IPTuple struct {
	DstIP    net.IP
	DstPort  uint16
	Protocol uint8
	SrcIP    net.IP
	SrcPort  uint16
}

type Flow struct {
	FamilyType uint8
	Forward    IPTuple
	Reverse    IPTuple

	rawDataBytes []byte
}

func DumpConntrackTable() ([]*Flow, error) {
	req := nl.NewNetlinkRequest((int(netlink.ConntrackTable)<<8)|nl.IPCTNL_MSG_CT_GET, unix.NLM_F_DUMP)

	// Create the Netlink request object
	// Add the netfilter header
	msg := &nl.Nfgenmsg{
		NfgenFamily: uint8(unix.AF_INET),
		Version:     nl.NFNETLINK_V0,
		ResId:       0,
	}
	req.AddData(msg)

	res, err := req.Execute(unix.NETLINK_NETFILTER, 0)
	if err != nil {
		return nil, err
	}

	var result []*Flow
	for _, dataRaw := range res {
		flow, _ := parse(dataRaw)
		result = append(result, flow)
	}

	return result, nil
}

func main() {
	flows, err := DumpConntrackTable()
	if err != nil {
		panic(err)
	}
	for _, flow := range flows {
		fmt.Println(flow)
	}
}

func parseNfAttrTL(r *bytes.Reader) (isNested bool, attrType, len uint16) {
	binary.Read(r, nl.NativeEndian(), &len)
	len -= nl.SizeofNfattr

	binary.Read(r, nl.NativeEndian(), &attrType)
	isNested = (attrType & nl.NLA_F_NESTED) == nl.NLA_F_NESTED
	attrType = attrType & (nl.NLA_F_NESTED - 1)
	return isNested, attrType, len
}

func parseNfAttrTLV(r *bytes.Reader) (isNested bool, attrType, len uint16, value []byte) {
	isNested, attrType, len = parseNfAttrTL(r)

	value = make([]byte, len)
	binary.Read(r, binary.BigEndian, &value)
	return isNested, attrType, len, value
}

func parseBERaw16(r *bytes.Reader, v *uint16) {
	binary.Read(r, binary.BigEndian, v)
}

func skipNfAttrValue(r *bytes.Reader, len uint16) uint16 {
	len = (len + nl.NLA_ALIGNTO - 1) & ^(nl.NLA_ALIGNTO - 1)
	r.Seek(int64(len), io.SeekCurrent)
	return len
}

func parse(data []byte) (*Flow, error) {
	flow := &Flow{}
	reader := bytes.NewReader(data)

	binary.Read(reader, nl.NativeEndian(), &flow.FamilyType)

	// skip the first 4 bytes (netfilter generic message).
	if _, err := reader.Seek(nl.SizeofNfgenmsg-1, io.SeekCurrent); err != nil {
		return nil, err
	}

	// now we are just left with the attributes(struct nlattr) after skipping netlink generic
	// message; we iterate over all the attributes one by one to construct our Counter object.
	for reader.Len() > 0 {

		// netlink attributes are in LTV(length, type and value) format.
		var length, attrType uint16
		var nested bool
		if nested, attrType, length = parseNfAttrTL(reader); nested {
			// STEP 4. parse value  [variable sized]
			// The value can assume any data-type. To read it into the appropriate data structure, we need
			// to know the data type in advance. We achieve this by switching on the attribute-type, and we
			// allocate the 'adjusted length' bytes (as done in step(3)) for the data-structure.
			switch attrType {
			case nl.CTA_TUPLE_ORIG:
				if nested, attrType, length = parseNfAttrTL(reader); nested && attrType == nl.CTA_TUPLE_IP {
					flow.Forward = parseIPTuple(reader)
				}
			case nl.CTA_TUPLE_REPLY:
				if nested, attrType, length = parseNfAttrTL(reader); nested && attrType == nl.CTA_TUPLE_IP {
					flow.Reverse = parseIPTuple(reader)
				} else {
					// Header not recognized skip it
					skipNfAttrValue(reader, attrType)
				}
			default:
				skipNfAttrValue(reader, length)
			}
		}
	}
	return flow, nil
}

func parseIPTuple(reader *bytes.Reader) IPTuple {
	var ipTuple IPTuple

	var length, attrType uint16
	var value []byte

	// capture source and destination ip address
	// we iterate twice
	for i := 0; i < 2; i++ {
		_, attrType, _, value = parseNfAttrTLV(reader)

		switch attrType {
		case nl.CTA_IP_V4_SRC, nl.CTA_IP_V6_SRC:
			ipTuple.SrcIP = value
		case nl.CTA_IP_V4_DST, nl.CTA_IP_V6_DST:
			ipTuple.DstIP = value
		}
	}

	_, _, protoInfoTotalLen := parseNfAttrTL(reader)

	_, attrType, length, value = parseNfAttrTLV(reader)

	protoInfoBytesRead := uint16(nl.SizeofNfattr) + length

	if attrType == nl.CTA_PROTO_NUM {
		ipTuple.Protocol = value[0]
	}

	// We only parse TCP & UDP headers. Skip the others.
	if ipTuple.Protocol != unix.IPPROTO_TCP && ipTuple.Protocol != unix.IPPROTO_UDP {
		// skip the rest
		bytesRemaining := protoInfoTotalLen - protoInfoBytesRead
		reader.Seek(int64(bytesRemaining), io.SeekCurrent)
		return ipTuple
	}

	reader.Seek(3, io.SeekCurrent)
	protoInfoBytesRead += 3

	for i := 0; i < 2; i++ {
		_, attrType, _ = parseNfAttrTL(reader)
		protoInfoBytesRead += uint16(nl.SizeofNfattr)
		switch attrType {
		case nl.CTA_PROTO_SRC_PORT:
			parseBERaw16(reader, &ipTuple.SrcPort)
			protoInfoBytesRead += 2
		case nl.CTA_PROTO_DST_PORT:
			parseBERaw16(reader, &ipTuple.DstPort)
			protoInfoBytesRead += 2
		}
		// Skip 2 bytes of padding
		reader.Seek(2, io.SeekCurrent)
		protoInfoBytesRead += 2
	}
	// Skip any remaining/unknown parts of the message
	bytesRemaining := protoInfoTotalLen - protoInfoBytesRead
	reader.Seek(int64(bytesRemaining), io.SeekCurrent)
	return ipTuple
}
