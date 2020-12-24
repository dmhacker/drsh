// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.12.4
// source: proto/packet.proto

package packet

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type Packet_PacketType int32

const (
	// Packet sent on startup to self to make sure receiver is online
	Packet_READY Packet_PacketType = 0
	// The client is responsible for initiating most requests
	// and should usually expect a response from the server
	Packet_CLIENT_PING      Packet_PacketType = 1
	Packet_CLIENT_HANDSHAKE Packet_PacketType = 2
	Packet_CLIENT_INPUT     Packet_PacketType = 3
	Packet_CLIENT_PTY       Packet_PacketType = 4
	Packet_CLIENT_EXIT      Packet_PacketType = 5
	// With the exception of SERVER_OUTPUT, these packets
	// are always a direct response to a client request
	Packet_SERVER_PING      Packet_PacketType = 6
	Packet_SERVER_HANDSHAKE Packet_PacketType = 7
	Packet_SERVER_OUTPUT    Packet_PacketType = 8
	Packet_SERVER_EXIT      Packet_PacketType = 9
)

// Enum value maps for Packet_PacketType.
var (
	Packet_PacketType_name = map[int32]string{
		0: "READY",
		1: "CLIENT_PING",
		2: "CLIENT_HANDSHAKE",
		3: "CLIENT_INPUT",
		4: "CLIENT_PTY",
		5: "CLIENT_EXIT",
		6: "SERVER_PING",
		7: "SERVER_HANDSHAKE",
		8: "SERVER_OUTPUT",
		9: "SERVER_EXIT",
	}
	Packet_PacketType_value = map[string]int32{
		"READY":            0,
		"CLIENT_PING":      1,
		"CLIENT_HANDSHAKE": 2,
		"CLIENT_INPUT":     3,
		"CLIENT_PTY":       4,
		"CLIENT_EXIT":      5,
		"SERVER_PING":      6,
		"SERVER_HANDSHAKE": 7,
		"SERVER_OUTPUT":    8,
		"SERVER_EXIT":      9,
	}
)

func (x Packet_PacketType) Enum() *Packet_PacketType {
	p := new(Packet_PacketType)
	*p = x
	return p
}

func (x Packet_PacketType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Packet_PacketType) Descriptor() protoreflect.EnumDescriptor {
	return file_proto_packet_proto_enumTypes[0].Descriptor()
}

func (Packet_PacketType) Type() protoreflect.EnumType {
	return &file_proto_packet_proto_enumTypes[0]
}

func (x Packet_PacketType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Packet_PacketType.Descriptor instead.
func (Packet_PacketType) EnumDescriptor() ([]byte, []int) {
	return file_proto_packet_proto_rawDescGZIP(), []int{0, 0}
}

type Packet struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Shared fields
	Type      Packet_PacketType `protobuf:"varint,1,opt,name=type,proto3,enum=packet.Packet_PacketType" json:"type,omitempty"`
	Sender    []byte            `protobuf:"bytes,2,opt,name=sender,proto3" json:"sender,omitempty"`       // UUID of sending machine
	Recipient []byte            `protobuf:"bytes,3,opt,name=recipient,proto3" json:"recipient,omitempty"` // UUID of receiving machine
	Payload   []byte            `protobuf:"bytes,4,opt,name=payload,proto3" json:"payload,omitempty"`     // Used by CLIENT_INPUT, SERVER_OUTPUT
	// Client only fields
	PtyRows    uint32 `protobuf:"varint,5,opt,name=pty_rows,json=ptyRows,proto3" json:"pty_rows,omitempty"`
	PtyCols    uint32 `protobuf:"varint,6,opt,name=pty_cols,json=ptyCols,proto3" json:"pty_cols,omitempty"`
	PtyXpixels uint32 `protobuf:"varint,7,opt,name=pty_xpixels,json=ptyXpixels,proto3" json:"pty_xpixels,omitempty"`
	PtyYpixels uint32 `protobuf:"varint,8,opt,name=pty_ypixels,json=ptyYpixels,proto3" json:"pty_ypixels,omitempty"`
	// Server only fields
	ServerName string `protobuf:"bytes,9,opt,name=server_name,json=serverName,proto3" json:"server_name,omitempty"`
	Success    bool   `protobuf:"varint,10,opt,name=success,proto3" json:"success,omitempty"`
	Error      string `protobuf:"bytes,11,opt,name=error,proto3" json:"error,omitempty"`
}

func (x *Packet) Reset() {
	*x = Packet{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_packet_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Packet) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Packet) ProtoMessage() {}

func (x *Packet) ProtoReflect() protoreflect.Message {
	mi := &file_proto_packet_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Packet.ProtoReflect.Descriptor instead.
func (*Packet) Descriptor() ([]byte, []int) {
	return file_proto_packet_proto_rawDescGZIP(), []int{0}
}

func (x *Packet) GetType() Packet_PacketType {
	if x != nil {
		return x.Type
	}
	return Packet_READY
}

func (x *Packet) GetSender() []byte {
	if x != nil {
		return x.Sender
	}
	return nil
}

func (x *Packet) GetRecipient() []byte {
	if x != nil {
		return x.Recipient
	}
	return nil
}

func (x *Packet) GetPayload() []byte {
	if x != nil {
		return x.Payload
	}
	return nil
}

func (x *Packet) GetPtyRows() uint32 {
	if x != nil {
		return x.PtyRows
	}
	return 0
}

func (x *Packet) GetPtyCols() uint32 {
	if x != nil {
		return x.PtyCols
	}
	return 0
}

func (x *Packet) GetPtyXpixels() uint32 {
	if x != nil {
		return x.PtyXpixels
	}
	return 0
}

func (x *Packet) GetPtyYpixels() uint32 {
	if x != nil {
		return x.PtyYpixels
	}
	return 0
}

func (x *Packet) GetServerName() string {
	if x != nil {
		return x.ServerName
	}
	return ""
}

func (x *Packet) GetSuccess() bool {
	if x != nil {
		return x.Success
	}
	return false
}

func (x *Packet) GetError() string {
	if x != nil {
		return x.Error
	}
	return ""
}

var File_proto_packet_proto protoreflect.FileDescriptor

var file_proto_packet_proto_rawDesc = []byte{
	0x0a, 0x12, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x22, 0x8f, 0x04, 0x0a,
	0x06, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x12, 0x2d, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x19, 0x2e, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x50,
	0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65,
	0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x12, 0x1c,
	0x0a, 0x09, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x0c, 0x52, 0x09, 0x72, 0x65, 0x63, 0x69, 0x70, 0x69, 0x65, 0x6e, 0x74, 0x12, 0x18, 0x0a, 0x07,
	0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x70,
	0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x74, 0x79, 0x5f, 0x72, 0x6f,
	0x77, 0x73, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x70, 0x74, 0x79, 0x52, 0x6f, 0x77,
	0x73, 0x12, 0x19, 0x0a, 0x08, 0x70, 0x74, 0x79, 0x5f, 0x63, 0x6f, 0x6c, 0x73, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x07, 0x70, 0x74, 0x79, 0x43, 0x6f, 0x6c, 0x73, 0x12, 0x1f, 0x0a, 0x0b,
	0x70, 0x74, 0x79, 0x5f, 0x78, 0x70, 0x69, 0x78, 0x65, 0x6c, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x0a, 0x70, 0x74, 0x79, 0x58, 0x70, 0x69, 0x78, 0x65, 0x6c, 0x73, 0x12, 0x1f, 0x0a,
	0x0b, 0x70, 0x74, 0x79, 0x5f, 0x79, 0x70, 0x69, 0x78, 0x65, 0x6c, 0x73, 0x18, 0x08, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x0a, 0x70, 0x74, 0x79, 0x59, 0x70, 0x69, 0x78, 0x65, 0x6c, 0x73, 0x12, 0x1f,
	0x0a, 0x0b, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x4e, 0x61, 0x6d, 0x65, 0x12,
	0x18, 0x0a, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x07, 0x73, 0x75, 0x63, 0x63, 0x65, 0x73, 0x73, 0x12, 0x14, 0x0a, 0x05, 0x65, 0x72, 0x72,
	0x6f, 0x72, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x09, 0x52, 0x05, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x22,
	0xbc, 0x01, 0x0a, 0x0a, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x54, 0x79, 0x70, 0x65, 0x12, 0x09,
	0x0a, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x10, 0x00, 0x12, 0x0f, 0x0a, 0x0b, 0x43, 0x4c, 0x49,
	0x45, 0x4e, 0x54, 0x5f, 0x50, 0x49, 0x4e, 0x47, 0x10, 0x01, 0x12, 0x14, 0x0a, 0x10, 0x43, 0x4c,
	0x49, 0x45, 0x4e, 0x54, 0x5f, 0x48, 0x41, 0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x10, 0x02,
	0x12, 0x10, 0x0a, 0x0c, 0x43, 0x4c, 0x49, 0x45, 0x4e, 0x54, 0x5f, 0x49, 0x4e, 0x50, 0x55, 0x54,
	0x10, 0x03, 0x12, 0x0e, 0x0a, 0x0a, 0x43, 0x4c, 0x49, 0x45, 0x4e, 0x54, 0x5f, 0x50, 0x54, 0x59,
	0x10, 0x04, 0x12, 0x0f, 0x0a, 0x0b, 0x43, 0x4c, 0x49, 0x45, 0x4e, 0x54, 0x5f, 0x45, 0x58, 0x49,
	0x54, 0x10, 0x05, 0x12, 0x0f, 0x0a, 0x0b, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5f, 0x50, 0x49,
	0x4e, 0x47, 0x10, 0x06, 0x12, 0x14, 0x0a, 0x10, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5f, 0x48,
	0x41, 0x4e, 0x44, 0x53, 0x48, 0x41, 0x4b, 0x45, 0x10, 0x07, 0x12, 0x11, 0x0a, 0x0d, 0x53, 0x45,
	0x52, 0x56, 0x45, 0x52, 0x5f, 0x4f, 0x55, 0x54, 0x50, 0x55, 0x54, 0x10, 0x08, 0x12, 0x0f, 0x0a,
	0x0b, 0x53, 0x45, 0x52, 0x56, 0x45, 0x52, 0x5f, 0x45, 0x58, 0x49, 0x54, 0x10, 0x09, 0x42, 0x13,
	0x5a, 0x11, 0x2e, 0x2f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x70, 0x61, 0x63,
	0x6b, 0x65, 0x74, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_packet_proto_rawDescOnce sync.Once
	file_proto_packet_proto_rawDescData = file_proto_packet_proto_rawDesc
)

func file_proto_packet_proto_rawDescGZIP() []byte {
	file_proto_packet_proto_rawDescOnce.Do(func() {
		file_proto_packet_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_packet_proto_rawDescData)
	})
	return file_proto_packet_proto_rawDescData
}

var file_proto_packet_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_proto_packet_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_proto_packet_proto_goTypes = []interface{}{
	(Packet_PacketType)(0), // 0: packet.Packet.PacketType
	(*Packet)(nil),         // 1: packet.Packet
}
var file_proto_packet_proto_depIdxs = []int32{
	0, // 0: packet.Packet.type:type_name -> packet.Packet.PacketType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_proto_packet_proto_init() }
func file_proto_packet_proto_init() {
	if File_proto_packet_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_packet_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Packet); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_packet_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_packet_proto_goTypes,
		DependencyIndexes: file_proto_packet_proto_depIdxs,
		EnumInfos:         file_proto_packet_proto_enumTypes,
		MessageInfos:      file_proto_packet_proto_msgTypes,
	}.Build()
	File_proto_packet_proto = out.File
	file_proto_packet_proto_rawDesc = nil
	file_proto_packet_proto_goTypes = nil
	file_proto_packet_proto_depIdxs = nil
}
