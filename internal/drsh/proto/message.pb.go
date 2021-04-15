// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.26.0
// 	protoc        v3.15.7
// source: internal/drsh/proto/message.proto

package proto

import (
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

type SessionMode int32

const (
	SessionMode_MODE_WAITING       SessionMode = 0
	SessionMode_MODE_PTY           SessionMode = 1
	SessionMode_MODE_FILE_UPLOAD   SessionMode = 2
	SessionMode_MODE_FILE_DOWNLOAD SessionMode = 3
)

// Enum value maps for SessionMode.
var (
	SessionMode_name = map[int32]string{
		0: "MODE_WAITING",
		1: "MODE_PTY",
		2: "MODE_FILE_UPLOAD",
		3: "MODE_FILE_DOWNLOAD",
	}
	SessionMode_value = map[string]int32{
		"MODE_WAITING":       0,
		"MODE_PTY":           1,
		"MODE_FILE_UPLOAD":   2,
		"MODE_FILE_DOWNLOAD": 3,
	}
)

func (x SessionMode) Enum() *SessionMode {
	p := new(SessionMode)
	*p = x
	return p
}

func (x SessionMode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SessionMode) Descriptor() protoreflect.EnumDescriptor {
	return file_internal_drsh_proto_message_proto_enumTypes[0].Descriptor()
}

func (SessionMode) Type() protoreflect.EnumType {
	return &file_internal_drsh_proto_message_proto_enumTypes[0]
}

func (x SessionMode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SessionMode.Descriptor instead.
func (SessionMode) EnumDescriptor() ([]byte, []int) {
	return file_internal_drsh_proto_message_proto_rawDescGZIP(), []int{0}
}

type PublicMessage_MessageType int32

const (
	PublicMessage_READY            PublicMessage_MessageType = 0 // C->C, S->S, used to test that Redis is delivering messages
	PublicMessage_PING_REQUEST     PublicMessage_MessageType = 1 // C->S, client wants to check if the server is active
	PublicMessage_PING_RESPONSE    PublicMessage_MessageType = 2 // S->C, server responds to the client that it is active
	PublicMessage_SESSION_REQUEST  PublicMessage_MessageType = 3 // C->S, client wants to establish an encrypted session with the server
	PublicMessage_SESSION_RESPONSE PublicMessage_MessageType = 4 // S->C, server responds if it is able to set up a session
)

// Enum value maps for PublicMessage_MessageType.
var (
	PublicMessage_MessageType_name = map[int32]string{
		0: "READY",
		1: "PING_REQUEST",
		2: "PING_RESPONSE",
		3: "SESSION_REQUEST",
		4: "SESSION_RESPONSE",
	}
	PublicMessage_MessageType_value = map[string]int32{
		"READY":            0,
		"PING_REQUEST":     1,
		"PING_RESPONSE":    2,
		"SESSION_REQUEST":  3,
		"SESSION_RESPONSE": 4,
	}
)

func (x PublicMessage_MessageType) Enum() *PublicMessage_MessageType {
	p := new(PublicMessage_MessageType)
	*p = x
	return p
}

func (x PublicMessage_MessageType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (PublicMessage_MessageType) Descriptor() protoreflect.EnumDescriptor {
	return file_internal_drsh_proto_message_proto_enumTypes[1].Descriptor()
}

func (PublicMessage_MessageType) Type() protoreflect.EnumType {
	return &file_internal_drsh_proto_message_proto_enumTypes[1]
}

func (x PublicMessage_MessageType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use PublicMessage_MessageType.Descriptor instead.
func (PublicMessage_MessageType) EnumDescriptor() ([]byte, []int) {
	return file_internal_drsh_proto_message_proto_rawDescGZIP(), []int{0, 0}
}

type SessionMessage_MessageType int32

const (
	SessionMessage_EXIT               SessionMessage_MessageType = 0 // C->S, S->C, sent by either party to indicate session is closed
	SessionMessage_BOOTSTRAP_REQUEST  SessionMessage_MessageType = 1 // C->S, client starts by requesting that the session follow some parameters
	SessionMessage_BOOTSTRAP_RESPONSE SessionMessage_MessageType = 2 // S->C, server acknowledges that it will respect the client's wishes
	SessionMessage_HEARTBEAT_REQUEST  SessionMessage_MessageType = 3 // C->S, empty message to signal that client is still active
	SessionMessage_HEARTBEAT_RESPONSE SessionMessage_MessageType = 4 // S->C, empty message to signal that server is still active
	SessionMessage_PTY_INPUT          SessionMessage_MessageType = 5 // C->S, client is sending commands to the server's PTY
	SessionMessage_PTY_WINCH          SessionMessage_MessageType = 6 // C->S, client wants to adjust the size of the server's PTY
	SessionMessage_PTY_OUTPUT         SessionMessage_MessageType = 7 // S->C, server is sending output from its PTY
	SessionMessage_FILE_CHUNK         SessionMessage_MessageType = 8 // S->C, C->S, the party sending a file uses this message to transfer data
	SessionMessage_FILE_CLOSE         SessionMessage_MessageType = 9 // S->C, C->S, the party sending a file indicates that they are done
)

// Enum value maps for SessionMessage_MessageType.
var (
	SessionMessage_MessageType_name = map[int32]string{
		0: "EXIT",
		1: "BOOTSTRAP_REQUEST",
		2: "BOOTSTRAP_RESPONSE",
		3: "HEARTBEAT_REQUEST",
		4: "HEARTBEAT_RESPONSE",
		5: "PTY_INPUT",
		6: "PTY_WINCH",
		7: "PTY_OUTPUT",
		8: "FILE_CHUNK",
		9: "FILE_CLOSE",
	}
	SessionMessage_MessageType_value = map[string]int32{
		"EXIT":               0,
		"BOOTSTRAP_REQUEST":  1,
		"BOOTSTRAP_RESPONSE": 2,
		"HEARTBEAT_REQUEST":  3,
		"HEARTBEAT_RESPONSE": 4,
		"PTY_INPUT":          5,
		"PTY_WINCH":          6,
		"PTY_OUTPUT":         7,
		"FILE_CHUNK":         8,
		"FILE_CLOSE":         9,
	}
)

func (x SessionMessage_MessageType) Enum() *SessionMessage_MessageType {
	p := new(SessionMessage_MessageType)
	*p = x
	return p
}

func (x SessionMessage_MessageType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (SessionMessage_MessageType) Descriptor() protoreflect.EnumDescriptor {
	return file_internal_drsh_proto_message_proto_enumTypes[2].Descriptor()
}

func (SessionMessage_MessageType) Type() protoreflect.EnumType {
	return &file_internal_drsh_proto_message_proto_enumTypes[2]
}

func (x SessionMessage_MessageType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use SessionMessage_MessageType.Descriptor instead.
func (SessionMessage_MessageType) EnumDescriptor() ([]byte, []int) {
	return file_internal_drsh_proto_message_proto_rawDescGZIP(), []int{1, 0}
}

// Public messages are sent without encryption between any server and client.
// They are ephmereal messages that require minimal or no state to be kept on the server.
// Sensitive information should not be transferred here.
type PublicMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// All messages
	Type   PublicMessage_MessageType `protobuf:"varint,1,opt,name=type,proto3,enum=drsh.proto.PublicMessage_MessageType" json:"type,omitempty"`
	Sender string                    `protobuf:"bytes,2,opt,name=sender,proto3" json:"sender,omitempty"`
	// Session messages
	SessionKeyPart  []byte `protobuf:"bytes,3,opt,name=session_key_part,json=sessionKeyPart,proto3" json:"session_key_part,omitempty"`  // Sent by both C&S to establish a shared key
	SessionCreated  bool   `protobuf:"varint,4,opt,name=session_created,json=sessionCreated,proto3" json:"session_created,omitempty"`   // Server indicates whether or not a session was created
	SessionError    string `protobuf:"bytes,5,opt,name=session_error,json=sessionError,proto3" json:"session_error,omitempty"`          // Server can optionally provide a error explaining why session cannot be created
	SessionHostname string `protobuf:"bytes,6,opt,name=session_hostname,json=sessionHostname,proto3" json:"session_hostname,omitempty"` // Server provides a valid session hostname if one was created
}

func (x *PublicMessage) Reset() {
	*x = PublicMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_drsh_proto_message_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PublicMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PublicMessage) ProtoMessage() {}

func (x *PublicMessage) ProtoReflect() protoreflect.Message {
	mi := &file_internal_drsh_proto_message_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PublicMessage.ProtoReflect.Descriptor instead.
func (*PublicMessage) Descriptor() ([]byte, []int) {
	return file_internal_drsh_proto_message_proto_rawDescGZIP(), []int{0}
}

func (x *PublicMessage) GetType() PublicMessage_MessageType {
	if x != nil {
		return x.Type
	}
	return PublicMessage_READY
}

func (x *PublicMessage) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

func (x *PublicMessage) GetSessionKeyPart() []byte {
	if x != nil {
		return x.SessionKeyPart
	}
	return nil
}

func (x *PublicMessage) GetSessionCreated() bool {
	if x != nil {
		return x.SessionCreated
	}
	return false
}

func (x *PublicMessage) GetSessionError() string {
	if x != nil {
		return x.SessionError
	}
	return ""
}

func (x *PublicMessage) GetSessionHostname() string {
	if x != nil {
		return x.SessionHostname
	}
	return ""
}

// Session messages are sent with encryption guarantees between a server and client.
// All session messages are assumed to be in a ciphertext format in transit.
// Thus, they can implement core logic associated with sensitive actions, such as
// transferring files, sending commands to a server as a user, etc.
type SessionMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// All messages
	Type   SessionMessage_MessageType `protobuf:"varint,1,opt,name=type,proto3,enum=drsh.proto.SessionMessage_MessageType" json:"type,omitempty"`
	Sender string                     `protobuf:"bytes,2,opt,name=sender,proto3" json:"sender,omitempty"`
	// Exit messages
	ExitNormal bool   `protobuf:"varint,3,opt,name=exit_normal,json=exitNormal,proto3" json:"exit_normal,omitempty"` // Sending party specifies if they are exiting normally
	ExitError  string `protobuf:"bytes,4,opt,name=exit_error,json=exitError,proto3" json:"exit_error,omitempty"`     // Sending party specifies that they are exiting because of an error
	// Bootstrap messages
	BootstrapMode     SessionMode `protobuf:"varint,5,opt,name=bootstrap_mode,json=bootstrapMode,proto3,enum=drsh.proto.SessionMode" json:"bootstrap_mode,omitempty"` // Client requests that the session be of this mode
	BootstrapUsername string      `protobuf:"bytes,6,opt,name=bootstrap_username,json=bootstrapUsername,proto3" json:"bootstrap_username,omitempty"`                  // Client requests that the session be tied to this user account
	BootstrapFilename string      `protobuf:"bytes,7,opt,name=bootstrap_filename,json=bootstrapFilename,proto3" json:"bootstrap_filename,omitempty"`                  // Client requests that the session prepare this remote file for transfer
	BootstrapMotd     string      `protobuf:"bytes,8,opt,name=bootstrap_motd,json=bootstrapMotd,proto3" json:"bootstrap_motd,omitempty"`                              // Server provides a MOTD to be displayed to the client
	// PTY messages
	PtyPayload    []byte `protobuf:"bytes,9,opt,name=pty_payload,json=ptyPayload,proto3" json:"pty_payload,omitempty"`            // Used by PTY_INPUT, PTY_OUTPUT messages
	PtyDimensions uint64 `protobuf:"varint,10,opt,name=pty_dimensions,json=ptyDimensions,proto3" json:"pty_dimensions,omitempty"` // Used by PTY_WINCH message
	// File messages
	FilePayload []byte `protobuf:"bytes,11,opt,name=file_payload,json=filePayload,proto3" json:"file_payload,omitempty"` // Used by FILE_CHUNK message
}

func (x *SessionMessage) Reset() {
	*x = SessionMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_drsh_proto_message_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SessionMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SessionMessage) ProtoMessage() {}

func (x *SessionMessage) ProtoReflect() protoreflect.Message {
	mi := &file_internal_drsh_proto_message_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SessionMessage.ProtoReflect.Descriptor instead.
func (*SessionMessage) Descriptor() ([]byte, []int) {
	return file_internal_drsh_proto_message_proto_rawDescGZIP(), []int{1}
}

func (x *SessionMessage) GetType() SessionMessage_MessageType {
	if x != nil {
		return x.Type
	}
	return SessionMessage_EXIT
}

func (x *SessionMessage) GetSender() string {
	if x != nil {
		return x.Sender
	}
	return ""
}

func (x *SessionMessage) GetExitNormal() bool {
	if x != nil {
		return x.ExitNormal
	}
	return false
}

func (x *SessionMessage) GetExitError() string {
	if x != nil {
		return x.ExitError
	}
	return ""
}

func (x *SessionMessage) GetBootstrapMode() SessionMode {
	if x != nil {
		return x.BootstrapMode
	}
	return SessionMode_MODE_WAITING
}

func (x *SessionMessage) GetBootstrapUsername() string {
	if x != nil {
		return x.BootstrapUsername
	}
	return ""
}

func (x *SessionMessage) GetBootstrapFilename() string {
	if x != nil {
		return x.BootstrapFilename
	}
	return ""
}

func (x *SessionMessage) GetBootstrapMotd() string {
	if x != nil {
		return x.BootstrapMotd
	}
	return ""
}

func (x *SessionMessage) GetPtyPayload() []byte {
	if x != nil {
		return x.PtyPayload
	}
	return nil
}

func (x *SessionMessage) GetPtyDimensions() uint64 {
	if x != nil {
		return x.PtyDimensions
	}
	return 0
}

func (x *SessionMessage) GetFilePayload() []byte {
	if x != nil {
		return x.FilePayload
	}
	return nil
}

// An encrypted session message contains a session message in ciphertext format.
type EncryptedSessionMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Ciphertext []byte `protobuf:"bytes,1,opt,name=ciphertext,proto3" json:"ciphertext,omitempty"`
	Nonce      []byte `protobuf:"bytes,2,opt,name=nonce,proto3" json:"nonce,omitempty"`
}

func (x *EncryptedSessionMessage) Reset() {
	*x = EncryptedSessionMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_drsh_proto_message_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *EncryptedSessionMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*EncryptedSessionMessage) ProtoMessage() {}

func (x *EncryptedSessionMessage) ProtoReflect() protoreflect.Message {
	mi := &file_internal_drsh_proto_message_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use EncryptedSessionMessage.ProtoReflect.Descriptor instead.
func (*EncryptedSessionMessage) Descriptor() ([]byte, []int) {
	return file_internal_drsh_proto_message_proto_rawDescGZIP(), []int{2}
}

func (x *EncryptedSessionMessage) GetCiphertext() []byte {
	if x != nil {
		return x.Ciphertext
	}
	return nil
}

func (x *EncryptedSessionMessage) GetNonce() []byte {
	if x != nil {
		return x.Nonce
	}
	return nil
}

// Any message in transit must be in one of the following formats.
type Message struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to Wrapper:
	//	*Message_PublicMessage
	//	*Message_EncryptedSessionMessage
	Wrapper isMessage_Wrapper `protobuf_oneof:"wrapper"`
}

func (x *Message) Reset() {
	*x = Message{}
	if protoimpl.UnsafeEnabled {
		mi := &file_internal_drsh_proto_message_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Message) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message) ProtoMessage() {}

func (x *Message) ProtoReflect() protoreflect.Message {
	mi := &file_internal_drsh_proto_message_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message.ProtoReflect.Descriptor instead.
func (*Message) Descriptor() ([]byte, []int) {
	return file_internal_drsh_proto_message_proto_rawDescGZIP(), []int{3}
}

func (m *Message) GetWrapper() isMessage_Wrapper {
	if m != nil {
		return m.Wrapper
	}
	return nil
}

func (x *Message) GetPublicMessage() *PublicMessage {
	if x, ok := x.GetWrapper().(*Message_PublicMessage); ok {
		return x.PublicMessage
	}
	return nil
}

func (x *Message) GetEncryptedSessionMessage() *EncryptedSessionMessage {
	if x, ok := x.GetWrapper().(*Message_EncryptedSessionMessage); ok {
		return x.EncryptedSessionMessage
	}
	return nil
}

type isMessage_Wrapper interface {
	isMessage_Wrapper()
}

type Message_PublicMessage struct {
	PublicMessage *PublicMessage `protobuf:"bytes,1,opt,name=public_message,json=publicMessage,proto3,oneof"`
}

type Message_EncryptedSessionMessage struct {
	EncryptedSessionMessage *EncryptedSessionMessage `protobuf:"bytes,2,opt,name=encrypted_session_message,json=encryptedSessionMessage,proto3,oneof"`
}

func (*Message_PublicMessage) isMessage_Wrapper() {}

func (*Message_EncryptedSessionMessage) isMessage_Wrapper() {}

var File_internal_drsh_proto_message_proto protoreflect.FileDescriptor

var file_internal_drsh_proto_message_proto_rawDesc = []byte{
	0x0a, 0x21, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x64, 0x72, 0x73, 0x68, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x0a, 0x64, 0x72, 0x73, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0xef, 0x02, 0x0a, 0x0d, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67,
	0x65, 0x12, 0x39, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x25, 0x2e, 0x64, 0x72, 0x73, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x50, 0x75, 0x62,
	0x6c, 0x69, 0x63, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x16, 0x0a, 0x06,
	0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x65,
	0x6e, 0x64, 0x65, 0x72, 0x12, 0x28, 0x0a, 0x10, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f,
	0x6b, 0x65, 0x79, 0x5f, 0x70, 0x61, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4b, 0x65, 0x79, 0x50, 0x61, 0x72, 0x74, 0x12, 0x27,
	0x0a, 0x0f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x63, 0x72, 0x65, 0x61, 0x74, 0x65,
	0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x64, 0x12, 0x23, 0x0a, 0x0d, 0x73, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x29, 0x0a, 0x10,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65,
	0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x48,
	0x6f, 0x73, 0x74, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x68, 0x0a, 0x0b, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x09, 0x0a, 0x05, 0x52, 0x45, 0x41, 0x44, 0x59, 0x10,
	0x00, 0x12, 0x10, 0x0a, 0x0c, 0x50, 0x49, 0x4e, 0x47, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53,
	0x54, 0x10, 0x01, 0x12, 0x11, 0x0a, 0x0d, 0x50, 0x49, 0x4e, 0x47, 0x5f, 0x52, 0x45, 0x53, 0x50,
	0x4f, 0x4e, 0x53, 0x45, 0x10, 0x02, 0x12, 0x13, 0x0a, 0x0f, 0x53, 0x45, 0x53, 0x53, 0x49, 0x4f,
	0x4e, 0x5f, 0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x03, 0x12, 0x14, 0x0a, 0x10, 0x53,
	0x45, 0x53, 0x53, 0x49, 0x4f, 0x4e, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10,
	0x04, 0x22, 0x9a, 0x05, 0x0a, 0x0e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x12, 0x3a, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x0e, 0x32, 0x26, 0x2e, 0x64, 0x72, 0x73, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2e, 0x4d,
	0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x16, 0x0a, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x12, 0x1f, 0x0a, 0x0b, 0x65, 0x78, 0x69, 0x74,
	0x5f, 0x6e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x18, 0x03, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0a, 0x65,
	0x78, 0x69, 0x74, 0x4e, 0x6f, 0x72, 0x6d, 0x61, 0x6c, 0x12, 0x1d, 0x0a, 0x0a, 0x65, 0x78, 0x69,
	0x74, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x65,
	0x78, 0x69, 0x74, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x12, 0x3e, 0x0a, 0x0e, 0x62, 0x6f, 0x6f, 0x74,
	0x73, 0x74, 0x72, 0x61, 0x70, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x17, 0x2e, 0x64, 0x72, 0x73, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x6f, 0x64, 0x65, 0x52, 0x0d, 0x62, 0x6f, 0x6f, 0x74, 0x73,
	0x74, 0x72, 0x61, 0x70, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x62, 0x6f, 0x6f, 0x74,
	0x73, 0x74, 0x72, 0x61, 0x70, 0x5f, 0x75, 0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x11, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x55,
	0x73, 0x65, 0x72, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x62, 0x6f, 0x6f, 0x74, 0x73,
	0x74, 0x72, 0x61, 0x70, 0x5f, 0x66, 0x69, 0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x07, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x11, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x46, 0x69,
	0x6c, 0x65, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x25, 0x0a, 0x0e, 0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74,
	0x72, 0x61, 0x70, 0x5f, 0x6d, 0x6f, 0x74, 0x64, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0d,
	0x62, 0x6f, 0x6f, 0x74, 0x73, 0x74, 0x72, 0x61, 0x70, 0x4d, 0x6f, 0x74, 0x64, 0x12, 0x1f, 0x0a,
	0x0b, 0x70, 0x74, 0x79, 0x5f, 0x70, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x09, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x0a, 0x70, 0x74, 0x79, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x12, 0x25,
	0x0a, 0x0e, 0x70, 0x74, 0x79, 0x5f, 0x64, 0x69, 0x6d, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x18, 0x0a, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0d, 0x70, 0x74, 0x79, 0x44, 0x69, 0x6d, 0x65, 0x6e,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x21, 0x0a, 0x0c, 0x66, 0x69, 0x6c, 0x65, 0x5f, 0x70, 0x61,
	0x79, 0x6c, 0x6f, 0x61, 0x64, 0x18, 0x0b, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0b, 0x66, 0x69, 0x6c,
	0x65, 0x50, 0x61, 0x79, 0x6c, 0x6f, 0x61, 0x64, 0x22, 0xc3, 0x01, 0x0a, 0x0b, 0x4d, 0x65, 0x73,
	0x73, 0x61, 0x67, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x08, 0x0a, 0x04, 0x45, 0x58, 0x49, 0x54,
	0x10, 0x00, 0x12, 0x15, 0x0a, 0x11, 0x42, 0x4f, 0x4f, 0x54, 0x53, 0x54, 0x52, 0x41, 0x50, 0x5f,
	0x52, 0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x01, 0x12, 0x16, 0x0a, 0x12, 0x42, 0x4f, 0x4f,
	0x54, 0x53, 0x54, 0x52, 0x41, 0x50, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10,
	0x02, 0x12, 0x15, 0x0a, 0x11, 0x48, 0x45, 0x41, 0x52, 0x54, 0x42, 0x45, 0x41, 0x54, 0x5f, 0x52,
	0x45, 0x51, 0x55, 0x45, 0x53, 0x54, 0x10, 0x03, 0x12, 0x16, 0x0a, 0x12, 0x48, 0x45, 0x41, 0x52,
	0x54, 0x42, 0x45, 0x41, 0x54, 0x5f, 0x52, 0x45, 0x53, 0x50, 0x4f, 0x4e, 0x53, 0x45, 0x10, 0x04,
	0x12, 0x0d, 0x0a, 0x09, 0x50, 0x54, 0x59, 0x5f, 0x49, 0x4e, 0x50, 0x55, 0x54, 0x10, 0x05, 0x12,
	0x0d, 0x0a, 0x09, 0x50, 0x54, 0x59, 0x5f, 0x57, 0x49, 0x4e, 0x43, 0x48, 0x10, 0x06, 0x12, 0x0e,
	0x0a, 0x0a, 0x50, 0x54, 0x59, 0x5f, 0x4f, 0x55, 0x54, 0x50, 0x55, 0x54, 0x10, 0x07, 0x12, 0x0e,
	0x0a, 0x0a, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x43, 0x48, 0x55, 0x4e, 0x4b, 0x10, 0x08, 0x12, 0x0e,
	0x0a, 0x0a, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x43, 0x4c, 0x4f, 0x53, 0x45, 0x10, 0x09, 0x22, 0x4f,
	0x0a, 0x17, 0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x53, 0x65, 0x73, 0x73, 0x69,
	0x6f, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x1e, 0x0a, 0x0a, 0x63, 0x69, 0x70,
	0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0a, 0x63,
	0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x6e, 0x6f, 0x6e,
	0x63, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x05, 0x6e, 0x6f, 0x6e, 0x63, 0x65, 0x22,
	0xbb, 0x01, 0x0a, 0x07, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x42, 0x0a, 0x0e, 0x70,
	0x75, 0x62, 0x6c, 0x69, 0x63, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x64, 0x72, 0x73, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x2e, 0x50, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48, 0x00,
	0x52, 0x0d, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12,
	0x61, 0x0a, 0x19, 0x65, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x5f, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x23, 0x2e, 0x64, 0x72, 0x73, 0x68, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2e,
	0x45, 0x6e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x65, 0x64, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x48, 0x00, 0x52, 0x17, 0x65, 0x6e, 0x63, 0x72, 0x79,
	0x70, 0x74, 0x65, 0x64, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x42, 0x09, 0x0a, 0x07, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x2a, 0x5b, 0x0a,
	0x0b, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x10, 0x0a, 0x0c,
	0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x57, 0x41, 0x49, 0x54, 0x49, 0x4e, 0x47, 0x10, 0x00, 0x12, 0x0c,
	0x0a, 0x08, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x50, 0x54, 0x59, 0x10, 0x01, 0x12, 0x14, 0x0a, 0x10,
	0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x46, 0x49, 0x4c, 0x45, 0x5f, 0x55, 0x50, 0x4c, 0x4f, 0x41, 0x44,
	0x10, 0x02, 0x12, 0x16, 0x0a, 0x12, 0x4d, 0x4f, 0x44, 0x45, 0x5f, 0x46, 0x49, 0x4c, 0x45, 0x5f,
	0x44, 0x4f, 0x57, 0x4e, 0x4c, 0x4f, 0x41, 0x44, 0x10, 0x03, 0x42, 0x17, 0x5a, 0x15, 0x2e, 0x2f,
	0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x2f, 0x64, 0x72, 0x73, 0x68, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_internal_drsh_proto_message_proto_rawDescOnce sync.Once
	file_internal_drsh_proto_message_proto_rawDescData = file_internal_drsh_proto_message_proto_rawDesc
)

func file_internal_drsh_proto_message_proto_rawDescGZIP() []byte {
	file_internal_drsh_proto_message_proto_rawDescOnce.Do(func() {
		file_internal_drsh_proto_message_proto_rawDescData = protoimpl.X.CompressGZIP(file_internal_drsh_proto_message_proto_rawDescData)
	})
	return file_internal_drsh_proto_message_proto_rawDescData
}

var file_internal_drsh_proto_message_proto_enumTypes = make([]protoimpl.EnumInfo, 3)
var file_internal_drsh_proto_message_proto_msgTypes = make([]protoimpl.MessageInfo, 4)
var file_internal_drsh_proto_message_proto_goTypes = []interface{}{
	(SessionMode)(0),                // 0: drsh.proto.SessionMode
	(PublicMessage_MessageType)(0),  // 1: drsh.proto.PublicMessage.MessageType
	(SessionMessage_MessageType)(0), // 2: drsh.proto.SessionMessage.MessageType
	(*PublicMessage)(nil),           // 3: drsh.proto.PublicMessage
	(*SessionMessage)(nil),          // 4: drsh.proto.SessionMessage
	(*EncryptedSessionMessage)(nil), // 5: drsh.proto.EncryptedSessionMessage
	(*Message)(nil),                 // 6: drsh.proto.Message
}
var file_internal_drsh_proto_message_proto_depIdxs = []int32{
	1, // 0: drsh.proto.PublicMessage.type:type_name -> drsh.proto.PublicMessage.MessageType
	2, // 1: drsh.proto.SessionMessage.type:type_name -> drsh.proto.SessionMessage.MessageType
	0, // 2: drsh.proto.SessionMessage.bootstrap_mode:type_name -> drsh.proto.SessionMode
	3, // 3: drsh.proto.Message.public_message:type_name -> drsh.proto.PublicMessage
	5, // 4: drsh.proto.Message.encrypted_session_message:type_name -> drsh.proto.EncryptedSessionMessage
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_internal_drsh_proto_message_proto_init() }
func file_internal_drsh_proto_message_proto_init() {
	if File_internal_drsh_proto_message_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_internal_drsh_proto_message_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PublicMessage); i {
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
		file_internal_drsh_proto_message_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SessionMessage); i {
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
		file_internal_drsh_proto_message_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*EncryptedSessionMessage); i {
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
		file_internal_drsh_proto_message_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Message); i {
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
	file_internal_drsh_proto_message_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*Message_PublicMessage)(nil),
		(*Message_EncryptedSessionMessage)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_internal_drsh_proto_message_proto_rawDesc,
			NumEnums:      3,
			NumMessages:   4,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_internal_drsh_proto_message_proto_goTypes,
		DependencyIndexes: file_internal_drsh_proto_message_proto_depIdxs,
		EnumInfos:         file_internal_drsh_proto_message_proto_enumTypes,
		MessageInfos:      file_internal_drsh_proto_message_proto_msgTypes,
	}.Build()
	File_internal_drsh_proto_message_proto = out.File
	file_internal_drsh_proto_message_proto_rawDesc = nil
	file_internal_drsh_proto_message_proto_goTypes = nil
	file_internal_drsh_proto_message_proto_depIdxs = nil
}
