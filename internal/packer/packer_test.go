package packer

import (
	"bytes"
	"testing"
)

func TestPackUnpackString(t *testing.T) {
	b, err := PackMessage("hello 世界")
	if err != nil {
		t.Fatal(err)
	}
	var out string
	if err := UnpackMessage(b, &out); err != nil {
		t.Fatal(err)
	}
	if out != "hello 世界" {
		t.Errorf("got %q, want %q", out, "hello 世界")
	}
}

func TestPackUnpackInt(t *testing.T) {
	b, err := PackMessage(-42)
	if err != nil {
		t.Fatal(err)
	}
	var out int
	if err := UnpackMessage(b, &out); err != nil {
		t.Fatal(err)
	}
	if out != -42 {
		t.Errorf("got %d, want -42", out)
	}
}

func TestPackUnpackBytes(t *testing.T) {
	in := []byte{0, 1, 2, 254, 255}
	b, err := PackMessage(in)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	if err := UnpackMessage(b, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(in, out) {
		t.Errorf("got %v, want %v", out, in)
	}
}

type message struct {
	Type string         `msgpack:"type"`
	ID   int            `msgpack:"id"`
	Data map[string]any `msgpack:"data"`
	OK   bool           `msgpack:"ok"`
}

func TestPackUnpackStruct(t *testing.T) {
	in := message{Type: "greeting", ID: 7, Data: map[string]any{"k": "v"}, OK: true}
	b, err := PackMessage(in)
	if err != nil {
		t.Fatal(err)
	}
	var out message
	if err := UnpackMessage(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Type != in.Type || out.ID != in.ID || out.OK != in.OK {
		t.Errorf("got %+v, want %+v", out, in)
	}
	if out.Data["k"] != "v" {
		t.Errorf("data = %+v, want k=v", out.Data)
	}
}

func TestUnpackInvalid(t *testing.T) {
	var out map[string]any
	if err := UnpackMessage([]byte{0xc1}, &out); err == nil {
		t.Error("expected an error decoding invalid msgpack, got nil")
	}
}
