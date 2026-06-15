package shell

import (
	"reflect"
	"testing"
)

func TestQuoteSplit(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"simple", "a b c", []string{"a", "b", "c"}},
		{"extra spaces", "  a   b ", []string{"a", "b"}},
		{"tabs and newlines", "a\tb\nc", []string{"a", "b", "c"}},
		{"single quotes", "'foo bar' baz", []string{"foo bar", "baz"}},
		{"double quotes", `"foo bar" baz`, []string{"foo bar", "baz"}},
		{"flag with value", "cmd --arg=val", []string{"cmd", "--arg=val"}},
		{"quoted in the middle", `echo "hello world" end`, []string{"echo", "hello world", "end"}},
		{"empty", "", nil},
		{"unterminated double quote", `"foo`, nil},
		{"unterminated single quote", `'foo`, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := QuoteSplit(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("QuoteSplit(%q) = %#v, want %#v", tt.in, got, tt.want)
			}
		})
	}
}

func TestNewCommandParsesArgs(t *testing.T) {
	c := NewCommand("echo hello world")
	defer func() { _ = c.Close() }()

	want := []string{"echo", "hello", "world"}
	if !reflect.DeepEqual(c.Args, want) {
		t.Errorf("Args = %#v, want %#v", c.Args, want)
	}
}
