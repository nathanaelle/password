package password // import "github.com/nathanaelle/password/v2"

import (
	"bytes"
	"testing"
)

type (
	testresult struct {
		salt   string
		input  string
		output string
	}

	testvalid struct {
		input string
		err   error
	}
)

func bytesTest(t *testing.T, src, dest []byte) {
	if !bytes.Equal(src, dest) {
		t.Errorf("[%s] != [%s]", src, dest)
	}
}

func Test_repeatBytes(t *testing.T) {
	bytesTest(t, repeatBytes([]byte("0123456789"), 4), []byte("0123"))
	bytesTest(t, repeatBytes([]byte("0123456789"), 10), []byte("0123456789"))
	bytesTest(t, repeatBytes([]byte("0123456789"), 16), []byte("0123456789012345"))
	bytesTest(t, repeatBytes([]byte("0123456789"), 20), []byte("01234567890123456789"))
	bytesTest(t, repeatBytes([]byte("0123456789"), 36), []byte("012345678901234567890123456789012345"))
}

func Test_multiplyBytes(t *testing.T) {
	bytesTest(t, repeatBytes([]byte("01234"), 5*1), bytes.Join(multiplyBytes([]byte("01234"), 1), []byte{}))
	bytesTest(t, repeatBytes([]byte("01234"), 5*5), bytes.Join(multiplyBytes([]byte("01234"), 5), []byte{}))
}
