package	password	// import "github.com/nathanaelle/password"

import	(
	"testing"
	"bytes"
)


type	(
	testresult struct {
		salt	string
		input	string
		output	string
	}

	testvalid struct {
		input	string
		err	error
	}
)


func t_bytes_test(t *testing.T, src, dest []byte)  {
	if !bytes.Equal( src, dest ) {
		t.Errorf("[%s] != [%s]", src, dest)
	}
}

func Test_repeat_bytes(t *testing.T) {
	t_bytes_test(t, repeat_bytes([]byte("0123456789"), 4), []byte("0123") )
	t_bytes_test(t, repeat_bytes([]byte("0123456789"), 10), []byte("0123456789") )
	t_bytes_test(t, repeat_bytes([]byte("0123456789"), 16), []byte("0123456789012345") )
	t_bytes_test(t, repeat_bytes([]byte("0123456789"), 20), []byte("01234567890123456789") )
	t_bytes_test(t, repeat_bytes([]byte("0123456789"), 36), []byte("012345678901234567890123456789012345") )
}

func Test_multiply_bytes(t *testing.T) {
	t_bytes_test(t, repeat_bytes([]byte("01234"), 5*1), bytes.Join( multiply_bytes([]byte("01234"), 1), []byte{} ))
	t_bytes_test(t, repeat_bytes([]byte("01234"), 5*5), bytes.Join( multiply_bytes([]byte("01234"), 5), []byte{} ))
}
