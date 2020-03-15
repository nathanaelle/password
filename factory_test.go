package password // import "github.com/nathanaelle/password/v2"

import (
	"testing"
)

func isError(err, seqerr error) bool {
	if err == nil {
		return seqerr != nil
	}

	if err == NoMatchingDef {
		// NoMatchingDef absorb any error
		// so the only isError possible is wen there is no error
		return seqerr == nil
	}

	return err != seqerr
}

func TestCryptSet(t *testing.T) {
	for idx, seq := range validSHA256 {
		if err := crypt.Set(seq.input); isError(err, seq.err) {
			t.Errorf("%3d : bogus err [%s] %v != %v", idx, seq.input, err, seq.err)
		}
	}

	for idx, seq := range validSHA512 {
		if err := crypt.Set(seq.input); isError(err, seq.err) {
			t.Errorf("%3d : bogus err [%s] %v != %v", idx, seq.input, err, seq.err)
		}
	}
}
