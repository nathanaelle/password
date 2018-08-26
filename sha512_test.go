package password // import "github.com/nathanaelle/password"

import (
	"testing"
)

var (
	result_sha512 []testresult = []testresult{
		{"$6$saltstring", "Hello world!", "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1"},
		{"$6$rounds=10000$saltstringsaltstring", "Hello world!", "$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v."},
		{"$6$rounds=5000$toolongsaltstring", "This is just a test", "$6$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0"},
		{"$6$rounds=123456$asaltof16chars..", "a short string", "$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1"},
		{"$6$rounds=10$roundstoolow", "the minimum number is still observed", "$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX."},
		{"$6$rounds=1400$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.", "$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1"},
		{"$6$rounds=77777$short", "we have a short salt string but not a short password", "$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0"},
	}

	valid_sha512 []testvalid = []testvalid{
		{"", ERR_NOPE},
		{"$", ERR_NOPE},
		{"$$", ERR_NOPE},
		{"$0$", ERR_NOPE},
		{"$6$rounds=xyz$", ERR_NOPE},
		{"$6$", nil},
		{"$6$saltstring", nil},
		{"$6$rounds=10000$", nil},
		{"$6$rounds=10000$saltstringsaltstring", nil},
		{"$6$rounds=5000$toolongsaltstring", nil},
		{"$6$rounds=123456$asaltof16chars..", nil},
		{"$6$rounds=10$roundstoolow", nil},
		{"$6$rounds=1400$anotherlongsaltstring", nil},
		{"$6$rounds=77777$short", nil},
	}
)

func TestDefSHA512Result(t *testing.T) {
	for idx, seq := range result_sha512 {
		if _, ok := SHA512.CrypterFound(seq.output); !ok {
			t.Errorf("%3d : invalid\t%s", idx, seq.output)
		}

		if _, ok := SHA512.CrypterFound(seq.salt); !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
		}
	}
}

func TestDefSHA512Valid(t *testing.T) {
	for idx, seq := range valid_sha512 {
		if _, ok := SHA512.CrypterFound(seq.input); ok != (seq.err == nil) {
			t.Errorf("%3d : bogus valid\t%s", idx, seq.input)
		}
	}

	for idx, seq := range valid_sha512 {
		if err := SHA512.Default().Set(seq.input); err != seq.err {
			t.Errorf("%3d : bogus err [%s] %v %v", idx, seq.input, seq.err, err)
		}
	}
}

func TestCrypterSHA512Crypt(t *testing.T) {
	for idx, seq := range result_sha512 {
		crypter, ok := SHA512.CrypterFound(seq.salt)
		if !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
			continue
		}

		out := crypter.Crypt([]byte(seq.input)).String()
		if out != seq.output {
			t.Errorf("-- %d\n%123s\n%123s", idx, out, seq.output)
		}
	}
}

func TestCrypterSHA512Verify(t *testing.T) {
	for idx, seq := range result_sha512 {
		crypter, ok := SHA512.CrypterFound(seq.output)
		if !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
			continue
		}

		if !crypter.Verify([]byte(seq.input)) {
			t.Errorf("-- %d don't match\n%123s\n%123s", idx, crypter.Crypt([]byte(seq.input)), seq.output)
		}
	}
}
