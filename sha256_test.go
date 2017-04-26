package	password	// import "github.com/nathanaelle/password"

import	(
	"testing"
)

var (
	result_sha256	[]testresult = []testresult{
		{ "$5$saltstring", "Hello world!",					"$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5" },
		{ "$5$rounds=10000$saltstringsaltstring", "Hello world!",		"$5$rounds=10000$saltstringsaltst$3xv.VbSHBb41AL9AvLeujZkZRBAwqFMz2.opqey6IcA" },
		{ "$5$rounds=5000$toolongsaltstring", "This is just a test",		"$5$toolongsaltstrin$Un/5jzAHMgOGZ5.mWJpuVolil07guHPvOW8mGRcvxa5" },
		{ "$5$rounds=123456$asaltof16chars..", "a short string",		"$5$rounds=123456$asaltof16chars..$gP3VQ/6X7UUEW3HkBn2w1/Ptq2jxPyzV/cZKmF/wJvD" },
		{ "$5$rounds=10$roundstoolow", "the minimum number is still observed",	"$5$rounds=1000$roundstoolow$yfvwcWrQ8l/K0DAWyuPMDNHpIVlTQebY9l/gL972bIC" },
		{ "$5$rounds=1400$anotherlongsaltstring", "a very much longer text to encrypt.  This one even stretches over morethan one line.", "$5$rounds=1400$anotherlongsalts$Rx.j8H.h8HjEDGomFU8bDkXm3XIUnzyxf12oP84Bnq1" },
		{ "$5$rounds=77777$short", "we have a short salt string but not a short password", "$5$rounds=77777$short$JiO1O3ZpDAxGJeaDIuqCoEFysAe1mZNJRs3pw0KQRd/" },
	}

	valid_sha256	[]testvalid = []testvalid{
		{ "", ERR_NOPE },
		{ "$", ERR_NOPE },
		{ "$$", ERR_NOPE },
		{ "$0$", ERR_NOPE },
		{ "$5$rounds=xyz$", ERR_NOPE },
		{ "$5$", nil },
		{ "$5$saltstring", nil },
		{ "$5$rounds=10000$", nil },
		{ "$5$rounds=10000$saltstringsaltstring", nil },
		{ "$5$rounds=5000$toolongsaltstring", nil },
		{ "$5$rounds=123456$asaltof16chars..", nil },
		{ "$5$rounds=10$roundstoolow", nil },
		{ "$5$rounds=1400$anotherlongsaltstring", nil },
		{ "$5$rounds=77777$short", nil },
	}
)

func TestDefSHA256Result(t *testing.T) {
	for idx, seq := range result_sha256 {
		if _, ok := SHA256.CrypterFound(seq.output); !ok {
			t.Errorf("%3d : invalid\t%s", idx, seq.output)
		}

		if _, ok := SHA256.CrypterFound(seq.salt); !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
		}
	}
}


func TestDefSHA256Valid(t *testing.T) {
	for idx, seq := range valid_sha256 {
		if _, ok := SHA256.CrypterFound(seq.input); ok != (seq.err == nil) {
			t.Errorf("%3d : bogus valid\t%s", idx, seq.input)
		}
	}

	for idx, seq := range valid_sha256 {
		if err := SHA256.Default().Set(seq.input); err != seq.err {
			t.Errorf("%3d : bogus err [%s] %v %v", idx, seq.input, seq.err, err)
		}
	}
}


func TestCrypterSHA256Crypt(t *testing.T) {
	for idx, seq := range result_sha256 {
		crypter, ok := SHA256.CrypterFound(seq.salt)
		if !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
			continue
		}

		out := crypter.Crypt([]byte(seq.input)).String()
		if out != seq.output {
			t.Errorf("-- %d\n%80s\n%80s", idx, out, seq.output)
		}
	}
}

func TestCrypterSHA256Verify(t *testing.T) {
	for idx, seq := range result_sha256 {
		crypter, ok := SHA256.CrypterFound(seq.output)
		if !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
			continue
		}

		if !crypter.Verify([]byte(seq.input)) {
			t.Errorf("-- %d don't match\n%80s\n%80s", idx, crypter.Crypt([]byte(seq.input)), seq.output)
		}
	}
}
