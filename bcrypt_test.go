package password // import "github.com/nathanaelle/password"

import (
	"testing"
)

var (
	// test vectors from https://bitbucket.org/vadim/bcrypt.net/src/464c41416dc9/BCrypt.Net.Test/TestBCrypt.cs?fileviewer=file-view-default
	result_bcrypt []testresult = []testresult{
		{"$2$06$DCq7YPn5Rq63x1Lad4cll.", "", "$2$06$DCq7YPn5Rq63x1Lad4cll.TV4S6ytwfsfvkgY8jIucDrjc8deX1s."},
		{"$2a$08$HqWuK6/Ng6sg9gQzbLrgb.", "", "$2a$08$HqWuK6/Ng6sg9gQzbLrgb.Tl.ZHfXLhvt/SgVyWhQqgqcZ7ZuUtye"},
		{"$2a$10$k1wbIrmNyFAPwPVPSVa/ze", "", "$2a$10$k1wbIrmNyFAPwPVPSVa/zecw2BCEnBwVS2GbrmgzxFUOqW9dk4TCW"},
		{"$2a$12$k42ZFHFWqBp3vWli.nIn8u", "", "$2a$k42ZFHFWqBp3vWli.nIn8uYyIkbvYRvodzbfbK18SSsY.CsIQPlxO"},
		{"$2a$06$m0CrhHm10qJ3lXRY.5zDGO", "a", "$2a$06$m0CrhHm10qJ3lXRY.5zDGO3rS2KdeeWLuGmsfGlMfOxih58VYVfxe"},
		{"$2a$08$cfcvVd2aQ8CMvoMpP2EBfe", "a", "$2a$08$cfcvVd2aQ8CMvoMpP2EBfeodLEkkFJ9umNEfPD18.hUF62qqlC/V."},
		{"$2a$10$k87L/MF28Q673VKh8/cPi.", "a", "$2a$10$k87L/MF28Q673VKh8/cPi.SUl7MU/rWuSiIDDFayrKk/1tBsSQu4u"},
		{"$2a$12$8NJH3LsPrANStV6XtBakCe", "a", "$2a$8NJH3LsPrANStV6XtBakCez0cKHXVxmvxIlcz785vxAIZrihHZpeS"},
		{"$2a$06$If6bvum7DFjUnE9p2uDeDu", "abc", "$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i"},
		{"$2a$08$Ro0CUfOqk6cXEKf3dyaM7O", "abc", "$2a$08$Ro0CUfOqk6cXEKf3dyaM7OhSCvnwM9s4wIX9JeLapehKK5YdLxKcm"},
		{"$2a$10$WvvTPHKwdBJ3uk0Z37EMR.", "abc", "$2a$10$WvvTPHKwdBJ3uk0Z37EMR.hLA2W6N9AEBhEgrAOljy2Ae5MtaSIUi"},
		{"$2a$12$EXRkfkdmXn2gzds2SSitu.", "abc", "$2a$EXRkfkdmXn2gzds2SSitu.MW9.gAVqa9eLS1//RYtYCmB1eLHg.9q"},
		{"$2a$06$.rCVZVOThsIa97pEDOxvGu", "abcdefghijklmnopqrstuvwxyz", "$2a$06$.rCVZVOThsIa97pEDOxvGuRRgzG64bvtJ0938xuqzv18d3ZpQhstC"},
		{"$2a$08$aTsUwsyowQuzRrDqFflhge", "abcdefghijklmnopqrstuvwxyz", "$2a$08$aTsUwsyowQuzRrDqFflhgekJ8d9/7Z3GV3UcgvzQW3J5zMyrTvlz."},
		{"$2a$10$fVH8e28OQRj9tqiDXs1e1u", "abcdefghijklmnopqrstuvwxyz", "$2a$10$fVH8e28OQRj9tqiDXs1e1uxpsjN0c7II7YPKXua2NAKYvM6iQk7dq"},
		{"$2a$12$D4G5f18o7aMMfwasBL7Gpu", "abcdefghijklmnopqrstuvwxyz", "$2a$D4G5f18o7aMMfwasBL7GpuQWuP3pkrZrOAnqP.bmezbMng.QwJ/pG"},
		{"$2a$06$fPIsBO8qRqkjj273rfaOI.", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$06$fPIsBO8qRqkjj273rfaOI.HtSV9jLDpTbZn782DC6/t7qT67P6FfO"},
		{"$2a$08$Eq2r4G/76Wv39MzSX262hu", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$08$Eq2r4G/76Wv39MzSX262huzPz612MZiYHVUJe/OcOql2jo4.9UxTW"},
		{"$2a$10$LgfYWkbzEvQ4JakH7rOvHe", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$10$LgfYWkbzEvQ4JakH7rOvHe0y8pHKF9OaFgwUZ2q7W2FFZmZzJYlfS"},
		{"$2a$12$WApznUOJfkEGSmYRfnkrPO", "~!@#$%^&*()      ~!@#$%^&*()PNBFRD", "$2a$WApznUOJfkEGSmYRfnkrPOr466oFDCaj4b6HY3EXGvfxm43seyhgC"},
	}

	valid_bcrypt []testvalid = []testvalid{
		{"", ERR_NOPE},
		{"$", ERR_NOPE},
		{"$$", ERR_NOPE},
		{"$0$", ERR_NOPE},
		{"$2a$rounds", ERR_NOPE},
		{"$2$", nil},
		{"$2a$", nil},
		{"$2b$", nil},
		{"$2x$", nil},
		{"$2y$", nil},
		{"$2a$1234567890123456789012", nil},
	}
)

func TestDefBCRYPTResult(t *testing.T) {
	for idx, seq := range result_bcrypt {
		if _, ok := BCRYPT.CrypterFound(seq.output); !ok {
			t.Errorf("%3d : invalid\t%s", idx, seq.output)
		}

		if _, ok := BCRYPT.CrypterFound(seq.salt); !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
		}
	}
}

func TestDefBCRYPTValid(t *testing.T) {
	for idx, seq := range valid_bcrypt {
		if _, ok := BCRYPT.CrypterFound(seq.input); ok != (seq.err == nil) {
			t.Errorf("%3d : bogus valid\t%s", idx, seq.input)
		}
	}

	for idx, seq := range valid_bcrypt {
		if err := BCRYPT.Default().Set(seq.input); err != seq.err {
			t.Errorf("%3d : bogus err [%s] %v %v", idx, seq.input, seq.err, err)
		}
	}
}

func TestCrypterBCRYPTCrypt(t *testing.T) {
	for idx, seq := range result_bcrypt {
		crypter, ok := BCRYPT.CrypterFound(seq.salt)
		if !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
			continue
		}

		out := crypter.Crypt([]byte(seq.input)).String()
		if out != seq.output {
			t.Errorf("-- %d\n[%60s]\n[%60s]", idx, out, seq.output)
		}
	}
}

func TestCrypterBCRYPTVerify(t *testing.T) {
	for idx, seq := range result_bcrypt {
		crypter, ok := BCRYPT.CrypterFound(seq.output)
		if !ok {
			t.Errorf("%3d : invalid\t%20s", idx, seq.salt)
			continue
		}

		if !crypter.Verify([]byte(seq.input)) {
			t.Errorf("-- %d don't match\n[%60s]\n[%60s]", idx, crypter.Crypt([]byte(seq.input)), seq.output)
		}
	}
}
