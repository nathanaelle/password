package password // import "github.com/nathanaelle/password/v2"

import (
	"crypto/sha512"
	"crypto/subtle"
	"fmt"
	"strings"
)

type (
	sha512driver struct {
		rounds int
	}

	sha512pwd struct {
		rounds int
		salt   []byte
		hashed [86]byte
	}
)

const (
	sha512MinRounds = 1000
	sha512MaxRounds = 999999999
	sha512DefRounds = 5000

	sha512Prefix = "$6$"
)

// SHA512 is the exported driver for SHA512-CRYPT
var SHA512 = register(sha512driver{sha512DefRounds})

func (d sha512driver) String() string {
	return "{SHA512-CRYPT}"
}

func (d sha512driver) Options() map[string]interface{} {
	return map[string]interface{}{
		"rounds": d.rounds,
	}
}

func (d sha512driver) SetOptions(o map[string]interface{}) Definition {
	iv, ok := o["rounds"]
	if !ok {
		return d
	}
	v, ok := iv.(int)
	if !ok {
		return d
	}

	return sha512driver{bounded(sha512MinRounds, v, sha512MaxRounds)}
}

func (d sha512driver) Default() Crypter {
	return &sha512pwd{
		rounds: d.rounds,
	}
}

func (d sha512driver) Crypt(pwd, salt []byte, options map[string]interface{}) string {
	return d.SetOptions(options).Default().Salt(salt).Crypt(pwd).String()
}

func (d sha512driver) CrypterFound(str string) (Crypter, bool) {
	if len(str) < len(sha512Prefix) || str[0:len(sha512Prefix)] != sha512Prefix {
		return nil, false
	}

	p := new(sha512pwd)
	if err := p.Set(str); err != nil {
		return nil, false
	}

	return p, true
}

func (p *sha512pwd) Salt(salt []byte) Crypter {
	if salt == nil || len(salt) == 0 {
		return &sha512pwd{p.rounds, getrandh64(16), p.hashed}
	}
	var s [16]byte

	l := copy(s[:], salt)

	return &sha512pwd{p.rounds, s[0:l], p.hashed}
}

func (p *sha512pwd) Hashed(hashed []byte) Crypter {
	var s [86]byte

	if hashed == nil || len(hashed) == 0 {
		return &sha512pwd{p.rounds, p.salt, s}
	}

	copy(s[:], hashed)

	return &sha512pwd{p.rounds, p.salt, s}
}

func (p *sha512pwd) Options() map[string]interface{} {
	return p.Definition().Options()
}

func (p *sha512pwd) Definition() Definition {
	return sha512driver{p.rounds}
}

func (p *sha512pwd) Crypt(pwd []byte) Crypter {
	np := new(sha512pwd)
	*np = *p

	hashed := p.crypt(pwd)
	copy(np.hashed[:], h64Encode(hashed[:]))

	return np
}

func (p *sha512pwd) String() string {
	hashencoded := string(p.hashed[:])
	saltencoded := string(p.salt)

	if p.rounds == sha512DefRounds {
		return fmt.Sprintf(sha512Prefix+"%s$%s", saltencoded, hashencoded)

	}
	return fmt.Sprintf(sha512Prefix+"rounds=%d$%s$%s", p.rounds, saltencoded, hashencoded)
}

func (p *sha512pwd) Verify(pwd []byte) bool {
	if pwd == nil || len(pwd) == 0 {
		return false
	}

	h := p.crypt(pwd)
	he := h64Encode(h[:])
	return (subtle.ConstantTimeCompare(he, p.hashed[:]) == 1)
}

func (p *sha512pwd) Set(str string) error {
	if p == nil {
		return ERR_NOPE
	}

	if len(str) < len(sha512Prefix) || str[0:len(sha512Prefix)] != sha512Prefix {
		return ERR_NOPE
	}

	if len(str) == len(sha512Prefix) {
		*p = sha512pwd{rounds: sha512DefRounds}
		return nil
	}

	list := strings.SplitN(str[len(sha512Prefix):], "$", 3)

	if list[len(list)-1] == "" {
		list = list[:len(list)-1]
	}

	opt := options(list[0])
	if opt == nil {
		np := (&sha512pwd{rounds: sha512DefRounds}).Salt([]byte(list[0]))
		switch len(list) {
		case 1:
			*p = *(np.(*sha512pwd))
			return nil

		case 2:
			*p = *(np.Hashed([]byte(list[1])).(*sha512pwd))
			return nil
		}
		return ERR_NOPE
	}

	sr, ok := optionInt(opt, "rounds", sha512DefRounds)
	if !ok {
		return ERR_NOPE
	}

	np := (&sha512pwd{rounds: bounded(sha512MinRounds, sr, sha512MaxRounds)})
	switch len(list) {
	case 1:
		*p = *np
		return nil

	case 2:
		*p = *(np.Salt([]byte(list[1])).(*sha512pwd))
		return nil

	case 3:
		*p = *(np.Salt([]byte(list[1])).Hashed([]byte(list[2])).(*sha512pwd))
		return nil
	}

	return ERR_NOPE
}

func (p *sha512pwd) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}

func (p *sha512pwd) crypt(pwd []byte) [64]byte {
	sumB := commonSum(sha512.New(), pwd, p.salt, pwd).Sum(nil)

	A := commonSum(sha512.New(), pwd, p.salt, repeatBytes(sumB, len(pwd)))
	sumA := commonSum(A, commonMixer(len(pwd), sumB, pwd)...).Sum(nil)

	sumP := repeatBytes(commonSum(sha512.New(), multiplyBytes(pwd, len(pwd))...).Sum(nil), len(pwd))
	sumS := repeatBytes(commonSum(sha512.New(), multiplyBytes(p.salt, (16+int(sumA[0])))...).Sum(nil), len(p.salt))

	sumC := sumA
	for i := 0; i < p.rounds; i++ {
		sumC = commonSum(sha512.New(), commonDispatch(i, sumC, sumP, sumS)...).Sum(nil)
	}

	return [64]byte{
		sumC[42], sumC[21], sumC[0],
		sumC[1], sumC[43], sumC[22],
		sumC[23], sumC[2], sumC[44],
		sumC[45], sumC[24], sumC[3],
		sumC[4], sumC[46], sumC[25],
		sumC[26], sumC[5], sumC[47],
		sumC[48], sumC[27], sumC[6],
		sumC[7], sumC[49], sumC[28],
		sumC[29], sumC[8], sumC[50],
		sumC[51], sumC[30], sumC[9],
		sumC[10], sumC[52], sumC[31],
		sumC[32], sumC[11], sumC[53],
		sumC[54], sumC[33], sumC[12],
		sumC[13], sumC[55], sumC[34],
		sumC[35], sumC[14], sumC[56],
		sumC[57], sumC[36], sumC[15],
		sumC[16], sumC[58], sumC[37],
		sumC[38], sumC[17], sumC[59],
		sumC[60], sumC[39], sumC[18],
		sumC[19], sumC[61], sumC[40],
		sumC[41], sumC[20], sumC[62],
		sumC[63],
	}
}
