package password	// import "github.com/nathanaelle/password"

import	(
	"strings"
	"fmt"
	"crypto/subtle"
	"crypto/sha256"
)


type	(
	sha256driver	struct{
		rounds	int
	}

	sha256pwd	struct{
		rounds	int
		salt	[]byte
		hashed	[43]byte
	}
)

const	(
	sha256_min_rounds	= 1000
	sha256_max_rounds	= 999999999
	sha256_def_rounds	= 5000

	sha256_prefix		= "$5$"
)



var SHA256	Definition	= register( sha256driver{ sha256_def_rounds } )



func (_ sha256driver)String() string {
	return	"{SHA256-CRYPT}"
}

func (d sha256driver)Options() map[string]interface{} {
	return	map[string]interface{} {
		"rounds":	d.rounds,
	}
}

func (d sha256driver)SetOptions(o map[string]interface{}) Definition {
	iv, ok	:= o["rounds"]
	if !ok {
		return	d
	}
	v, ok	:= iv.(int)
	if !ok {
		return	d
	}

	return	sha256driver { bounded(sha256_min_rounds, v, sha256_max_rounds) }
}

func (d sha256driver)Default() Crypter {
	return &sha256pwd{
		rounds: d.rounds,
	}
}


func (d sha256driver)Crypt(pwd, salt []byte, options map[string]interface{}) string {
	return	d.SetOptions(options).Default().Salt(salt).Crypt(pwd).String()
}

func (d sha256driver)CrypterFound(str string)	(Crypter,bool) {
	if len(str) < len(sha256_prefix) || str[0:len(sha256_prefix)] != sha256_prefix {
		return nil, false
	}

	p := new(sha256pwd)
	if err := p.Set(str); err != nil {
		return nil, false
	}

	return p, true
}

func (p *sha256pwd)Salt(salt []byte) Crypter {
	if salt == nil || len(salt) == 0 {
		return &sha256pwd{ p.rounds, getrandh64(16), p.hashed }
	}
	var s [16]byte

	l := copy(s[:], salt)

	return &sha256pwd{ p.rounds, s[0:l], p.hashed }
}

func (p *sha256pwd)Hashed(hashed []byte) Crypter {
	var s [43]byte

	if hashed == nil || len(hashed) == 0 {
		return &sha256pwd{ p.rounds, p.salt, s }
	}

	copy(s[:], hashed)

	return &sha256pwd{ p.rounds, p.salt, s }
}


func (p *sha256pwd) Options() map[string]interface{} {
	return p.Definition().Options()
}

func (p *sha256pwd) Definition() Definition  {
	return sha256driver{ p.rounds }
}


func (p *sha256pwd) Crypt(pwd []byte)	Crypter {
	np	:= new(sha256pwd)
	*np	= *p

	hashed	:= p.crypt(pwd)
	copy(np.hashed[:], h64Encode(hashed[:]))

	return	np
}


func (p *sha256pwd) String() string {
	hashencoded := string(p.hashed[:])
	saltencoded := string(p.salt)

	if p.rounds == sha256_def_rounds {
		return fmt.Sprintf(sha256_prefix+"%s$%s", saltencoded, hashencoded)

	}
	return fmt.Sprintf(sha256_prefix+"rounds=%d$%s$%s", p.rounds, saltencoded, hashencoded)
}


func (p *sha256pwd) Verify(pwd []byte)	bool {
	if pwd == nil || len(pwd) == 0 {
		return	false
	}

	h := p.crypt(pwd)
	he := h64Encode(h[:])
	return	(subtle.ConstantTimeCompare(he, p.hashed[:]) == 1)
}


func (p *sha256pwd)Set(str string)	error {
	if p == nil {
		return	ERR_NOPE
	}

	if len(str) < len(sha256_prefix) || str[0:len(sha256_prefix)] != sha256_prefix {
		return	ERR_NOPE
	}

	if len(str) == len(sha256_prefix) {
		*p = sha256pwd{ rounds: sha256_def_rounds }
		return	nil
	}

	list	:= strings.SplitN(str[len(sha256_prefix):], "$", 3)

	if list[len(list)-1] == "" {
		list	= list[:len(list)-1]
	}

	opt := options(list[0])
	if opt == nil {
		np	:= (&sha256pwd{ rounds: sha256_def_rounds }).Salt([]byte(list[0]))
		switch(len(list)) {
		case	1:
			*p = *(np.(*sha256pwd))
			return	nil

		case	2:
			*p = *(np.Hashed([]byte(list[1])).(*sha256pwd))
			return	nil
		}
		return	ERR_NOPE
	}

	sr, ok	:= option_int(opt, "rounds", sha256_def_rounds)
	if !ok {
		return	ERR_NOPE
	}

	np	:= (&sha256pwd{ rounds: bounded(sha256_min_rounds, sr, sha256_max_rounds) })
	switch(len(list)) {
	case	1:
		*p = *np
		return	nil

	case	2:
		*p = *(np.Salt([]byte(list[1])).(*sha256pwd))
		return	nil

	case	3:
		*p = *(np.Salt([]byte(list[1])).Hashed([]byte(list[2])).(*sha256pwd))
		return	nil
	}

	return ERR_NOPE
}

func (p *sha256pwd) MarshalText() ([]byte, error) {
	return	[]byte(p.String()), nil
}

func (p *sha256pwd) crypt(pwd []byte)	[32]byte {
	sumB	:= common_sum( sha256.New(), pwd, p.salt, pwd).Sum(nil)

	A	:= common_sum( sha256.New(), pwd, p.salt, repeat_bytes(sumB, len(pwd)) )
	sumA	:= common_sum(A, common_mixer(len(pwd), sumB, pwd)...).Sum(nil)

	sumP	:= repeat_bytes( common_sum( sha256.New(), multiply_bytes(pwd, len(pwd))... ).Sum(nil), len(pwd) )
	sumS	:= repeat_bytes( common_sum( sha256.New(), multiply_bytes(p.salt, (16+int(sumA[0])) )... ).Sum(nil), len(p.salt) )

	sumC	:= sumA
	for i := 0; i < p.rounds; i++ {
		sumC	= common_sum( sha256.New(), common_dispatch(i, sumC, sumP, sumS)... ).Sum(nil)
	}

	return	[32]byte{
		sumC[20], sumC[10], sumC[0],
		sumC[11], sumC[1], sumC[21],
		sumC[2], sumC[22], sumC[12],
		sumC[23], sumC[13], sumC[3],
		sumC[14], sumC[4], sumC[24],
		sumC[5], sumC[25], sumC[15],
		sumC[26], sumC[16], sumC[6],
		sumC[17], sumC[7], sumC[27],
		sumC[8], sumC[28], sumC[18],
		sumC[29], sumC[19], sumC[9],
		sumC[30], sumC[31],
	}
}
