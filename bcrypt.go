package password // import "github.com/nathanaelle/password"

import (
	"crypto/subtle"
	"fmt"
	"golang.org/x/crypto/blowfish"
	"strings"
)

type (
	bcryptdriver struct {
		prefix string
		cost   int
	}

	bcryptpwd struct {
		prefix string
		cost   int
		salt   []byte
		hashed [31]byte
	}
)

const (
	bcrypt_min_cost = 4
	bcrypt_max_cost = 31
	bcrypt_def_cost = 12
)

var (
	orpheanbeholderscrydoubt = []byte("OrpheanBeholderScryDoubt")
	bcrypt_prefix            = [5]string{"$2a$", "$2$", "$2b$", "$2x$", "$2y$"}
)

var BCRYPT Definition = register(bcryptdriver{bcrypt_prefix[0], bcrypt_def_cost})

func (_ bcryptdriver) String() string {
	return "{BLF-CRYPT}"
}

func (d bcryptdriver) Options() map[string]interface{} {
	return map[string]interface{}{
		"cost": d.cost,
	}
}

func (d bcryptdriver) SetOptions(o map[string]interface{}) Definition {
	iv, ok := o["cost"]
	if !ok {
		return d
	}
	v, ok := iv.(int)
	if !ok {
		return d
	}

	return bcryptdriver{d.prefix, bounded(bcrypt_min_cost, v, bcrypt_max_cost)}
}

func (d bcryptdriver) Default() Crypter {
	return &bcryptpwd{
		prefix: d.prefix,
		cost:   d.cost,
	}
}

func (d bcryptdriver) Crypt(pwd, salt []byte, options map[string]interface{}) string {
	return d.SetOptions(options).Default().Salt(salt).Crypt(pwd).String()
}

func (d bcryptdriver) CrypterFound(str string) (Crypter, bool) {
	if _, ok := dispatch_bcrypt_prefix(str); !ok {
		return nil, false
	}

	p := new(bcryptpwd)
	if err := p.Set(str); err != nil {
		return nil, false
	}

	return p, true
}

func (p *bcryptpwd) Salt(salt []byte) Crypter {
	if salt == nil || len(salt) != 22 {
		panic(len(salt))
		return &bcryptpwd{p.prefix, p.cost, getrand(16), p.hashed}
	}
	var s [16]byte
	if _, err := bc64.Decode(s[:], salt); err != nil {
		panic(err)
		return &bcryptpwd{p.prefix, p.cost, getrand(16), p.hashed}
	}

	return &bcryptpwd{p.prefix, p.cost, s[:], p.hashed}
}

func (p *bcryptpwd) Hashed(hashed []byte) Crypter {
	var s [31]byte

	if hashed == nil || len(hashed) != 31 {
		return &bcryptpwd{p.prefix, p.cost, p.salt, s}
	}

	copy(s[:], hashed)

	return &bcryptpwd{p.prefix, p.cost, p.salt, s}
}

func (p *bcryptpwd) Options() map[string]interface{} {
	return p.Definition().Options()
}

func (p *bcryptpwd) Definition() Definition {
	return bcryptdriver{p.prefix, p.cost}
}

func (p *bcryptpwd) Crypt(pwd []byte) Crypter {
	np := new(bcryptpwd)
	*np = *p

	hashed := np.crypt(pwd)
	copy(np.hashed[:], []byte(bc64.EncodeToString(hashed[:])))

	return np
}

func (p *bcryptpwd) String() string {
	hashencoded := string(p.hashed[:])
	saltencoded := bc64.EncodeToString(p.salt)
	if p.cost == bcrypt_def_cost {
		return fmt.Sprintf(p.prefix+"%s%s", saltencoded, hashencoded)

	}
	return fmt.Sprintf(p.prefix+"%02d$%s%s", p.cost, saltencoded, hashencoded)
}

func (p *bcryptpwd) Verify(pwd []byte) bool {
	h := p.crypt(pwd)
	he := []byte(bc64.EncodeToString(h[:]))
	return (subtle.ConstantTimeCompare(he, p.hashed[:]) == 1)
}

func dispatch_bcrypt_prefix(str string) (string, bool) {
	for _, prefix := range bcrypt_prefix {
		if len(str) >= len(prefix) && str[0:len(prefix)] == prefix {
			return prefix, true
		}
	}

	return "", false
}

func (p *bcryptpwd) Set(str string) error {
	if p == nil {
		return ERR_NOPE
	}

	prefix, ok := dispatch_bcrypt_prefix(str)
	if !ok {
		return ERR_NOPE
	}

	if len(str) == len(prefix) {
		*p = bcryptpwd{prefix: prefix, cost: bcrypt_def_cost}
		return nil
	}

	list := strings.SplitN(str[len(prefix):], "$", 2)

	if list[len(list)-1] == "" {
		list = list[:len(list)-1]
	}

	opt := options_single_int(list[0], "cost", 2)
	if opt == nil {
		np := (&bcryptpwd{prefix: prefix, cost: bcrypt_def_cost})
		blob := []byte(list[0])
		switch len(blob) {
		case 22:
			*p = *(np.Salt(blob[0:22]).(*bcryptpwd))
			return nil

		case 53:
			*p = *(np.Salt(blob[0:22]).Hashed(blob[22:53]).(*bcryptpwd))
			return nil
		}
		return ERR_NOPE
	}

	sr, ok := option_int(opt, "cost", bcrypt_def_cost)
	if !ok {
		return ERR_NOPE
	}

	np := (&bcryptpwd{prefix: prefix, cost: bounded(bcrypt_min_cost, sr, bcrypt_max_cost)})
	if len(list) == 1 {
		*p = *np
		return nil
	}

	blob := []byte(list[1])
	switch len(blob) {
	case 22:
		*p = *(np.Salt(blob[0:22]).(*bcryptpwd))
		return nil

	case 53:
		*p = *(np.Salt(blob[0:22]).Hashed(blob[22:53]).(*bcryptpwd))
		return nil
	}

	return ERR_NOPE
}

func (p *bcryptpwd) crypt(pwd []byte) (ret [23]byte) {
	var obsd [24]byte

	copy(obsd[:], orpheanbeholderscrydoubt[:])

	bfc, err := bcryptSetup(append(pwd, 0), p.salt, uint(p.cost))
	if err != nil {
		panic(err)
	}

	for i := 0; i < 64; i++ {
		bfc.Encrypt(obsd[0:8], obsd[0:8])
		bfc.Encrypt(obsd[8:16], obsd[8:16])
		bfc.Encrypt(obsd[16:24], obsd[16:24])
	}
	copy(ret[:], obsd[:])

	return
}

func bcryptSetup(pwd []byte, salt []byte, cost uint) (*blowfish.Cipher, error) {
	bfcipher, err := blowfish.NewSaltedCipher(pwd, salt)
	if err != nil {
		return nil, err
	}

	for rounds := 1 << cost; rounds > 0; rounds-- {
		blowfish.ExpandKey(pwd, bfcipher)
		blowfish.ExpandKey(salt, bfcipher)
	}

	return bfcipher, nil
}

func (p *bcryptpwd) MarshalText() ([]byte, error) {
	return []byte(p.String()), nil
}
