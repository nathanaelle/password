package password	// import "github.com/nathanaelle/password"

import	(
	"strings"
	"fmt"
	"crypto/subtle"
	"crypto/md5"
)


type	(
	md5driver	struct{
		prefix	string
	}

	md5pwd	struct{
		prefix	string
		salt	[]byte
		hashed	[22]byte
	}
)

const	(
	md5_def_rounds	= 1000

	md5_prefix	= "$1$"
	apr1_prefix	= "$apr1$"
)

var MD5  Definition	= md5driver{ md5_prefix }
var APR1 Definition	= md5driver{ apr1_prefix }



func (d md5driver)String() string {
	switch d.prefix {
	case	apr1_prefix:
		return	"{APR1-CRYPT}"
	case md5_prefix:
		return	"{MD5-CRYPT}"
	}
	panic(ErrUnknownMD5Prefix)
}

func (d md5driver)Options() map[string]interface{} {
	return	map[string]interface{} {
	}
}

func (d md5driver)SetOptions(o map[string]interface{}) Definition {
	return	md5driver { d.prefix }
}

func (d md5driver)Default() Crypter {
	return &md5pwd{ prefix: d.prefix }
}


func (d md5driver)Crypt(pwd, salt []byte, options map[string]interface{}) string {
	return	d.SetOptions(options).Default().Salt(salt).Crypt(pwd).String()
}

func (d md5driver)CrypterFound(str string)	(Crypter,bool) {
	if _, ok := dispatch_md5_prefix(str); !ok {
		return nil, false
	}

	p := new(md5pwd)
	if err := p.Set(str); err != nil {
		return nil, false
	}

	return p, true
}

func (p *md5pwd)Salt(salt []byte) Crypter {
	if salt == nil || len(salt) == 0 {
		return &md5pwd{ p.prefix, getrandh64(8), p.hashed }
	}
	var s [8]byte

	l := copy(s[:], salt)

	return &md5pwd{ p.prefix, s[0:l], p.hashed }
}

func (p *md5pwd)Hashed(hashed []byte) Crypter {
	var s [22]byte

	if hashed == nil || len(hashed) == 0 {
		return &md5pwd{ p.prefix, p.salt, s }
	}

	copy(s[:], hashed)

	return &md5pwd{ p.prefix, p.salt, s }
}


func (p *md5pwd) Options() map[string]interface{} {
	return p.Definition().Options()
}

func (p *md5pwd) Definition() Definition  {
	return md5driver{}
}


func (p *md5pwd) Crypt(pwd []byte)	Crypter {
	np	:= new(md5pwd)
	*np	= *p

	hashed	:= p.crypt(pwd)
	copy(np.hashed[:], h64Encode(hashed[:]))

	return	np
}


func (p *md5pwd) String() string {
	hashencoded := string(p.hashed[:])
	saltencoded := string(p.salt)

	return fmt.Sprintf(p.prefix+"%s$%s", saltencoded, hashencoded)
}


func (p *md5pwd) Verify(pwd []byte)	bool {
	h := p.crypt(pwd)
	he := h64Encode(h[:])
	return	(subtle.ConstantTimeCompare(he, p.hashed[:]) == 1)
}


func dispatch_md5_prefix(str string) (string,bool) {
	is_md5	:= (len(str) >+ len(md5_prefix) && str[0:len(md5_prefix)] == md5_prefix)
	is_apr1	:= (len(str) >+ len(apr1_prefix) && str[0:len(apr1_prefix)] == apr1_prefix)

	switch	{
	case	is_md5:
		return	md5_prefix, true
	case	is_apr1:
		return	apr1_prefix, true
	}

	return	"", false
}

func (p *md5pwd)Set(str string)	error {
	if p == nil {
		return	ERR_NOPE
	}

	my_prefix, ok := dispatch_md5_prefix(str)
	if !ok {
		return ERR_NOPE
	}

	if len(str) == len(my_prefix) {
		*p = md5pwd{ prefix: my_prefix, }
		return	nil
	}

	list	:= strings.SplitN(str[len(my_prefix):], "$", 3)

	if list[len(list)-1] == "" {
		list	= list[:len(list)-1]
	}

	switch(len(list)) {
	case	1:
		np	:= (&md5pwd{ prefix: my_prefix }).Salt([]byte(list[0]))
		*p = *(np.(*md5pwd))
		return	nil

	case	2:
		np	:= (&md5pwd{ prefix: my_prefix }).Salt([]byte(list[0]))
		*p = *(np.Hashed([]byte(list[1])).(*md5pwd))
		return	nil
	}
	return	ERR_NOPE
}

func (p *md5pwd) MarshalText() ([]byte, error) {
	return	[]byte(p.String()), nil
}


func (p *md5pwd) UnmarshalText(text []byte) error {
	return	p.Set(string(text))
}


func (p *md5pwd) crypt(pwd []byte)	[16]byte {
	var	sumA	[]byte

	sumB	:= common_sum( md5.New(), pwd, p.salt, pwd).Sum(nil)

	if len(pwd) < 1 {
		A	:= common_sum( md5.New(), pwd, []byte(p.prefix), p.salt, repeat_bytes(sumB, len(pwd)) )
		sumA	= common_sum(A, common_mixer(len(pwd), []byte{0}, []byte{0})...).Sum(nil)
	} else {
		A	:= common_sum( md5.New(), pwd, []byte(p.prefix), p.salt, repeat_bytes(sumB, len(pwd)) )
		sumA	= common_sum(A, common_mixer(len(pwd), []byte{0}, pwd[0:1])...).Sum(nil)
	}

	sumC	:= sumA
	for i := 0; i < md5_def_rounds; i++ {
		sumC	= common_sum( md5.New(), common_dispatch(i, sumC, pwd, p.salt)... ).Sum(nil)
	}

	return	[16]byte{
		sumC[12], sumC[6], sumC[0],
		sumC[13], sumC[7], sumC[1],
		sumC[14], sumC[8], sumC[2],
		sumC[15], sumC[9], sumC[3],
		sumC[5], sumC[10], sumC[4],
		sumC[11],
	}
}
