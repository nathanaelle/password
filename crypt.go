package	password

import	(
	"fmt"
)

type	(
	Definition	interface {
		String()		string
		CrypterFound(string)	(Crypter,bool)
		Options()		map[string]interface{}
		Default()		Crypter

		SetOptions(map[string]interface{})	Definition

		Crypt(pwd, salt []byte, options map[string]interface{})	string
	}

	Crypter	interface {
		Salt(salt []byte)		Crypter
		Hashed(pwd []byte)		Crypter
		Set(pwd string) 		error
		Crypt(pwd []byte)		string
		Verify(pwd []byte)		bool
		Options()			map[string]interface{}
		Definition()			Definition
	}

	Crypt	struct {
		index	[]Definition
		deflt	Crypter
		found	Crypter
	}
)

var	(
	NoMatchingDef	error	= fmt.Errorf("No Matching Definition Found")

	crypt	*Crypt	= &Crypt{
	}
)

func register(def Definition) Definition {
	crypt.Register(def)
	return	def
}


func Register(def ...Definition) {
	crypt.Register(def...)
}

func SetDefault(def Definition) {
	crypt.SetDefault(def)
}

func Set(pwd string) error {
	return	crypt.Set(pwd)
}


func (c *Crypt)Register(def ...Definition) {
	c.index = append(c.index, def...)
}


func (c *Crypt)SetDefault(def Definition) {
	c.deflt	= def.Default()
}

func (c *Crypt)Set(pwd string) error {
	for _,i := range c.index {
		if crypter, ok := i.CrypterFound(pwd); ok {
			c.found = crypter
			return nil
		}
	}

	if c.deflt != nil {
		c.found = c.deflt
		return nil
	}

	return	NoMatchingDef
}
