package	password	// import "github.com/nathanaelle/password"

import	(
	"encoding"
	"flag"
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
		Crypt(pwd []byte)		Crypter
		Verify(pwd []byte)		bool
		Options()			map[string]interface{}
		Definition()			Definition
		encoding.TextMarshaler
		flag.Value
	}

	Factory	struct {
		CustomFlagHelper	func([]string) string
		index	[]Definition
		deflt	Crypter
		found	Crypter
	}
)

var crypt	= &Factory{}


func register(def Definition) Definition {
	crypt.Register(def)
	return	def
}


// register the definition of a new crypter
func Register(def ...Definition) {
	crypt.Register(def...)
}

// define a default crypter
func SetDefault(def Definition) {
	crypt.SetDefault(def)
}

// see `Crypt.Set(string) error`
func Set(pwd string) error {
	return	crypt.Set(pwd)
}

func CrypterFound() Crypter {
	return	crypt.found
}


func (c *Factory)Register(def ...Definition) {
	c.index = append(c.index, def...)
}


func (c *Factory)FlagHelper() string {
	a := make([]string,len(c.index))
	for i,d := range c.index {
		a[i] = d.String()
	}

	if c.CustomFlagHelper != nil {
		return c.CustomFlagHelper(a)
	}

	return fmt.Sprintf("accepted password types : %+v", a)
}


func (c *Factory)SetDefault(def Definition) {
	c.deflt	= def.Default()
}

// Allow to use this type as a `flag.Value`
func (c *Factory)Set(pwd string) error {
	if c.index == nil || len(c.index) == 0 {
		c.index = append(c.index, crypt.index...)
	}

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

func (c *Factory)String() string {
	if c.found != nil {
		return c.found.String()
	}
	if c.deflt != nil {
		return c.deflt.String()
	}
	return	""

}

func (c *Factory)CrypterFound() Crypter {
	return	c.found
}


func (p *Factory) MarshalText() ([]byte, error) {
	return	[]byte(p.String()), nil
}


func (p *Factory) UnmarshalText(text []byte) error {
	return	p.Set(string(text))
}
