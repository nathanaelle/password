package	password	// import "github.com/nathanaelle/password"

import	(
	"hash"
	"crypto/rand"
	"strings"
	"fmt"
	"strconv"
	"encoding/base64"
)


var rawbase64	= base64.RawStdEncoding
var bc64	= base64.NewEncoding("./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789").WithPadding(base64.NoPadding)

func getrand(l int) []byte {
	if l<1 || l>65536 {
		panic("get rand size <l> is not valid")
	}

	ret := make([]byte, l)
	_, err := rand.Read(ret)
	if err != nil {
		panic(err)
	}

	return	ret
}



func getrandh64(l int) []byte {
	if l<1 || l>65536 {
		panic("get rand size <l> is not valid")
	}

	t := make([]byte, l)
	_, err := rand.Read(t)
	if err != nil {
		panic(err)
	}

	ret := h64Encode(t)

	return	ret[:l]
}


func options_single_int(str, opt_name string, max_len int) map[string]interface{} {
	if str == "" {
		return	nil
	}

	if len(str) > max_len {
		return	nil
	}

	v,err := strconv.Atoi(str)
	if err != nil {
		return	nil
	}
	ret	:= make(map[string]interface{})
	ret[opt_name] = v

	return	ret
}

func options(str string) map[string]interface{} {
	if str == "" {
		return	nil
	}

	if !strings.Contains(str, "=") {
		return	nil
	}

	list	:= strings.Split(str, ",")
	ret	:= make(map[string]interface{})

	for _, tok := range list {
		kv := strings.SplitN(tok, "=", 2)
		if len(kv) == 2 {
			ret[kv[0]] = kv[1]
		}
	}

	return	ret
}

func option_int(opt map[string]interface{}, k string, def int) (int,bool) {
	if opt == nil {
		return	def, true
	}

	ienc,ok := opt[k]
	if !ok {
		return	def, true
	}

	switch enc := ienc.(type) {
	case string:
		v,err := strconv.Atoi(enc)
		if err != nil {
			return	0,false
		}
		return	v,true

	case	int:
		return	enc,true
	}
	return	0,false
}



func assert(t bool, i interface{})  {
	if !t {
		panic(i)
	}
}

func bounded(min, v, max int) int {
	if v < min {
		return	min
	}
	if v > max {
		return	max
	}
	return	v
}

func repeat_bytes(src []byte, l_dest int) []byte {
	dest	:= make([]byte, 0, l_dest)
	l_src	:= len(src)
	mod	:= l_dest % l_src
	rounds	:= (l_dest-mod)

	if rounds > 0 {
		for i := 0; i < rounds; i += l_src {
			dest = append(dest, src...)
		}
	}

	if mod != 0 {
		dest = append(dest, src[0:mod]...)
	}

	assert( len(dest) == l_dest, fmt.Errorf("l_dest [%d] != len(dest) [%d] l_src [%d]", l_dest, len(dest), l_src))

	return	dest
}

func multiply_bytes(src []byte, scalar int) [][]byte {
	ret := make([][]byte, scalar)
	for i,_ := range ret {
		ret[i]	= src
	}

	return	ret
}


const (
	h64	string = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
)

func h64Encode(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}

	hashSize := len(src) * 4 / 3
	if (len(src) % 3) != 0 {
		hashSize += 1
	}
	hash := make([]byte, hashSize)

	dst := hash
	for len(src) > 0 {
		switch len(src) {
		default:
			dst[0] = h64[src[0]&0x3f]
			dst[1] = h64[((src[0]>>6)|(src[1]<<2))&0x3f]
			dst[2] = h64[((src[1]>>4)|(src[2]<<4))&0x3f]
			dst[3] = h64[(src[2]>>2)&0x3f]
			src = src[3:]
			dst = dst[4:]
		case 2:
			dst[0] = h64[src[0]&0x3f]
			dst[1] = h64[((src[0]>>6)|(src[1]<<2))&0x3f]
			dst[2] = h64[(src[1]>>4)&0x3f]
			src = src[2:]
			dst = dst[3:]
		case 1:
			dst[0] = h64[src[0]&0x3f]
			dst[1] = h64[(src[0]>>6)&0x3f]
			src = src[1:]
			dst = dst[2:]
		}
	}

	return hash
}


// used in SHA256-CRYPT SHA512-CRYPT MD5-CRYPT
func common_sum(h hash.Hash, vec ...[]byte) hash.Hash {
	for _, s := range vec {
		h.Write(s)
	}

	return	h
}

// used in SHA256-CRYPT SHA512-CRYPT
func common_dispatch(i int, sumC, sumP, sumS []byte) [][]byte {
	if i%42 == 0 {
		return [][]byte{ sumC, sumP }
	}
	if i%21 == 0 {
		return [][]byte{ sumP, sumC }
	}
	if i%14 == 0 {
		return [][]byte{ sumC, sumS, sumP }
	}
	if i%7 == 0 {
		return [][]byte{ sumP, sumS, sumC }
	}
	if i%6 == 0 {
		return [][]byte{ sumC, sumP, sumP }
	}
	if i%3 == 0 {
		return [][]byte{ sumP, sumP, sumC }
	}
	if i%2 == 0 {
		return [][]byte{ sumC, sumS, sumP, sumP }
	}
	return [][]byte{ sumP, sumS, sumP, sumC }
}

func common_mixer(l int, caseA, caseB []byte) (ret [][]byte) {
	for i := l; i > 0; i >>= 1 {
		if (i%2) != 0 {
			ret = append(ret, caseA)
		} else {
			ret = append(ret, caseB)
		}
	}
	return
}
