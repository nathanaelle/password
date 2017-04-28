package	password	// import "github.com/nathanaelle/password"

import	(
	"errors"
)

var (
	NoMatchingDef		error	= errors.New("No Matching Definition Found")
	ERR_NOPE		error	= errors.New("NOPE")
	ErrUnknownMD5Prefix	error	= errors.New("Unknown MD5-CRYPT Prefix")
)
