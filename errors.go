package	password

import	(
	"errors"
)

var (
	NoMatchingDef	error	= errors.New("No Matching Definition Found")
	ERR_NOPE	error	= errors.New("NOPE")
)
