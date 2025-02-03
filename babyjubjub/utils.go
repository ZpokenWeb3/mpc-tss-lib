package babyjubjub

import (
	"fmt"
	"math/big"
)

// NewIntFromString creates a new big.Int from a decimal integer encoded as a
// string.  It will panic if the string is not a decimal integer.
func NewIntFromString(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 10) //nolint:gomnd
	if !ok {
		panic(fmt.Sprintf("Bad base 10 string %s", s))
	}
	return v
}
