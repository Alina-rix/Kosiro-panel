package adminkey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
)

var formatRe = regexp.MustCompile(`^A_R:[A-Za-z0-9._-]+#\d{6}$`)

// Valid reports whether s matches the Kosiro admin key format.
func Valid(s string) bool {
	return formatRe.MatchString(s)
}

// Generate builds A_R:SRV-<slug>#<6digits> from host and install secret.
func Generate(publicHost, installSecret string) (string, error) {
	sum := sha256.Sum256([]byte(publicHost + ":" + installSecret))
	slug := hex.EncodeToString(sum[:3])
	n, err := rand.Int(rand.Reader, big.NewInt(900000))
	if err != nil {
		return "", err
	}
	id := int(n.Int64()) + 100000
	return fmt.Sprintf("A_R:SRV-%s#%06d", slug, id), nil
}

// Equal compares two keys in constant time when lengths match.
func Equal(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
