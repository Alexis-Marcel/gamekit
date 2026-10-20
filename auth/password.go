package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Mots de passe : argon2id aux paramètres minimaux recommandés par l'OWASP
// (19 Mio, 2 passes, 1 fil), raisonnables sur un petit serveur. Le format PHC
// garde les paramètres avec l'empreinte : on pourra les relever sans casser
// les mots de passe existants.

const (
	argonMemory  = 19 * 1024 // Kio
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
)

var b64 = base64.RawStdEncoding

func hashPassword(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

var errBadHash = errors.New("empreinte de mot de passe illisible")

func checkPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, errBadHash
	}
	var version int
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, errBadHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, errBadHash
	}
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return false, errBadHash
	}
	want, err := b64.DecodeString(parts[5])
	if err != nil {
		return false, errBadHash
	}
	got := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// dummyHash sert à vérifier un mot de passe même quand le compte n'existe pas :
// la réponse prend le même temps, et ne dit pas quels noms sont pris.
var dummyHash = func() string {
	h, _ := hashPassword("pas un vrai mot de passe")
	return h
}()
