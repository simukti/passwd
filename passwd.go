// Copyright (c) 2016 - Sarjono Mukti Aji <me@simukti.net>
// Unless otherwise noted, this source code license is MIT-License

// Generate and validate password hash using libsodium crypto_pwhash_*, and bcrypt
package passwd

// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"
import (
	"golang.org/x/crypto/bcrypt"
	"unsafe"
)

var (
	// available public var
	ScryptOpsLimitInteractive  = ScryptLimit(C.crypto_pwhash_scryptsalsa208sha256_opslimit_interactive())
	ScryptMemLimitInteractive  = ScryptLimit(C.crypto_pwhash_scryptsalsa208sha256_memlimit_interactive())
	ScryptOpsLimitSensitive    = ScryptLimit(C.crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive())
	ScryptMemLimitSensitive    = ScryptLimit(C.crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive())
	Argon2iOpsLimitInteractive = ArgonLimit(C.crypto_pwhash_opslimit_interactive())
	Argon2iMemLimitInteractive = ArgonLimit(C.crypto_pwhash_memlimit_interactive())
	Argon2iOpsLimitModerate    = ArgonLimit(C.crypto_pwhash_opslimit_moderate())
	Argon2iMemLimitModerate    = ArgonLimit(C.crypto_pwhash_memlimit_moderate())
	Argon2iOpsLimitSensitive   = ArgonLimit(C.crypto_pwhash_opslimit_sensitive())
	Argon2iMemLimitSensitive   = ArgonLimit(C.crypto_pwhash_memlimit_sensitive())

	// internal params var
	argon2iStringBytesLen = int(C.crypto_pwhash_strbytes())
	scryptStringBytesLen  = int(C.crypto_pwhash_scryptsalsa208sha256_strbytes())
	bcryptDefaultConst    = 12 // http://security.stackexchange.com/q/17207
)

type ArgonLimit int
type ScryptLimit int

type Argon2iPassword struct {
	Operation ArgonLimit
	Memory    ArgonLimit
}

type ScryptPassword struct {
	Operation ScryptLimit
	Memory    ScryptLimit
}

type BcryptPassword struct {
	Cost int
}

func (p *Argon2iPassword) Argon2iHash(plaintext []byte) ([]byte, bool) {
	length := len(plaintext)
	result := make([]C.char, argon2iStringBytesLen)
	isOk := int(C.crypto_pwhash_str(
		(*C.char)(unsafe.Pointer(&result[0])),
		(*C.char)(unsafe.Pointer(&plaintext[0])),
		(C.ulonglong)(length),
		(C.ulonglong)(p.Operation),
		(C.size_t)(p.Memory),
	)) == 0

	C.sodium_memzero(unsafe.Pointer(&plaintext[0]), C.size_t(length))

	// if result is []byte, I have to trim null-ending from it
	return []byte(C.GoString(&result[0])), isOk
}

func Argon2iPasswordHash(plaintext []byte) ([]byte, bool) {
	p := &Argon2iPassword{
		Operation: Argon2iOpsLimitInteractive,
		Memory:    Argon2iMemLimitInteractive,
	}

	return p.Argon2iHash(plaintext)
}

func Argon2iPasswordVerify(plaintext, hash []byte) bool {
	if len(hash) < argon2iStringBytesLen {
		hash = append(hash, make([]byte, argon2iStringBytesLen-len(hash))...)
	}

	length := len(plaintext)
	isOk := int(C.crypto_pwhash_str_verify(
		(*C.char)(unsafe.Pointer(&hash[0])),
		(*C.char)(unsafe.Pointer(&plaintext[0])),
		(C.ulonglong)(length),
	)) == 0

	C.sodium_memzero(unsafe.Pointer(&plaintext[0]), C.size_t(length))

	return isOk
}

func (p *ScryptPassword) ScryptHash(plaintext []byte) ([]byte, bool) {
	length := len(plaintext)
	result := make([]C.char, scryptStringBytesLen)
	isOk := int(C.crypto_pwhash_scryptsalsa208sha256_str(
		(*C.char)(unsafe.Pointer(&result[0])),
		(*C.char)(unsafe.Pointer(&plaintext[0])),
		(C.ulonglong)(length),
		(C.ulonglong)(p.Operation),
		(C.size_t)(p.Memory),
	)) == 0

	C.sodium_memzero(unsafe.Pointer(&plaintext[0]), C.size_t(length))

	// if result is []byte, I have to trim null-ending from it
	return []byte(C.GoString(&result[0])), isOk
}

func ScryptPasswordHash(plaintext []byte) ([]byte, bool) {
	p := &ScryptPassword{
		Operation: ScryptOpsLimitInteractive,
		Memory:    ScryptMemLimitInteractive,
	}

	return p.ScryptHash(plaintext)
}

func ScryptPasswordVerify(plaintext, hash []byte) bool {
	length := len(plaintext)
	isOk := int(C.crypto_pwhash_scryptsalsa208sha256_str_verify(
		(*C.char)(unsafe.Pointer(&hash[0])),
		(*C.char)(unsafe.Pointer(&plaintext[0])),
		(C.ulonglong)(length),
	)) == 0

	C.sodium_memzero(unsafe.Pointer(&plaintext[0]), C.size_t(length))

	return isOk
}

func (p *BcryptPassword) BcryptHash(plaintext []byte) ([]byte, bool) {
	hash, err := bcrypt.GenerateFromPassword(plaintext, p.Cost)

	return hash, (err == nil)
}

func BcryptPasswordHash(plaintext []byte) ([]byte, bool) {
	p := BcryptPassword{
		Cost: bcryptDefaultConst,
	}

	return p.BcryptHash(plaintext)
}

func BcryptPasswordVerify(plaintext, hash []byte) bool {
	isOk := (bcrypt.CompareHashAndPassword(hash, plaintext) == nil)

	return isOk
}
