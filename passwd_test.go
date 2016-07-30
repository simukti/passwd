// Copyright (c) 2016 - Sarjono Mukti Aji <me@simukti.net>
// Unless otherwise noted, this source code license is MIT-License

package passwd

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var (
	pwd = "123123"
	// generated from pecl-sodium (https://pecl.php.net/package/libsodium)
	scryptStored = "$7$C6..../....rNnORaTnYgMTI6yzGVF9H4vin8ImRP5gtYiGWJH1nH/$fq7DcYRYpN.r.uPOAhE0kaOgQknFSYjAeZnzOHg7M/4"
	argon2Stored = "$argon2i$v=19$m=32768,t=4,p=1$mO9vZWw/KIgYg3ZRWXzQQA$RQi6ApPqaNNJX6uH1Y2q/OeYqoArfeoLPMJI9WgJ040"
	// generated from php 5.6 with cost 13 and 10
	bcryptStored       = "$2a$13$LoE7AFiigNGpLRJ7.Iojuu.VPYguc9n5u8yc.i17u/bzDx3X3u.RG"
	bcryptCost10Stored = "$2a$10$1fE8Jr88P0RwV/OjgyGFS.A14xOW6dg3uRABbD59MzvJ7h0mcMwB2"
)

func TestScryptHashGenerate(t *testing.T) {
	_, ok := ScryptPasswordHash([]byte(pwd))
	assert.Equal(t, true, ok)
}

func TestScryptHashValidate(t *testing.T) {
	hashed, _ := ScryptPasswordHash([]byte(pwd))
	isValid := ScryptPasswordVerify([]byte(pwd), hashed)
	assert.Equal(t, true, isValid)
}

func TestScryptHashValidateModeSensitive(t *testing.T) {
	p := ScryptPassword{
		Operation: ScryptOpsLimitSensitive,
		Memory:    ScryptMemLimitSensitive,
	}

	hashed, _ := p.ScryptHash([]byte(pwd))
	isValid := ScryptPasswordVerify([]byte(pwd), hashed)
	assert.Equal(t, true, isValid)
}

func TestScryptHashValidateFromOtherApp(t *testing.T) {
	isStoredValid := ScryptPasswordVerify([]byte(pwd), []byte(scryptStored))
	assert.Equal(t, true, isStoredValid)
}

func TestArgon2iHashGenerate(t *testing.T) {
	_, ok := Argon2iPasswordHash([]byte(pwd))
	assert.Equal(t, true, ok)
}

func TestArgon2iHashValidate(t *testing.T) {
	hashed, _ := Argon2iPasswordHash([]byte(pwd))
	isValid := Argon2iPasswordVerify([]byte(pwd), hashed)
	assert.Equal(t, true, isValid)
}

func TestArgon2iHashValidateModeModerate(t *testing.T) {
	p := Argon2iPassword{
		Operation: Argon2iOpsLimitModerate,
		Memory:    Argon2iMemLimitModerate,
	}

	hashed, _ := p.Argon2iHash([]byte(pwd))
	isValid := Argon2iPasswordVerify([]byte(pwd), hashed)
	assert.Equal(t, true, isValid)
}

func TestArgon2iHashValidateModeSensitive(t *testing.T) {
	p := Argon2iPassword{
		Operation: Argon2iOpsLimitSensitive,
		Memory:    Argon2iMemLimitSensitive,
	}

	hashed, _ := p.Argon2iHash([]byte(pwd))
	isValid := Argon2iPasswordVerify([]byte(pwd), hashed)
	assert.Equal(t, true, isValid)
}

func TestArgon2iHashValidateFromOtherApp(t *testing.T) {
	isStoredValid := Argon2iPasswordVerify([]byte(pwd), []byte(argon2Stored))
	assert.Equal(t, true, isStoredValid)
}

func TestBcryptHashGenerate(t *testing.T) {
	_, ok := BcryptPasswordHash([]byte(pwd))
	assert.Equal(t, true, ok)
}

func TestBcryptHashValidate(t *testing.T) {
	hashed, _ := BcryptPasswordHash([]byte(pwd))
	isValid := BcryptPasswordVerify([]byte(pwd), hashed)
	assert.Equal(t, true, isValid)
}

func TestBcryptHashValidateFromOtherApp(t *testing.T) {
	isStoredValid := BcryptPasswordVerify([]byte(pwd), []byte(bcryptStored))
	assert.Equal(t, true, isStoredValid)
}

func TestBcryptWithCustomCost(t *testing.T) {
	p := BcryptPassword{
		Cost: 10,
	}

	hashed, ok := p.BcryptHash([]byte(pwd))
	assert.Equal(t, true, ok)

	isValid := BcryptPasswordVerify([]byte(pwd), hashed)
	assert.Equal(t, true, isValid)

	isValidFromStored := BcryptPasswordVerify([]byte(pwd), []byte(bcryptCost10Stored))
	assert.Equal(t, true, isValidFromStored)
}
