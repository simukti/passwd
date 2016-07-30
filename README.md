## passwd

A Golang wrapper for hashing and validating password based on :
- [Libsodium Argon2i](https://download.libsodium.org/libsodium/content/password_hashing/the_argon2i_function.html) (C wrapper)
- [Libsodium Scrypt](https://download.libsodium.org/libsodium/content/password_hashing/scrypt.html) (C wrapper)
- [Bcrypt](https://godoc.org/golang.org/x/crypto/bcrypt)

Further details :
- Argon2 is the winner of [Password Hashing Competition](https://password-hashing.net/) 
- [Bcrypt](https://en.wikipedia.org/wiki/Bcrypt) is a good old friend for dev.

## Requirements
This package require libsodium >= 1.0.10 and currently tested on OSX libsodium via `brew install libsodium`

- OSX : 
    * `brew update`
    * `brew install libsodium` 
- Linux :
    * Download and install libsodium from its website (https://download.libsodium.org/libsodium/content/installation/)

## Install
`go get -u -v github.com/simukti/passwd`

## Example
- **Argon2i**
```go
// default mode is interactive
hashed, _ := passwd.Argon2iPasswordHash([]byte(pwd))

// OR with custom operation
p := passwd.Argon2iPassword{
    Operation: Argon2iOpsLimitModerate,
    Memory:    Argon2iMemLimitModerate,
}

hashed, _ := p.Argon2iHash([]byte(pwd))
```

- **Scrypt**
```go
// default mode is interactive
hashed, _ := passwd.ScryptPasswordHash([]byte(pwd))

// OR with custom operation
p := passwd.ScryptPassword{
    Operation: ScryptOpsLimitSensitive,
    Memory:    ScryptMemLimitSensitive,
}

hashed, _ := p.ScryptHash([]byte(pwd))
```

- **Bcrypt**
```go
// using default cost (12)
hashed, _ := passwd.BcryptPasswordHash([]byte(pwd))

// OR with custom bcrypt cost
p := passwd.BcryptPassword{
    Cost: 10, // default bcrypt cost is 10
}

hashed, ok := p.BcryptHash([]byte(pwd))
```

## Tests
`go test -v ./...`

```
$ go test -v ./...
=== RUN   TestScryptHashGenerate
--- PASS: TestScryptHashGenerate (0.05s)
=== RUN   TestScryptHashValidate
--- PASS: TestScryptHashValidate (0.10s)
=== RUN   TestScryptHashValidateModeSensitive
--- PASS: TestScryptHashValidateModeSensitive (6.40s)
=== RUN   TestScryptHashValidateFromOtherApp
--- PASS: TestScryptHashValidateFromOtherApp (0.05s)
=== RUN   TestArgon2iHashGenerate
--- PASS: TestArgon2iHashGenerate (0.14s)
=== RUN   TestArgon2iHashValidate
--- PASS: TestArgon2iHashValidate (0.27s)
=== RUN   TestArgon2iHashValidateModeModerate
--- PASS: TestArgon2iHashValidateModeModerate (1.71s)
=== RUN   TestArgon2iHashValidateModeSensitive
--- PASS: TestArgon2iHashValidateModeSensitive (9.49s)
=== RUN   TestArgon2iHashValidateFromOtherApp
--- PASS: TestArgon2iHashValidateFromOtherApp (0.14s)
=== RUN   TestBcryptHashGenerate
--- PASS: TestBcryptHashGenerate (0.33s)
=== RUN   TestBcryptHashValidate
--- PASS: TestBcryptHashValidate (0.67s)
=== RUN   TestBcryptHashValidateFromOtherApp
--- PASS: TestBcryptHashValidateFromOtherApp (0.66s)
=== RUN   TestBcryptWithCustomCost
--- PASS: TestBcryptWithCustomCost (0.24s)
PASS
ok  	github.com/simukti/passwd	20.257s
```

## License
MIT