# password

[![License](http://img.shields.io/badge/license-Simplified_BSD-blue.svg?style=flat)](LICENSE.txt) [![Go Doc](http://img.shields.io/badge/godoc-password-blue.svg?style=flat)](http://godoc.org/github.com/nathanaelle/password) [![Build Status](https://travis-ci.org/nathanaelle/password.svg?branch=master)](https://travis-ci.org/nathanaelle/password)

## Implemented schemas

### Safe schemas

  * [x] `$5$` SHA256-CRYPT https://www.akkadia.org/drepper/sha-crypt.html
  * [x] `$6$` SHA512-CRYPT https://www.akkadia.org/drepper/sha-crypt.html
  * [x] `$2a$` BLF-CRYPT / BCRYPT
  * [ ] `$2b$`, `$2y$` aliases of `$2a$`

### Unsafe schemas

  * [ ] `$2$` BCRYPT ( if you provide a $2$ hash, it may be produced by a buggy version of bcrypt )
  * [ ] `$2x$` BCRYPT ( explicitly buggy version of  php bcrypt )
  * [ ] `$1$` MD5-CRYPT
  * [ ] `$apr1$` APR1

## License

BSD-2
