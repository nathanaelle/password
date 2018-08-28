# password

[![License](http://img.shields.io/badge/license-Simplified_BSD-blue.svg?style=flat)](LICENSE.txt) [![Go Doc](http://img.shields.io/badge/godoc-password-blue.svg?style=flat)](http://godoc.org/github.com/nathanaelle/password) [![Build Status](https://travis-ci.org/nathanaelle/password.svg?branch=master)](https://travis-ci.org/nathanaelle/password)  [![Go Report Card](https://goreportcard.com/badge/github.com/nathanaelle/password)](https://goreportcard.com/report/github.com/nathanaelle/password)


## Implemented schemas

### Safe schemas

  * [x] SHA256-CRYPT `$5$` https://www.akkadia.org/drepper/sha-crypt.html
  * [x] SHA512-CRYPT `$6$` https://www.akkadia.org/drepper/sha-crypt.html
  * [x] BLF-CRYPT / BCRYPT `$2a$`, `$2$`, `$2x$`, `$2y$`, `$2b$`

### Unsafe schemas

  * [x] MD5-CRYPT `$1$`
  * [x] APR1 `$apr1$`

### BLF-CRYPT apparent mess

BCrypt algorithm is secure but there was flaws in few implementations.
This is the summary of the explanation of the different flavors of bcrypt :

  * `$2$` may be produced by a buggy version who doesn't cope with UNICODE
  * `$2x$` is the PHP name for buggy `$2$`
  * `$2y$` is the PHP name of `$2a$`
  * `$2b$` is the bcrypt prefix used in OpendBSD for the corrected version of `$2a$` (password length was limited to 255 bytes)

## License

BSD-2
