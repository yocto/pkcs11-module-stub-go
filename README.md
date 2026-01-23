# PKCS#11 Module Stub

[![Go](https://github.com/yocto/pkcs11-module-stub-go/actions/workflows/go.yml/badge.svg)](https://github.com/yocto/pkcs11-module-stub-go/actions/workflows/go.yml)

A PKCS#11 module with only stub functions.

## Usage

Fork, clone or download this repository and use it as base for your own PKCS#11 module.

## Build

To build this module, you just run:

```shell
./download_headers.sh
go build --buildmode=c-shared -o bin/
```

Note: Because of Cgo, `gcc` is expected to be installed.