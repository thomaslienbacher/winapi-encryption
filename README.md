# winapi-encryption: cngcrypt

A file encryption program that uses the WinAPI library [Cryptography API: Next Generation](https://docs.microsoft.com/en-us/windows/desktop/seccng/cng-portal).
The compiled binary name is `cngcrypt` as this is easier to remember and write.
This program only works on Windows and can be compiled by using CMake.

### How to use
`cngcrypt [FLAGS] <SECRET> <INPUT> <OUTPUT>` 

* `FLAGS` must use specify at least one flag
* `SECRET` password used to derive the AES key from
* `INPUT` input file
* `OUTPUT` output file

### Flags
* `-h` prints help information and exits
* `-e` encrypt input file to output file
* `-d` decrypt input file to output file
* `-S` print derived AES key and IV, optional

### Technical details
This program uses AES-128 to encrypt the files. 
The AES key is derived by generating a SHA-256 hash of the password and
collapsing the hash into 128-bit using XOR (see `data_half_collapse()` in `crypto.c`).
The IV is generated randomly using `BCryptGenRandom()`.

### Encrypted file
The encrypted file consists of three parts.
The first 8 bytes are used to store the original file length.
The next 16 bytes are used to store the IV.
After that the actual encrypted contents start. 

