# Third-party notices

## Wycheproof ECDSA test vectors

The unchanged secp256k1 SHA-256 P1363 corpus under
`tests/HeroCrypt.Tests/Fixtures/Wycheproof` comes from
[C2SP/wycheproof](https://github.com/C2SP/wycheproof), revision
`7a325932231bd7a724c791c8b0d65ea4d6d2f435`.
It is distributed under Apache-2.0. The upstream license and fixture provenance
are included in that directory. These files are used only by the test project.

## BIP39 English wordlist and reference vectors

The English wordlist in `src/HeroCrypt/Protocols/HdWallet/Bip39English.txt` is
copied unchanged from the [Bitcoin BIPs repository](https://github.com/bitcoin/bips/blob/master/bip-0039/english.txt).
BIP39 was authored by Marek Palatinus, Pavol Rusnak, Aaron Voisine and Sean Bowe and
is [licensed under MIT](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki).

The test vectors embedded in `Bip39MnemonicTests.cs` are from the MIT-licensed
[Trezor python-mnemonic project](https://github.com/trezor/python-mnemonic),
Copyright (c) 2013-2016 Pavol Rusnak.

### MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
