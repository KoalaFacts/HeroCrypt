"""Independent affine Edwards arithmetic for public normalized-XEdDSA fixtures.

MIT, HeroCrypt contributors. No foreign implementation source copied.
Construction reference: Signal XEdDSA and curve25519-java revision
70fae57d6dccff7e78a46203c534314b07dfdd98, additions/xeddsa.c and sign_modified.c.
Never use these variable-time test routines or fixture randomness in production.
"""
import hashlib
import json
from pathlib import Path

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, -1, P) % P
Y = 4 * pow(5, -1, P) % P
xx = (Y*Y-1) * pow(D*Y*Y+1, -1, P) % P
X = pow(xx, (P+3)//8, P)
if X*X % P != xx:
    X = X * pow(2, (P-1)//4, P) % P
if X % 2:
    X = P-X
B = (X, Y)


def add(a, b):
    x, y = a
    u, v = b
    t = D*x*u*y*v % P
    return ((x*v+y*u)*pow(1+t, -1, P) % P,
            (y*v+x*u)*pow(1-t, -1, P) % P)


def mul(k):
    q, b = (0, 1), B
    while k:
        if k & 1:
            q = add(q, b)
        b = add(b, b)
        k >>= 1
    return q


def encode(q):
    x, y = q
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


vectors = []
for i in range(16):
    raw = hashlib.sha256(f'XEdDSA public fixture {i}'.encode()).digest()
    kbytes = bytearray(raw)
    kbytes[0] &= 248
    kbytes[31] = (kbytes[31] & 127) | 64
    k = int.from_bytes(kbytes, 'little')
    point = mul(k)
    sign = point[0] & 1
    a = (-k % L).to_bytes(32, 'little') if sign else bytes(kbytes)
    public_ed = point[1].to_bytes(32, 'little')
    public_u = ((1+point[1])*pow(1-point[1], -1, P) % P).to_bytes(32, 'little')
    msg = b'' if i == 0 else f'normalized message {i}'.encode()
    randomness = hashlib.sha512(f'fixture randomness {i}'.encode()).digest()
    r = int.from_bytes(hashlib.sha512(b'\xfe'+b'\xff'*31+a+msg+randomness).digest(), 'little') % L
    encoded_r = encode(mul(r))
    h = int.from_bytes(hashlib.sha512(encoded_r+public_ed+msg).digest(), 'little') % L
    s = (r+h*int.from_bytes(a, 'little')) % L
    vectors.append(dict(private=raw.hex(), clamped=bytes(kbytes).hex(), message=msg.hex(),
                        randomness=randomness.hex(), public=public_u.hex(), edwards=public_ed.hex(),
                        sign=sign, signature=(encoded_r+s.to_bytes(32, 'little')).hex()))
assert {v['sign'] for v in vectors} == {0, 1}
Path(__file__).with_name('vectors.json').write_text(json.dumps(vectors, indent=2)+'\n')
