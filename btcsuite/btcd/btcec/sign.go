/*
 * @Description: secp256k1
 * @Copyright: meetone
 * @Author: sandman sandmanhome@hotmail.com
 * @Date: 2019-12-12 11:37:25
 * @LastEditTime: 2019-12-12 16:44:35
 * @LastEditors: sandman
 */
package btcec

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"secp256k1/sm3"
)

/**
 * @description: copy from SignCanonical, change to infinite loop
 * @param :
 * @return:
 */
// SignCanonical goes through signatures and returns only a canonical
// representations.  This matches the EOS blockchain expectations.
func (p *PrivateKey) SignCanonicalInfinite(curve *KoblitzCurve, hash []byte) ([]byte, error) {
	for i := 0; ; i++ {
		sig, err := signRFC6979(p, hash, i)
		if err != nil {
			return nil, err
		}

		compactSig, err := makeCompact(curve, sig, p, hash, true)
		if err != nil {
			continue
		}

		if isCanonical(compactSig) {
			return compactSig, nil
		}
	}
}

func (p *PrivateKey) SignCanonicalInfiniteSM2(hash []byte) ([]byte, error) {
	for i := 0; ; i++ {
		sig, err := signRFC6979SM2(p, hash, i)
		if err != nil {
			return nil, err
		}

		compactSig, err := makeCompactSM2(P256Sm2(), sig, p, hash, true)
		if err != nil {
			continue
		}

		if isCanonical(compactSig) {
			return compactSig, nil
		}
	}
}

// signRFC6979 generates a deterministic ECDSA signature according to RFC 6979 and BIP 62.
func signRFC6979SM2(privateKey *PrivateKey, hash []byte, nonce int) (*Signature, error) {
	privkey := privateKey.ToECDSA()
	N := P256Sm2().Params().N
	halfOrder := P256Sm2().halfOrder
	k := nonceRFC6979SM2(privkey.D, hash, nonce)
	inv := new(big.Int).ModInverse(k, N)
	r, _ := privkey.Curve.ScalarBaseMult(k.Bytes())
	// if r.Cmp(N) == 1 {
	// 	r.Sub(r, N)
	// }
	r.Mod(r, N)

	if r.Sign() == 0 {
		return nil, errors.New("calculated R is zero")
	}

	e := hashToInt(hash, privkey.Curve)
	s := new(big.Int).Mul(privkey.D, r)
	s.Add(s, e)
	s.Mul(s, inv)
	s.Mod(s, N)

	if s.Cmp(halfOrder) == 1 {
		s.Sub(N, s)
	}
	if s.Sign() == 0 {
		return nil, errors.New("calculated S is zero")
	}
	return &Signature{R: r, S: s}, nil
}

// nonceRFC6979 generates an ECDSA nonce (`k`) deterministically according to RFC 6979.
// It takes a 32-byte hash as an input and returns 32-byte nonce to be used in ECDSA algorithm.
func nonceRFC6979SM2(privkey *big.Int, hash []byte, nonce int) *big.Int {
	if nonce > 0 {
		moreHash := sm3.New()
		moreHash.Write(hash)
		moreHash.Write(bytes.Repeat([]byte{0x00}, nonce))
		hash = moreHash.Sum(nil)
	}

	curve := P256Sm2()
	q := curve.Params().N
	x := privkey
	alg := sm3.New

	qlen := q.BitLen()
	holen := alg().Size()
	rolen := (qlen + 7) >> 3
	bx := append(int2octets(x, rolen), bits2octets(hash, curve, rolen)...)

	// Step B
	v := bytes.Repeat(oneInitializer, holen)

	// Step C (Go zeroes the all allocated memory)
	k := make([]byte, holen)

	// Step D
	k = mac(alg, k, append(append(v, 0x00), bx...))

	// Step E
	v = mac(alg, k, v)

	// Step F
	k = mac(alg, k, append(append(v, 0x01), bx...))

	// Step G
	v = mac(alg, k, v)

	// Step H
	for {
		// Step H1
		var t []byte

		// Step H2
		for len(t)*8 < qlen {
			v = mac(alg, k, v)
			t = append(t, v...)
		}

		// Step H3
		secret := hashToInt(t, curve)
		if secret.Cmp(one) >= 0 && secret.Cmp(q) < 0 {
			return secret
		}
		k = mac(alg, k, append(v, 0x00))
		v = mac(alg, k, v)
	}
}

func makeCompactSM2(curve *Sm2P256Curve, sig *Signature, key *PrivateKey, hash []byte, isCompressedKey bool) ([]byte, error) {
	for i := 0; i < (curve.H+1)*2; i++ {
		pk, err := recoverKeyFromSignatureSM2(curve, sig, hash, i, true)
		if err == nil && pk.X.Cmp(key.X) == 0 && pk.Y.Cmp(key.Y) == 0 {
			result := make([]byte, 1, 2*curve.byteSize+1)
			result[0] = 27 + byte(i)
			if isCompressedKey {
				result[0] += 4
			}
			// Not sure this needs rounding but safer to do so.
			curvelen := (curve.BitSize + 7) / 8

			// Pad R and S to curvelen if needed.
			bytelen := (sig.R.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig.R.Bytes()...)

			bytelen = (sig.S.BitLen() + 7) / 8
			if bytelen < curvelen {
				result = append(result,
					make([]byte, curvelen-bytelen)...)
			}
			result = append(result, sig.S.Bytes()...)

			return result, nil
		}
	}

	return nil, errors.New("no valid solution for pubkey found")
}

func recoverKeyFromSignatureSM2(curve *Sm2P256Curve, sig *Signature, msg []byte,
	iter int, doChecks bool) (*PublicKey, error) {
	// 1.1 x = (n * i) + r
	Rx := new(big.Int).Mul(curve.Params().N,
		new(big.Int).SetInt64(int64(iter/2)))
	Rx.Add(Rx, sig.R)
	if Rx.Cmp(curve.Params().P) != -1 {
		return nil, errors.New("calculated Rx is larger than curve P")
	}

	// convert 02<Rx> to point R. (step 1.2 and 1.3). If we are on an odd
	// iteration then 1.6 will be done with -R, so we calculate the other
	// term when uncompressing the point.
	Ry, err := decompressPointSM2(curve, Rx, iter%2 == 1)
	if err != nil {
		return nil, err
	}

	// 1.4 Check n*R is point at infinity
	if doChecks {
		nRx, nRy := curve.ScalarMult(Rx, Ry, curve.Params().N.Bytes())
		if nRx.Sign() != 0 || nRy.Sign() != 0 {
			return nil, errors.New("n*R does not equal the point at infinity")
		}
	}

	// 1.5 calculate e from message using the same algorithm as ecdsa
	// signature calculation.
	e := hashToInt(msg, curve)

	// Step 1.6.1:
	// We calculate the two terms sR and eG separately multiplied by the
	// inverse of r (from the signature). We then add them to calculate
	// Q = r^-1(sR-eG)
	invr := new(big.Int).ModInverse(sig.R, curve.Params().N)

	// first term.
	invrS := new(big.Int).Mul(invr, sig.S)
	invrS.Mod(invrS, curve.Params().N)
	sRx, sRy := curve.ScalarMult(Rx, Ry, invrS.Bytes())

	// second term.
	e.Neg(e)
	e.Mod(e, curve.Params().N)
	e.Mul(e, invr)
	e.Mod(e, curve.Params().N)
	minuseGx, minuseGy := curve.ScalarBaseMult(e.Bytes())

	// TODO: this would be faster if we did a mult and add in one
	// step to prevent the jacobian conversion back and forth.
	Qx, Qy := curve.Add(sRx, sRy, minuseGx, minuseGy)

	return &PublicKey{
		Curve: curve,
		X:     Qx,
		Y:     Qy,
	}, nil
}

// decompressPoint decompresses a point on the given curve given the X point and
// the solution to use.
func decompressPointSM2(curve *Sm2P256Curve, x *big.Int, ybit bool) (*big.Int, error) {
	// TODO: This will probably only work for secp256k1 due to
	// optimizations.

	// Y = +-sqrt(x^3 + B)
	x3 := new(big.Int).Mul(x, x)
	x3.Mul(x3, x)
	x3.Add(x3, curve.Params().B)

	// Y = +-sqrt(x^3 + ax + B)
	var ax, x_ sm2P256FieldElement
	sm2P256FromBig(&x_, x)
	sm2P256Mul(&ax, &curve.a, &x_) // a = a * x
	x3.Add(x3, sm2P256ToBig(&ax))

	// now calculate sqrt mod p of x2 + B
	// This code used to do a full sqrt based on tonelli/shanks,
	// but this was replaced by the algorithms referenced in
	// https://bitcointalk.org/index.php?topic=162805.msg1712294#msg1712294
	y := new(big.Int).Exp(x3, curve.QPlus1Div4(), curve.Params().P)

	if ybit != isOdd(y) {
		y.Sub(curve.Params().P, y)
	}
	if ybit != isOdd(y) {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}
	return y, nil
}

// RecoverCompact verifies the compact signature "signature" of "hash" for the
// Koblitz curve in "curve". If the signature matches then the recovered public
// key will be returned as well as a boolen if the original key was compressed
// or not, else an error will be returned.
func RecoverCompactSM2(curve *Sm2P256Curve, signature,
	hash []byte) (*PublicKey, bool, error) {
	bitlen := (curve.BitSize + 7) / 8
	if len(signature) != 1+bitlen*2 {
		return nil, false, errors.New("invalid compact signature size")
	}

	iteration := int((signature[0] - 27) & ^byte(4))

	// format is <header byte><bitlen R><bitlen S>
	sig := &Signature{
		R: new(big.Int).SetBytes(signature[1 : bitlen+1]),
		S: new(big.Int).SetBytes(signature[bitlen+1:]),
	}
	// The iteration used here was encoded
	key, err := recoverKeyFromSignatureSM2(curve, sig, hash, iteration, false)
	if err != nil {
		return nil, false, err
	}

	return key, ((signature[0] - 27) & 4) == 4, nil
}
