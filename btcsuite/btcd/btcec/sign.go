/*
 * @Description: secp256k1
 * @Copyright: meetone
 * @Author: sandman sandmanhome@hotmail.com
 * @Date: 2019-12-12 11:37:25
 * @LastEditTime: 2019-12-12 16:44:35
 * @LastEditors: sandman
 */
package btcec

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
