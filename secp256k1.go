/*
 * @Description: secp256k1
 * @Copyright: meetone
 * @Author: sandman sandmanhome@hotmail.com
 * @Date: 2019-12-11 15:54:24
 * @LastEditTime: 2019-12-18 11:15:40
 * @LastEditors: sandman
 */
package secp256k1

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"secp256k1/btcsuite/btcd/btcec"
	"secp256k1/btcsuite/btcutil"
	"secp256k1/btcsuite/btcutil/base58"

	"golang.org/x/crypto/ripemd160"
)

/**
 * @description: Sign hash by privateKey string
 * @param : privateKey of "PVT_K1_..."
 * @param : hash sha256 of msg
 * @return: SIG_K1_
 */
func Sign(privateKey string, hash []byte) (string, error) {
	_, _, privateRawData, err := stringToKey(privateKey)
	if err != nil {
		return "", err
	}

	return sign(privateRawData, hash)
}

/**
 * @description: Sign hash by legacyPrivateKey string
 * @param : legacyPrivateKey
 * @param : hash sha256 of msg
 * @return: "SIG_K1_...
 */
func SignFromLegacyPrivateKey(legacyPrivateKey string, hash []byte) (string, error) {
	privateRawData, err := stringToPrivateRawData(legacyPrivateKey)
	if err != nil {
		return "", err
	}

	return sign(privateRawData, hash)
}

func getKeyByPrivateRawData(privateRawData []byte) (*btcec.PrivateKey, *btcec.PublicKey) {
	return btcec.PrivKeyFromBytes(btcec.S256(), privateRawData)
}

func sign(privateRawData, hash []byte) (string, error) {
	privKey, _ := getKeyByPrivateRawData(privateRawData)
	sigData, err := privKey.SignCanonicalInfinite(btcec.S256(), hash)
	if err != nil {
		return "", err
	}

	return keyToString("SIG", "K1", sigData), nil
}

func privateRawDataToPrivKey(privateRawData []byte) *btcec.PrivateKey {
	privKeyBytes := privateRawData[1 : 1+btcec.PrivKeyBytesLen]
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), privKeyBytes)
	return privKey
}

/**
 * @description: secp256k1 NewKeyPair, format "PVT_K1_..."
 * @param :
 * @return: privateKey publicKey
 */
func NewKeyPair() (string, string, error) {
	privKey, err := newRandomPrivKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	privateRawData := getPrivateRawData(privKey)
	privateKey := keyToString("PVT", "K1", privateRawData)

	X, Y := getPublicRawData(privKey)
	publicRawKey := encodeToPublicRawKey(X, Y)
	publicKey := keyToString("PUB", "K1", publicRawKey)

	return privateKey, publicKey, nil
}

/**
 * @description: secp256k1 Legacy NewKeyPair, publicKey format "EOS..."
 * @param :
 * @return: privateKey publicKey
 */
func NewEosKeyPair() (string, string, error) {
	privKey, err := newRandomPrivKey(rand.Reader)
	if err != nil {
		return "", "", err
	}

	privateRawData := getPrivateRawData(privKey)
	legacyPrivateRawKey := encodeToLegacyPrivateRawKey(privateRawData)
	legacyPrivate := legacyPrivateKeyToString(legacyPrivateRawKey)

	X, Y := getPublicRawData(privKey)
	legacyPublicRawKey := encodeToLegacyPublicRawKey(X, Y)
	legacyPublicKey := legacyPublicKeyToString("EOS", legacyPublicRawKey)

	return legacyPrivate, legacyPublicKey, nil

}

/**
 * @description: Convert legacyPrivateKey to PrivateKey
 * @param : legacyPrivateKey
 * @return: PrivateKey
 */
func ConvertLegacyPrivateKey(legacyPrivateKey string) (string, error) {
	if len(legacyPrivateKey) != 51 {
		return "", fmt.Errorf("INVALID_PRIVATE_KEY")
	}

	privateRawData, err := stringToPrivateRawData(legacyPrivateKey)
	if err != nil {
		return "", err
	}

	return keyToString("PVT", "K1", privateRawData), nil
}

/**
 * @description: Convert legacyPublicKey to publicKey
 * @param : legacyPublicKey
 * @return: publicKey
 */
func ConvertLegacyPublicKey(legacyPublicKey string) (string, error) {
	if len(legacyPublicKey) < 50 {
		return "", fmt.Errorf("INVALID_PUBLIC_KEY")
	}

	X, Y0, err := stringToPublicRawData(legacyPublicKey)
	if err != nil {
		return "", err
	}

	publicRawKey := encodeToPublicRawKeyByY0(X, Y0)
	return keyToString("PUB", "K1", publicRawKey), nil
}

func encodeToLegacyPrivateRawKey(rawKey []byte) []byte {
	payloadLen := len(rawKey) + 1
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, 0x80)
	payload = append(payload, rawKey...)
	return payload
}

func decodeLegacyPrivateRawKey(legacyPrivateRawKey []byte) ([]byte, error) {
	if legacyPrivateRawKey[0] != 0x80 {
		return nil, fmt.Errorf("unrecognized private key format")
	}

	return legacyPrivateRawKey[1:], nil
}

func PrivateKeyToPublicKey(privateKey string) (string, error) {
	_, curveType, payload, err := stringToKey(privateKey)
	if err != nil {
		return "", err
	}

	if curveType != "K1" {
		return "", fmt.Errorf("Only support K1")
	}

	X, Y := getPointFromEcc(payload)
	publicRawKey := encodeToPublicRawKey(X, Y)
	return keyToString("PUB", "K1", publicRawKey), nil
}

func isEven(bit uint) bool {
	if bit&0x01 == 0x01 {
		return false
	}
	return true
}

func encodeToPublicRawKey(X, Y *big.Int) []byte {
	var y byte = 0x02
	if !isEven(Y.Bit(0)) {
		y = 0x03
	}

	payloadLen := len(X.Bytes()) + 1
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, y)
	payload = append(payload, X.Bytes()...)
	return payload
}

func encodeToPublicRawKeyByY0(X []byte, Y0 byte) []byte {
	payloadLen := len(X) + 1
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, Y0)
	payload = append(payload, X...)
	return payload
}

func encodeToLegacyPublicRawKey(X, Y *big.Int) []byte {
	return encodeToPublicRawKey(X, Y)
}

func decodeLegacyPublicRawKey(legacyPublicRawKey []byte) ([]byte, byte, error) {
	return legacyPublicRawKey[1:], legacyPublicRawKey[0:1][0], nil
}

func getPointFromEcc(privateRawKey []byte) (*big.Int, *big.Int) {
	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), privateRawKey)
	return pubKey.X, pubKey.Y
}

func newRandomPrivKey(randSource io.Reader) (*btcec.PrivateKey, error) {
	rawPrivKey := make([]byte, 32)
	written, err := io.ReadFull(randSource, rawPrivKey)
	if err != nil {
		return nil, fmt.Errorf("error feeding crypto-rand numbers to seed ephemeral private key: %s", err)
	}
	if written != 32 {
		return nil, fmt.Errorf("couldn't write 32 bytes of randomness to seed ephemeral private key")
	}

	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), rawPrivKey)
	return privKey, nil
}

func getPrivateRawData(privKey *btcec.PrivateKey) []byte {
	return privKey.D.Bytes()
}

func getPublicRawData(privKey *btcec.PrivateKey) (*big.Int, *big.Int) {
	return privKey.PubKey().X, privKey.PubKey().Y
}

func keyToString(prefix, curveType string, payload []byte) string {
	checksum := ripemd160checksum(payload, curveType)
	encodeLen := len(payload) + len(checksum)

	a := make([]byte, 0, encodeLen)
	a = append(a, payload...)
	a = append(a, checksum...)

	return prefix + "_" + curveType + "_" + base58.Encode(a)
}

func legacyPublicKeyToString(prefix string, payload []byte) string {
	checksum := ripemd160checksum(payload, "")
	encodeLen := len(payload) + len(checksum)

	a := make([]byte, 0, encodeLen)
	a = append(a, payload...)
	a = append(a, checksum...)

	return prefix + base58.Encode(a)
}

func legacyPrivateKeyToString(payload []byte) string {
	return base58CheckEncode(payload)
}

func stringToKey(keyStr string) (string, string, []byte, error) {
	arr := strings.Split(keyStr, "_")
	if len(arr) != 3 || (arr[0] != "PUB" && arr[0] != "PVT" && arr[0] != "SIG") {
		return "", "", nil, fmt.Errorf("unrecognized key format")
	}

	curveType := arr[1]
	rawData := base58.Decode(arr[2])
	payloadLen := len(rawData) - 4
	payload := rawData[0:payloadLen]
	checksum := rawData[payloadLen:]
	reChecksum := ripemd160checksum(payload, curveType)
	if !bytes.Equal(checksum, reChecksum) {
		return "", "", nil, fmt.Errorf("checksum doesn't match")
	}

	return arr[0], curveType, payload, nil
}

func stringToPrivateRawData(legacyPrivateKey string) ([]byte, error) {
	legacyPrivateRawKey, _, err := base58CheckDecode(legacyPrivateKey)
	if err != nil {
		return nil, err
	}

	return decodeLegacyPrivateRawKey(legacyPrivateRawKey)
}

func stringToPublicRawData(leagcyPublicKey string) ([]byte, byte, error) {
	payload := base58.Decode(strings.TrimPrefix(leagcyPublicKey, "EOS"))
	legacyPublicRawKey := payload[0 : len(payload)-4]
	checksum := payload[len(payload)-4:]
	if !bytes.Equal(checksum, ripemd160checksum(legacyPublicRawKey, "")) {
		return nil, 0, fmt.Errorf("public key's checksum doesn't match")
	}

	return decodeLegacyPublicRawKey(legacyPublicRawKey)
}

func ripemd160checksum(in []byte, salt string) []byte {
	h := ripemd160.New()
	_, _ = h.Write(in) // this implementation has no error path

	if salt != "" {
		_, _ = h.Write([]byte(salt))
	}

	sum := h.Sum(nil)
	return sum[:4]
}

func base58CheckEncode(payload []byte) string {
	cksum := btcutil.DoubleHashB(payload)[:4]
	a := make([]byte, 0, len(payload)+len(cksum))
	a = append(a, payload...)
	a = append(a, cksum...)
	return base58.Encode(a)
}

func base58CheckDecode(encodeStr string) ([]byte, []byte, error) {
	a := base58.Decode(encodeStr)
	payload := a[0 : len(a)-4]
	checksum := a[len(a)-4:]

	reChecksum := btcutil.DoubleHashB(payload)[:4]
	if !bytes.Equal(reChecksum, checksum) {
		return nil, nil, fmt.Errorf("base58CheckDecode checksum not match")
	}

	return payload, checksum, nil
}
