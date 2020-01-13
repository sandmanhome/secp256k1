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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
 * @param : privateKey of "PVT_K1_..."  "PVT_SM2_..."
 * @param : hash sha256 of msg
 * @return: SIG_K1_ or SIG_SM2_
 */
func SignMsg(privateKey string, msg []byte) (string, error) {
	_, curveType, privateRawData, err := StringToKey(privateKey)
	if err != nil {
		return "", err
	}

	// if curveType == "SM2" {
	// 	hash := sm3.Sm3Sum(msg)
	// 	return sign(privateRawData, hash[:], curveType)
	// }

	hash := sha256.Sum256(msg)
	return sign(privateRawData, hash[:], curveType)
}

/**
 * @description: Sign hash by privateKey string
 * @param : privateKey of "PVT_K1_..."
 * @param : hash sha256 of msg
 * @return: SIG_K1_
 */
func Sign(privateKey string, hash []byte) (string, error) {
	_, curveType, privateRawData, err := StringToKey(privateKey)
	if err != nil {
		return "", err
	}

	return sign(privateRawData, hash, curveType)
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

	return sign(privateRawData, hash, "K1")
}

const keyBytesLen uint = 32

func getKeyByPrivateRawData(curveType string, privateRawData []byte) (*btcec.PrivateKey, *btcec.PublicKey) {
	if curveType == "SM2" {
		return btcec.PrivKeyFromBytes(btcec.P256Sm2(), privateRawData)
	}
	return btcec.PrivKeyFromBytes(btcec.S256(), privateRawData)
}

func sign(privateRawData, hash []byte, curveType string) (string, error) {
	privKey, _ := getKeyByPrivateRawData(curveType, privateRawData)
	var sigData []byte
	var err error
	if curveType == "SM2" {
		sigData, err = privKey.SignCanonicalInfiniteSM2(hash)
	} else {
		curve := btcec.S256()
		sigData, err = privKey.SignCanonicalInfinite(curve, hash)
	}

	if err != nil {
		return "", err
	}

	return KeyToString("SIG", curveType, sigData), nil
}

func NewKeyPairRaw(curve elliptic.Curve) ([]byte, []byte, error) {
	privKey, err := newRandomPrivKey(rand.Reader, curve)
	if err != nil {
		return nil, nil, err
	}

	privateRawKey := getPrivateRawKey(privKey)

	X, Y := getPublicRawData(privKey)
	publicRawKey := encodeToPublicRawKey(X, Y)

	return privateRawKey, publicRawKey, nil
}

/**
 * @description: secp256k1 NewKeyPair, format "PVT_K1_..."
 * @param :
 * @return: privateKey publicKey
 */
func NewSM2KeyPair() (string, string, error) {
	privateRawKey, publicRawKey, err := NewKeyPairRaw(btcec.P256Sm2())
	if err != nil {
		return "", "", err
	}

	privateKey := KeyToString("PVT", "SM2", privateRawKey)
	publicKey := KeyToString("PUB", "SM2", publicRawKey)
	return privateKey, publicKey, nil
}

/**
 * @description: secp256k1 NewKeyPair, format "PVT_K1_..."
 * @param :
 * @return: privateKey publicKey
 */
func NewKeyPair() (string, string, error) {
	privateRawKey, publicRawKey, err := NewKeyPairRaw(btcec.S256())
	if err != nil {
		return "", "", err
	}

	privateKey := KeyToString("PVT", "K1", privateRawKey)
	publicKey := KeyToString("PUB", "K1", publicRawKey)
	return privateKey, publicKey, nil
}

/**
 * @description: secp256k1 Legacy NewKeyPair, publicKey format "EOS..."
 * @param :
 * @return: privateKey publicKey
 */
func NewEosKeyPair() (string, string, error) {
	privateRawKey, publicRawKey, err := NewKeyPairRaw(btcec.S256())
	if err != nil {
		return "", "", err
	}

	legacyPrivateRawKey := encodeToLegacyPrivateRawKey(privateRawKey)
	legacyPrivate := legacyPrivateKeyToString(legacyPrivateRawKey)

	legacyPublicKey := legacyPublicKeyToString("EOS", publicRawKey)
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

	return KeyToString("PVT", "K1", privateRawData), nil
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
	return KeyToString("PUB", "K1", publicRawKey), nil
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
	_, curveType, payload, err := StringToKey(privateKey)
	if err != nil {
		return "", err
	}

	publicRawKey, err := PrivateRawKeyToPublicRawKey(curveType, payload)
	return KeyToString("PUB", curveType, publicRawKey), nil
}

func PrivateRawKeyToPublicRawKey(curveType string, privateRawKey []byte) ([]byte, error) {
	var curve elliptic.Curve
	if curveType == "K1" {
		curve = btcec.S256()
	} else if curveType == "SM2" {
		curve = btcec.P256Sm2()
	} else {
		return nil, fmt.Errorf("Only support K1/SM2")
	}

	X, Y := getPointFromEcc(privateRawKey, curve)
	publicRawKey := encodeToPublicRawKey(X, Y)
	return publicRawKey, nil
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

	payloadLen := keyBytesLen + 1
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, y)
	return paddedAppend(keyBytesLen, payload, X.Bytes())
}

func encodeToPublicRawKeyByY0(X []byte, Y0 byte) []byte {
	// fmt.Println(len(X))
	// payloadLen := len(X) + 1
	// payload := make([]byte, 0, payloadLen)
	// payload = append(payload, Y0)
	// payload = append(payload, X...)
	// return payload

	payloadLen := keyBytesLen + 1
	fmt.Println(payloadLen)
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, Y0)
	return paddedAppend(keyBytesLen, payload, X)
}

func encodeToLegacyPublicRawKey(X, Y *big.Int) []byte {
	return encodeToPublicRawKey(X, Y)
}

func decodeLegacyPublicRawKey(legacyPublicRawKey []byte) ([]byte, byte, error) {
	return legacyPublicRawKey[1:], legacyPublicRawKey[0:1][0], nil
}

func getPointFromEcc(privateRawKey []byte, curve elliptic.Curve) (*big.Int, *big.Int) {
	_, pubKey := btcec.PrivKeyFromBytes(curve, privateRawKey)
	return pubKey.X, pubKey.Y
}

func newRandomPrivKey(randSource io.Reader, curve elliptic.Curve) (*btcec.PrivateKey, error) {
	rawPrivKey := make([]byte, 32)
	written, err := io.ReadFull(randSource, rawPrivKey)
	if err != nil {
		return nil, fmt.Errorf("error feeding crypto-rand numbers to seed ephemeral private key: %s", err)
	}
	if written != 32 {
		return nil, fmt.Errorf("couldn't write 32 bytes of randomness to seed ephemeral private key")
	}

	privKey, _ := btcec.PrivKeyFromBytes(curve, rawPrivKey)
	return privKey, nil
}

func getPrivateRawKey(privKey *btcec.PrivateKey) []byte {
	payload := make([]byte, 0, keyBytesLen)
	return paddedAppend(keyBytesLen, payload, privKey.D.Bytes())
}

func getPublicRawData(privKey *btcec.PrivateKey) (*big.Int, *big.Int) {
	return privKey.PubKey().X, privKey.PubKey().Y
}

func KeyToString(prefix, curveType string, payload []byte) string {
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

func StringToKey(keyStr string) (string, string, []byte, error) {
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

// paddedAppend appends the src byte slice to dst, returning the new slice.
// If the length of the source is smaller than the passed size, leading zero
// bytes are appended to the dst slice before appending src.
func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
