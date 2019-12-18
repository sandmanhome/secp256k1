package secp256k1

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"secp256k1/btcsuite/btcd/btcec"

	"testing"

	"github.com/stretchr/testify/assert"
)

const EXAMPLE_PRIVATE_KEY = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
const EXAMPLE_PUBLIC_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
const EXCEPT_EXAMPLE_PRIVATE_KEY = "PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V"
const EXCEPT_EXAMPLE_PUBLIC_KEY = "PUB_K1_6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5BoDq63"
const EXAMPLE_PRIVATE_KEY1 = "PVT_K1_GjWZm14kTvh2beuqufQYYxfSncuMr4DGEaD5n9mdCJPpRgzBJ"
const EXAMPLE_PUBLIC_KEY1 = "PUB_K1_4wcf7rKqTqkgk3nHpBYh3YVS7UmKu2Ai5hdZuWtiA12vMirf5n"

const MSG = "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906" +
	"c0fbc75d000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000"
const EXCEPT_SIGN_STR = "SIG_K1_K8chr6Q23BaVB3zwFLzkLmmbFUvN7aq6WATpSd79SFdTdyJSKamS4XuSK83auTkkL59icGfuCsS7Rniaip8MBGYYcVsGCm"

func TestConvertLegacyKey(t *testing.T) {
	privateKey, _ := ConvertLegacyPrivateKey(EXAMPLE_PRIVATE_KEY)
	publicKey, _ := ConvertLegacyPublicKey(EXAMPLE_PUBLIC_KEY)
	assert.Equal(t, EXCEPT_EXAMPLE_PRIVATE_KEY, privateKey)
	assert.Equal(t, EXCEPT_EXAMPLE_PUBLIC_KEY, publicKey)
	fmt.Println("privkey", EXAMPLE_PRIVATE_KEY, "=", privateKey)
	fmt.Println("pubkey", EXAMPLE_PUBLIC_KEY, "=", publicKey)
}

func TestPrivateKeyToPublicKey(t *testing.T) {
	publicKeyByPrivateKey, _ := PrivateKeyToPublicKey(EXAMPLE_PRIVATE_KEY1)
	fmt.Println("publicKeyByPrivateKey", publicKeyByPrivateKey)
	assert.Equal(t, EXAMPLE_PUBLIC_KEY1, publicKeyByPrivateKey)
}

func TestNewKeyPair(t *testing.T) {
	privateKey, publicKey, _ := NewKeyPair()
	fmt.Println(privateKey)
	fmt.Println(publicKey)
	publicKeyByPrivateKey, _ := PrivateKeyToPublicKey(privateKey)
	fmt.Println("publicKeyByPrivateKey", publicKeyByPrivateKey)
	assert.Equal(t, publicKey, publicKeyByPrivateKey)
}

func TestLegacySign(t *testing.T) {
	msg, _ := hex.DecodeString(MSG)
	hash := sha256.Sum256(msg)
	signStr, _ := SignFromLegacyPrivateKey(EXAMPLE_PRIVATE_KEY, hash[:])
	fmt.Println(signStr)
	assert.Equal(t, EXCEPT_SIGN_STR, signStr)

	privateRawData, _ := stringToPrivateRawData(EXAMPLE_PRIVATE_KEY)
	_, pubKey := getKeyByPrivateRawData(privateRawData)
	_, _, sig, _ := stringToKey(signStr)
	recoverPubKey, _, _ := btcec.RecoverCompact(btcec.S256(), sig, hash[:])
	assert.Equal(t, pubKey.X, recoverPubKey.X)
	assert.Equal(t, pubKey.Y, recoverPubKey.Y)
}

func TestSign(t *testing.T) {
	msg, _ := hex.DecodeString(MSG)
	hash := sha256.Sum256(msg)
	signStr, _ := Sign(EXCEPT_EXAMPLE_PRIVATE_KEY, hash[:])
	fmt.Println(signStr)
	assert.Equal(t, EXCEPT_SIGN_STR, signStr)

	_, _, privateRawData, _ := stringToKey(EXCEPT_EXAMPLE_PRIVATE_KEY)
	_, pubKey := getKeyByPrivateRawData(privateRawData)
	_, _, sig, _ := stringToKey(signStr)
	recoverPubKey, _, _ := btcec.RecoverCompact(btcec.S256(), sig, hash[:])
	assert.Equal(t, pubKey.X, recoverPubKey.X)
	assert.Equal(t, pubKey.Y, recoverPubKey.Y)
}
