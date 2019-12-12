# secp256k1
  use secp256k1 to generate key-pair, then encode them 
 
## Getting Started

  ```
  git clone https://github.com/sandmanhome/secp256k1.git
  cd secp256k1
  go mod tidy
  go test
  ```

## Example

* NewKeyPair
  ```
  privateKey, publicKey, _ := NewKeyPair()
  fmt.Println(privateKey)
  fmt.Println(publicKey)
  ```

* PrivateKeyToPublicKey
  ```
  const EXCEPT_EXAMPLE_PRIVATE_KEY = "PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V"
  publicKeyByPrivateKey, _ := PrivateKeyToPublicKey(EXCEPT_EXAMPLE_PRIVATE_KEY)
  fmt.Println("publicKeyByPrivateKey", publicKeyByPrivateKey)
  ```

* Sign
  ```
  const EXCEPT_EXAMPLE_PRIVATE_KEY = "PVT_K1_2bfGi9rYsXQSXXTvJbDAPhHLQUojjaNLomdm3cEJ1XTzMqUt3V"
  MSG := "hello"
  msg, _ := hex.DecodeString(MSG)
  hash := sha256.Sum256(msg)
  signStr, _ := Sign(EXCEPT_EXAMPLE_PRIVATE_KEY, hash[:])
  fmt.Println(signStr)
  ```
  
* NewEosKeyPair
  ```
  privateKey, publicKey, _ := NewEosKeyPair()
  fmt.Println(privateKey)
  fmt.Println(publicKey)
  ```

* ConvertLegacyKey
  ```
  const EXAMPLE_PRIVATE_KEY = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"
  const EXAMPLE_PUBLIC_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"
  privateKey, _ := ConvertLegacyPrivateKey(EXAMPLE_PRIVATE_KEY)
  publicKey, _ := ConvertLegacyPublicKey(EXAMPLE_PUBLIC_KEY)
  fmt.Println("privkey", EXAMPLE_PRIVATE_KEY, "=", privateKey)
  fmt.Println("pubkey", EXAMPLE_PUBLIC_KEY, "=", publicKey)
  ```
