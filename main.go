package main

import (
	// Modified https://github.com/o1egl/paseto/tree/v0.2.0, export WithNonce method
	"jwt-paseto/paseto"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"

	"encoding/hex"
	"fmt"

	"crypto/rand"
	"crypto/rsa"
	"encoding/json"

	"golang.org/x/crypto/ed25519"
)

var privateKey *rsa.PrivateKey
var publicKey *rsa.PublicKey

func main() {
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
	publicKey = &privateKey.PublicKey

	nonce1 := "000000000000000000000000000000000000000000000000"
	nonce2 := "45742c976d684ff84ebdc0de59809a97cda2f64c84fda19b"

	EncryptResult("Test Vector v2-E-1", map[string]interface{}{
		"data": "this is a signed message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, nonce1, nil)

	EncryptResult("Test Vector v2-E-2", map[string]interface{}{
		"data": "this is a secret message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, nonce1, nil)

	EncryptResult("Test Vector v2-E-3", map[string]interface{}{
		"data": "this is a signed message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, nonce2, nil)

	EncryptResult("Test Vector v2-E-4", map[string]interface{}{
		"data": "this is a secret message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, nonce2, nil)

	EncryptResult("Test Vector v2-E-5", map[string]interface{}{
		"data": "this is a signed message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, nonce2, map[string]interface{}{"kid": "UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"})

	EncryptResult("Test Vector v2-E-6", map[string]interface{}{
		"data": "this is a secret message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, nonce2, map[string]interface{}{"kid": "UbkK8Y6iv4GZhFp6Tx3IWLWLfNXSEvJcdT3zdR65YZxo"})

	SignResult("Test Vector v2-S-1", map[string]interface{}{
		"data": "this is a signed message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, nil)

	SignResult("Test Vector v2-S-2", map[string]interface{}{
		"data": "this is a signed message",
		"exp":  "2019-01-01T00:00:00+00:00",
	}, map[string]interface{}{"kid": "dYkISylxQeecEcHELfzF88UZrwbLolNiCdpzUHGw9Uqn"})
}

func EncryptResult(name string, payload interface{}, nonce string, footer interface{}) {
	payloadJson, _ := json.Marshal(payload)
	footerJson, _ := json.Marshal(footer)
	decodedNonce, _ := hex.DecodeString(nonce)
	pasetoToken := PASETOEncrypt(payload, decodedNonce, footer)
	jwtToken := JWE(payload, footer)

	fmt.Println(name)
	fmt.Println("key     :", "707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	fmt.Println("nonce   :", nonce)
	fmt.Println("payload :", string(payloadJson))
	if footer != nil {
		fmt.Println("footer  :", string(footerJson))
	} else {
		fmt.Println("footer  :")
	}
	fmt.Println()
	fmt.Println("paseto  :", pasetoToken)
	fmt.Println("length  :", len(pasetoToken))
	fmt.Println()
	fmt.Println("jwt     :", jwtToken)
	fmt.Println("length  :", len(jwtToken))
	fmt.Println()
	fmt.Println()
}

func SignResult(name string, payload interface{}, footer interface{}) {
	payloadJson, _ := json.Marshal(payload)
	footerJson, _ := json.Marshal(footer)
	pasetoToken := PASETOSign(payload, footer)
	jwtToken := JWS(payload, footer)

	fmt.Println(name)
	fmt.Println("key     :", "b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	fmt.Println("payload :", string(payloadJson))
	if footer != nil {
		fmt.Println("footer  :", string(footerJson))
	} else {
		fmt.Println("footer  :")
	}
	fmt.Println()
	fmt.Println("paseto  :", pasetoToken)
	fmt.Println("length  :", len(pasetoToken))
	fmt.Println()
	fmt.Println("jwt     :", jwtToken)
	fmt.Println("length  :", len(jwtToken))
	fmt.Println()
	fmt.Println()
}

func SignKeys() (ed25519.PrivateKey, ed25519.PublicKey) {
	privateBytes, _ := hex.DecodeString("b4cbfb43df4ce210727d953e4a713307fa19bb7d9f85041438d9e11b942a37741eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")
	publicBytes, _ := hex.DecodeString("1eb9dbbbbc047c03fd70604e0071f0987e16b28b757225c11f00415d0e20b1a2")

	privateKey := ed25519.PrivateKey(privateBytes)
	publicKey := ed25519.PublicKey(publicBytes)

	return privateKey, publicKey
}

func EncryptKey() []byte {
	key, _ := hex.DecodeString("707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f")
	return key
}

func PASETOSign(payload interface{}, footer interface{}) string {
	var token string
	var err error

	privateKey, publicKey := SignKeys()
	v2 := paseto.NewV2()

	if footer == nil {
		token, err = v2.Sign(privateKey, payload)
	} else {
		token, err = v2.Sign(privateKey, payload, paseto.WithFooter(footer))
	}

	if err != nil {
		panic(err)
	}

	// Verify token
	err = v2.Verify(token, publicKey, nil, nil)
	if err != nil {
		panic(err)
	}

	return token
}

func PASETOEncrypt(payload interface{}, nonce []byte, footer interface{}) string {
	var token string
	var err error

	v2 := paseto.NewV2()

	if footer == nil {
		token, err = v2.Encrypt(EncryptKey(), payload, paseto.WithNonce(nonce))
	} else {
		token, err = v2.Encrypt(EncryptKey(), payload, paseto.WithNonce(nonce), paseto.WithFooter(footer))
	}

	if err != nil {
		panic(err)
	}

	// Verify token
	err = v2.Decrypt(token, EncryptKey(), nil, nil)
	if err != nil {
		panic(err)
	}

	return token
}

func JWS(payload interface{}, footer interface{}) string {
	privateKey, publicKey := SignKeys()

	algo := jose.SigningKey{Algorithm: jose.EdDSA, Key: privateKey}
	var opts *jose.SignerOptions = nil
	if footer != nil {
		opts = &jose.SignerOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": footer.(map[string]interface{})["kid"],
		}}
	}

	signer, err := jose.NewSigner(algo, opts)
	if err != nil {
		panic(err)
	}

	builder := jwt.Signed(signer).Claims(payload)
	token, err := builder.CompactSerialize()
	if err != nil {
		panic(err)
	}

	// Verify token
	jws, _ := jose.ParseSigned(token)
	_, err = jws.Verify(publicKey)
	if err != nil {
		panic(err)
	}

	return token
}

func JWE(payload interface{}, footer interface{}) string {
	var opts *jose.EncrypterOptions = nil
	if footer != nil {
		opts = &jose.EncrypterOptions{ExtraHeaders: map[jose.HeaderKey]interface{}{
			"kid": footer.(map[string]interface{})["kid"],
		}}
	}

	encrypter, err := jose.NewEncrypter(jose.A128CBC_HS256, jose.Recipient{Algorithm: jose.RSA_OAEP_256, Key: publicKey}, opts)
	if err != nil {
		panic(err)
	}

	builder := jwt.Encrypted(encrypter).Claims(payload)
	token, err := builder.CompactSerialize()
	if err != nil {
		panic(err)
	}

	// Verify token
	jwe, _ := jose.ParseEncrypted(token)
	_, err = jwe.Decrypt(privateKey)
	if err != nil {
		panic(err)
	}

	return token
}
