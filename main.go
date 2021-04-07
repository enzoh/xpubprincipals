package main

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"hash/crc32"
	"os"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/hdkeychain"
)

type ECPubKeyMetadata struct {
	ECPubKeyOID   asn1.ObjectIdentifier
	NamedCurveOID asn1.ObjectIdentifier
}

type ECPubKey struct {
	Metadata  ECPubKeyMetadata
	PublicKey asn1.BitString
}

func main() {
	argXPubKey := flag.String("xpub", "", "Extended public key. (required)")
	argN := flag.Int("n", 8, "Number of addresses.")
	flag.Parse()
	if *argXPubKey == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
	err := run(*argXPubKey, *argN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(argXPubKey string, argN int) error {
	masterXPubKey, err := hdkeychain.NewKeyFromString(argXPubKey)
	if err != nil {
		return err
	}
	principals, err := generate(masterXPubKey, argN)
	if err != nil {
		return err
	}
	for _, principal := range principals {
		fmt.Println(principal)
	}
	return nil
}

func generate(
	masterXPubKey *hdkeychain.ExtendedKey,
	n int,
) ([]string, error) {
	masterXPubKey0, err := masterXPubKey.Child(0)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0)
	for i := 0; i < n; i++ {
		childXPubKey, err := masterXPubKey0.Child(uint32(i))
		if err != nil {
			return nil, err
		}
		pubKey, err := childXPubKey.ECPubKey()
		if err != nil {
			return nil, err
		}
		principal, err := ECPubKeyToPrincipal(pubKey)
		if err != nil {
			return nil, err
		}
		result = append(result, principal)
	}
	return result, nil
}

func ECPubKeyToPrincipal(pubKey *btcec.PublicKey) (string, error) {
	der, err := EncodeECPubKey(pubKey)
	if err != nil {
		return "", err
	}
	return SelfAuthenticating(der), nil
}

func EncodeECPubKey(pubKey *btcec.PublicKey) ([]byte, error) {
	curve := btcec.S256()
	point := pubKey.ToECDSA()
	return asn1.Marshal(ECPubKey{
		Metadata: ECPubKeyMetadata{
			ECPubKeyOID:   asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1},
			NamedCurveOID: SECP256K1(),
		},
		PublicKey: asn1.BitString{
			Bytes: elliptic.Marshal(curve, point.X, point.Y),
		},
	})
}

func SECP256K1() asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{1, 3, 132, 0, 10}
}

func SelfAuthenticating(der []byte) string {
	digest := sha256.Sum224(der)
	tag := []byte{2}
	data := append(digest[:], tag...)
	crc := make([]byte, 4)
	binary.BigEndian.PutUint32(crc, crc32.ChecksumIEEE(data))
	encoder := base32.StdEncoding.WithPadding(base32.NoPadding)
	str := encoder.EncodeToString(append(crc, data...))
	return strings.Join(SplitN(strings.ToLower(str), 5), "-")
}

func SplitN(str string, n int) []string {
	if n >= len(str) {
		return []string{str}
	}
	var chunks []string
	chunk := make([]rune, n)
	i := 0
	for _, r := range str {
		chunk[i] = r
		i++
		if i == n {
			chunks = append(chunks, string(chunk))
			i = 0
		}
	}
	if i > 0 {
		chunks = append(chunks, string(chunk[:i]))
	}
	return chunks
}
