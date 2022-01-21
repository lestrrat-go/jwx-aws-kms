package jwxkms

import (
	"context"
	"crypto"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
	"github.com/lestrrat-go/jwx/jwa"
)

type RSA struct {
	alg    jwa.SignatureAlgorithm
	client *kms.Client
	ctx    context.Context
	kid    string
}

func NewRSA(client *kms.Client) *RSA {
	return &RSA{
		client: client,
	}
}

func (sv *RSA) WithAlgorithm(alg jwa.SignatureAlgorithm) *RSA {
	return &RSA{
		alg:    alg,
		client: sv.client,
		ctx:    sv.ctx,
		kid:    sv.kid,
	}
}

// WithContext creates a new RSA object with the context.Context
// associated with it.
func (sv *RSA) WithContext(ctx context.Context) *RSA {
	return &RSA{
		alg:    sv.alg,
		client: sv.client,
		ctx:    ctx,
		kid:    sv.kid,
	}
}

// WithKeyID creates a new RSA object with the key ID
// associated with it.
func (sv *RSA) WithKeyID(kid string) *RSA {
	return &RSA{
		alg:    sv.alg,
		client: sv.client,
		ctx:    sv.ctx,
		kid:    kid,
	}
}

func getRSAParams(alg jwa.SignatureAlgorithm) (crypto.Hash, types.SigningAlgorithmSpec, error) {
	switch alg {
	case jwa.RS256:
		return crypto.SHA256, types.SigningAlgorithmSpecRsassaPkcs1V15Sha256, nil
	case jwa.RS384:
		return crypto.SHA384, types.SigningAlgorithmSpecRsassaPkcs1V15Sha384, nil
	case jwa.RS512:
		return crypto.SHA512, types.SigningAlgorithmSpecRsassaPkcs1V15Sha512, nil
	default:
		return crypto.Hash(0), types.SigningAlgorithmSpec(""), fmt.Errorf(`unsupported algorithm %q`, alg.String())
	}
}

// Sign generates a signature for the given payload using AWS KMS.
func (sv *RSA) Sign(payload []byte) ([]byte, error) {
	if sv.kid == "" {
		return nil, fmt.Errorf(`aws.RSA.Sign() requires the key ID`)
	}
	if sv.ctx == nil {
		return nil, fmt.Errorf(`aws.RSA.Sign() required context.Context`)
	}

	hash, algspec, err := getRSAParams(sv.alg)
	if err != nil {
		return nil, err
	}

	h := hash.New()
	if _, err := h.Write(payload); err != nil {
		return nil, fmt.Errorf(`failed to write payload to hash: %w`, err)
	}
	input := kms.SignInput{
		KeyId:            aws.String(sv.kid),
		Message:          h.Sum(nil),
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: algspec,
	}
	signed, err := sv.client.Sign(sv.ctx, &input)
	if err != nil {
		return nil, fmt.Errorf(`failed to sign via KMS: %w`, err)
	}

	return signed.Signature, nil
}

func (sv *RSA) Verify(payload []byte, signature []byte) error {
	if sv.kid == "" {
		return fmt.Errorf(`aws.RSA.Sign() requires the key ID`)
	}
	if sv.ctx == nil {
		return fmt.Errorf(`aws.RSA.Sign() required context.Context`)
	}

	hash, algspec, err := getRSAParams(sv.alg)
	if err != nil {
		return err
	}

	h := hash.New()
	if _, err := h.Write(payload); err != nil {
		return fmt.Errorf(`failed to write payload to hash: %w`, err)
	}

	input := kms.VerifyInput{
		KeyId:            aws.String(sv.kid),
		Message:          h.Sum(nil),
		MessageType:      types.MessageTypeDigest,
		Signature:        signature,
		SigningAlgorithm: algspec,
	}
	out, err := sv.client.Verify(sv.ctx, &input)
	if err != nil {
		return fmt.Errorf(`failed to sign via KMS: %w`, err)
	}

	if !out.SignatureValid {
		return fmt.Errorf(`invalid signature`)
	}

	return nil
}
