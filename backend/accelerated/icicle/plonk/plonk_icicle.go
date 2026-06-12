//go:build icicle

package plonk

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs_bls12377 "github.com/consensys/gnark/constraint/bls12-377"
	cs_bls12381 "github.com/consensys/gnark/constraint/bls12-381"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	cs_bw6761 "github.com/consensys/gnark/constraint/bw6-761"

	kzg_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/kzg"
	kzg_bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/kzg"
	kzg_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/kzg"
	kzg_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/kzg"

	icicle_bls12377 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bls12-377"
	icicle_bls12381 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bls12-381"
	icicle_bn254 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bn254"
	icicle_bw6761 "github.com/consensys/gnark/backend/accelerated/icicle/plonk/bw6-761"

	"github.com/consensys/gnark/backend/accelerated/icicle"
	"github.com/consensys/gnark/backend/accelerated/icicle/internal/gpuinit"
)

// Prove generates a PLONK proof from a SparseR1CS with full witness (secret + public part).
//
// NB! the provided proving key must contain the device pointers required for
// the acceleration. Initialize and deserialize the proving key using
// [NewProvingKey] and the serialization methods.
func Prove(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, fullWitness witness.Witness, opts ...icicle.Option) (plonk.Proof, error) {
	config, err := icicle.NewConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("initializing config: %w", err)
	}
	gpuinit.WarmUpOnce(config)
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		return icicle_bn254.Prove(tccs, pk.(*icicle_bn254.ProvingKey), fullWitness, config)
	case *cs_bls12377.SparseR1CS:
		return icicle_bls12377.Prove(tccs, pk.(*icicle_bls12377.ProvingKey), fullWitness, config)
	case *cs_bls12381.SparseR1CS:
		return icicle_bls12381.Prove(tccs, pk.(*icicle_bls12381.ProvingKey), fullWitness, config)
	case *cs_bw6761.SparseR1CS:
		return icicle_bw6761.Prove(tccs, pk.(*icicle_bw6761.ProvingKey), fullWitness, config)
	default:
		panic("icicle backend requested but constraint system is not of a supported curve")
	}
}

// Setup prepares the public data associated to a circuit + public inputs.
// The kzg SRS must be provided in canonical and lagrange form.
//
// The method wraps the [plonk.Setup] method, but the returned proving key
// contains device pointers for acceleration. To convert the key to a standard
// PLONK proving key, use the serialization methods.
func Setup(ccs constraint.ConstraintSystem, srs, srsLagrange kzg.SRS) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	switch tccs := ccs.(type) {
	case *cs_bn254.SparseR1CS:
		return icicle_bn254.Setup(tccs, *srs.(*kzg_bn254.SRS), *srsLagrange.(*kzg_bn254.SRS))
	case *cs_bls12377.SparseR1CS:
		return icicle_bls12377.Setup(tccs, *srs.(*kzg_bls12377.SRS), *srsLagrange.(*kzg_bls12377.SRS))
	case *cs_bls12381.SparseR1CS:
		return icicle_bls12381.Setup(tccs, *srs.(*kzg_bls12381.SRS), *srsLagrange.(*kzg_bls12381.SRS))
	case *cs_bw6761.SparseR1CS:
		return icicle_bw6761.Setup(tccs, *srs.(*kzg_bw6761.SRS), *srsLagrange.(*kzg_bw6761.SRS))
	default:
		panic("icicle backend requested but constraint system is not of a supported curve")
	}
}

// NewProvingKey creates a new empty proving key for deserializing into.
//
// The method is compatible with [plonk.NewProvingKey], but returns an
// ICICLE proving key with device pointers for acceleration.
func NewProvingKey(curveID ecc.ID) plonk.ProvingKey {
	switch curveID {
	case ecc.BN254:
		return icicle_bn254.NewProvingKey()
	case ecc.BLS12_377:
		return icicle_bls12377.NewProvingKey()
	case ecc.BLS12_381:
		return icicle_bls12381.NewProvingKey()
	case ecc.BW6_761:
		return icicle_bw6761.NewProvingKey()
	default:
		panic("icicle backend requested but curve is not supported")
	}
}
