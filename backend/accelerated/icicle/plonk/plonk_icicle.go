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
	switch ccs.(type) {
	case *cs_bn254.SparseR1CS:
		panic("bn254 icicle plonk prover not yet wired — Phase 3 (P3.5)")
	case *cs_bls12377.SparseR1CS:
		panic("not yet implemented — Phase 4")
	case *cs_bls12381.SparseR1CS:
		panic("not yet implemented — Phase 4")
	case *cs_bw6761.SparseR1CS:
		panic("not yet implemented — Phase 4")
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
	switch ccs.(type) {
	case *cs_bn254.SparseR1CS:
		panic("bn254 icicle plonk setup not yet wired — Phase 3 (P3.3)")
	case *cs_bls12377.SparseR1CS:
		panic("not yet implemented — Phase 4")
	case *cs_bls12381.SparseR1CS:
		panic("not yet implemented — Phase 4")
	case *cs_bw6761.SparseR1CS:
		panic("not yet implemented — Phase 4")
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
		panic("bn254 icicle plonk proving key not yet wired — Phase 3 (P3.3)")
	case ecc.BLS12_377:
		panic("not yet implemented — Phase 4")
	case ecc.BLS12_381:
		panic("not yet implemented — Phase 4")
	case ecc.BW6_761:
		panic("not yet implemented — Phase 4")
	default:
		panic("icicle backend requested but curve is not supported")
	}
}
