//go:build !icicle

package plonk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/accelerated/icicle"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Prove generates a PLONK proof from a SparseR1CS with full witness (secret + public part).
//
// NB! the provided proving key must contain the device pointers required for
// the acceleration. Initialize and deserialize the proving key using
// [NewProvingKey] and the serialization methods.
func Prove(ccs constraint.ConstraintSystem, pk plonk.ProvingKey, fullWitness witness.Witness, opts ...icicle.Option) (plonk.Proof, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

// Setup prepares the public data associated to a circuit + public inputs.
// The kzg SRS must be provided in canonical and lagrange form.
//
// The method wraps the [plonk.Setup] method, but the returned proving key
// contains device pointers for acceleration. To convert the key to a standard
// PLONK proving key, use the serialization methods.
func Setup(ccs constraint.ConstraintSystem, srs, srsLagrange kzg.SRS) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}

// NewProvingKey creates a new empty proving key for deserializing into.
//
// The method is compatible with [plonk.NewProvingKey], but returns an
// ICICLE proving key with device pointers for acceleration.
func NewProvingKey(curveID ecc.ID) plonk.ProvingKey {
	panic("icicle backend requested but program compiled without 'icicle' build tag")
}
