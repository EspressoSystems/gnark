// Package plonk implements PLONK proof system with ICICLE acceleration.
package plonk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
)

// Verify verifies a PLONK proof. It wraps [plonk.Verify] function, but is provided for completeness.
func Verify(proof plonk.Proof, vk plonk.VerifyingKey, publicWitness witness.Witness, opts ...backend.VerifierOption) error {
	return plonk.Verify(proof, vk, publicWitness, opts...)
}

// NewVerifyingKey creates a new empty verifying key for deserializing into. It is compatible with [plonk.NewVerifyingKey].
func NewVerifyingKey(curveID ecc.ID) plonk.VerifyingKey {
	return plonk.NewVerifyingKey(curveID)
}

// NewProof creates a new empty proof for deserializing into. It is compatible with [plonk.NewProof].
func NewProof(curveID ecc.ID) plonk.Proof {
	return plonk.NewProof(curveID)
}

// NewCS creates new typed SparseR1CS constraint system for the given curve. It is compatible with [plonk.NewCS].
// It is used for deserializing SparseR1CS constraint systems.
func NewCS(curveID ecc.ID) constraint.ConstraintSystem {
	return plonk.NewCS(curveID)
}
