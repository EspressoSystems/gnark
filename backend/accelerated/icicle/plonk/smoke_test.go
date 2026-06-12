//go:build icicle

package plonk_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	icicle_groth16 "github.com/consensys/gnark/backend/accelerated/icicle/groth16"
	icicle_plonk "github.com/consensys/gnark/backend/accelerated/icicle/plonk"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// TestMixedGroth16PlonkSmoke is the sequential mixed-use gate (DESIGN.md
// §11.6, doc.go coexistence contract item 2): groth16 → plonk → groth16 GPU
// proves in ONE process on one device, bn254, small circuits. The plonk
// package owns no NTT-domain state, so the groth16 ICICLE backend's domain
// and the shared gpuinit warm-up must be unaffected by the interleaved plonk
// prove — every proof must verify. Modeled on
// backend/accelerated/icicle/groth16/marshal_test.go.
func TestMixedGroth16PlonkSmoke(t *testing.T) {
	assert := test.NewAssert(t)
	curve := ecc.BN254
	assignment := circuit{A: 3, B: 5, Res: 15}

	// groth16 leg (r1cs builder).
	g16Ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit{})
	assert.NoError(err)
	g16Pk, g16Vk, err := icicle_groth16.Setup(g16Ccs)
	assert.NoError(err)
	g16W, err := frontend.NewWitness(&assignment, curve.ScalarField())
	assert.NoError(err)
	g16Pub, err := g16W.Public()
	assert.NoError(err)

	// plonk leg (scs builder).
	plonkCcs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &circuit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(plonkCcs)
	assert.NoError(err)
	plonkPk, plonkVk, err := icicle_plonk.Setup(plonkCcs, srs, srsLagrange)
	assert.NoError(err)
	plonkW, err := frontend.NewWitness(&assignment, curve.ScalarField())
	assert.NoError(err)
	plonkPub, err := plonkW.Public()
	assert.NoError(err)

	// 1. groth16 GPU prove.
	g16Proof1, err := icicle_groth16.Prove(g16Ccs, g16Pk, g16W)
	assert.NoError(err)
	assert.NoError(icicle_groth16.Verify(g16Proof1, g16Vk, g16Pub))

	// 2. plonk GPU prove, unmodified native verifier.
	plonkProof, err := icicle_plonk.Prove(plonkCcs, plonkPk, plonkW)
	assert.NoError(err)
	assert.NoError(native_plonk.Verify(plonkProof, plonkVk, plonkPub))

	// 3. groth16 GPU prove again — plonk must not have disturbed the groth16
	// backend's device state.
	g16Proof2, err := icicle_groth16.Prove(g16Ccs, g16Pk, g16W)
	assert.NoError(err)
	assert.NoError(icicle_groth16.Verify(g16Proof2, g16Vk, g16Pub))
}
