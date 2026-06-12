//go:build icicle

package plonk_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	icicle_plonk "github.com/consensys/gnark/backend/accelerated/icicle/plonk"
	native_plonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/consensys/gnark/test/unsafekzg"
)

// testCurves lists the curves wired into the ICICLE PLONK backend. bn254
// landed in Phase 3, bls12-377 in P4.1, bls12-381 in P4.2, bw6-761 in P4.3.
var testCurves = []ecc.ID{ecc.BN254, ecc.BLS12_377, ecc.BLS12_381, ecc.BW6_761}

// circuit mirrors the groth16 ICICLE marshal-test circuit adapted to the
// PLONK scs builder: two public inputs (>1, exercising the nbPublic window
// geometry of the L/R/O commitments) and one private witness.
type circuit struct {
	A, B frontend.Variable `gnark:",public"`
	Res  frontend.Variable
}

func (c *circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(c.A, c.B), c.Res)
	return nil
}

// pkBytes returns the WriteTo serialization of a proving key. The icicle
// wrapper embeds the native key BY VALUE, so the streams of a native and an
// icicle key are directly comparable — PLONK has no IsDifferent, and a byte
// comparison is strictly stronger anyway (DESIGN.md §11.3).
func pkBytes(t *testing.T, pk native_plonk.ProvingKey) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	if _, err := pk.WriteTo(buf); err != nil {
		t.Fatalf("pk WriteTo: %v", err)
	}
	return buf.Bytes()
}

// testMarshalNativeToIcicle: native Setup → WriteTo → ReadFrom into the
// icicle ProvingKey → icicle Prove → the UNMODIFIED native plonk.Verify
// accepts. Also asserts the TestProver invariant: icicle Prove must not
// mutate the proving key bytes (this additionally guards against any write
// to the shared host SRS backing arrays).
func testMarshalNativeToIcicle(t *testing.T, curve ecc.ID) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &circuit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)

	nativePK, vk, err := native_plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)
	iciPK := icicle_plonk.NewProvingKey(curve)
	buf := new(bytes.Buffer)
	_, err = nativePK.WriteTo(buf)
	assert.NoError(err)
	_, err = iciPK.ReadFrom(buf)
	assert.NoError(err)
	if !bytes.Equal(pkBytes(t, nativePK), pkBytes(t, iciPK)) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, curve.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	pkBefore := pkBytes(t, iciPK)
	proofNative, err := native_plonk.Prove(ccs, nativePK, w)
	assert.NoError(err)
	proofIcicle, err := icicle_plonk.Prove(ccs, iciPK, w)
	assert.NoError(err)
	if !bytes.Equal(pkBefore, pkBytes(t, iciPK)) {
		t.Error("icicle Prove mutated the proving key")
	}

	err = native_plonk.Verify(proofNative, vk, pw)
	assert.NoError(err)
	err = native_plonk.Verify(proofIcicle, vk, pw)
	assert.NoError(err)
}

// testMarshalIcicleToNative: icicle Setup → WriteTo → ReadFrom into a native
// proving key → native Prove verifies; and icicle Prove with the
// icicle-Setup key also verifies.
func testMarshalIcicleToNative(t *testing.T, curve ecc.ID) {
	assert := test.NewAssert(t)
	ccs, err := frontend.Compile(curve.ScalarField(), scs.NewBuilder, &circuit{})
	assert.NoError(err)
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	assert.NoError(err)

	iciPK, vk, err := icicle_plonk.Setup(ccs, srs, srsLagrange)
	assert.NoError(err)
	nativePK := native_plonk.NewProvingKey(curve)
	buf := new(bytes.Buffer)
	_, err = iciPK.WriteTo(buf)
	assert.NoError(err)
	_, err = nativePK.ReadFrom(buf)
	assert.NoError(err)
	if !bytes.Equal(pkBytes(t, iciPK), pkBytes(t, nativePK)) {
		t.Error("marshal output difference")
	}

	assignment := circuit{A: 3, B: 5, Res: 15}
	w, err := frontend.NewWitness(&assignment, curve.ScalarField())
	assert.NoError(err)
	pw, err := w.Public()
	assert.NoError(err)

	pkBefore := pkBytes(t, iciPK)
	proofNative, err := native_plonk.Prove(ccs, nativePK, w)
	assert.NoError(err)
	proofIcicle, err := icicle_plonk.Prove(ccs, iciPK, w)
	assert.NoError(err)
	if !bytes.Equal(pkBefore, pkBytes(t, iciPK)) {
		t.Error("icicle Prove mutated the proving key")
	}

	err = native_plonk.Verify(proofNative, vk, pw)
	assert.NoError(err)
	err = native_plonk.Verify(proofIcicle, vk, pw)
	assert.NoError(err)
}

func TestMarshalNativeToIcicle(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(fmt.Sprintf("curve=%s", curve.String()), func(t *testing.T) {
			testMarshalNativeToIcicle(t, curve)
		})
	}
}

func TestMarshalIcicleToNative(t *testing.T) {
	for _, curve := range testCurves {
		t.Run(fmt.Sprintf("curve=%s", curve.String()), func(t *testing.T) {
			testMarshalIcicleToNative(t, curve)
		})
	}
}
