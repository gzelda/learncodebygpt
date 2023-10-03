package main

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	r1csbuilder "github.com/consensys/gnark/frontend/cs/r1cs"
	"log"
)

// Define your circuit structure
type SimpleCircuit struct {
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable //`gnark:",public"`
	Z frontend.Variable `gnark:",public"`
}

// Define the circuit's constraints
func (c *SimpleCircuit) Define(api frontend.API) error {
	// Ensure X + Y = Z

	api.AssertIsEqual(api.Add(c.X, c.Y), c.Z)
	return nil
}

func main() {
	// Compile the circuit into R1CS
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1csbuilder.NewBuilder, &SimpleCircuit{})
	if err != nil {
		log.Fatalf("Failed to compile the circuit: %v", err)
	}

	// Setup phase to produce proving and verification keys
	provingKey, verificationKey, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatalf("Failed to set up the keys: %v", err)
	}

	// Create a witness for the circuit
	var w SimpleCircuit
	w.X = frontend.Variable(10)
	w.Y = frontend.Variable(32)
	w.Z = frontend.Variable(42)

	witness, err := frontend.NewWitness(&w, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}
	publicWitness, _ := witness.Public()
	// Generate a zk-SNARK proof by witness
	proof, err := groth16.Prove(r1cs, provingKey, witness)
	if err != nil {
		log.Fatalf("Failed to create a proof: %v", err)
	}

	// Verify the proof by public witness
	err = groth16.Verify(proof, verificationKey, publicWitness)
	if err != nil {
		log.Fatalf("Failed to verify the proof: %v", err)
	}
}
