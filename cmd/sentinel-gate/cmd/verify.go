package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	evidence "github.com/Sentinel-Gate/Sentinelgate/internal/adapter/outbound/evidence"
)

var verifyEvidenceFile string
var verifyKeyFile string
var verifyPubKeyFile string

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify cryptographic evidence chain integrity",
	Long: `Verify the integrity of an evidence file produced by SentinelGate.

Checks:
  1. Every record's ECDSA P-256 signature is valid
  2. The hash chain is unbroken (each record references the previous)
  3. No records have been tampered with, inserted, or removed

Usage:
  sentinel-gate verify --evidence-file evidence.jsonl --key-file evidence-key.pem
  sentinel-gate verify --evidence-file evidence.jsonl --pub-key public-key.pem`,
	Run: runVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringVar(&verifyEvidenceFile, "evidence-file", "", "Path to evidence JSONL file (required)")
	verifyCmd.Flags().StringVar(&verifyKeyFile, "key-file", "", "Path to evidence signing key PEM file (private key)")
	verifyCmd.Flags().StringVar(&verifyPubKeyFile, "pub-key", "", "Path to PEM public key file (preferred for external verification)")
	verifyCmd.MarkFlagRequired("evidence-file")
	verifyCmd.MarkFlagsOneRequired("key-file", "pub-key")
	verifyCmd.MarkFlagsMutuallyExclusive("key-file", "pub-key")
}

func runVerify(cmd *cobra.Command, args []string) {
	fmt.Printf("Verifying evidence file: %s\n", verifyEvidenceFile)

	var result *evidence.VerifyResult
	var err error

	if verifyPubKeyFile != "" {
		fmt.Printf("Using public key: %s\n\n", verifyPubKeyFile)
		pubKeyPEM, readErr := os.ReadFile(verifyPubKeyFile)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "Error reading public key: %v\n", readErr)
			os.Exit(1)
		}
		result, err = evidence.VerifyFileWithPubKey(verifyEvidenceFile, pubKeyPEM)
	} else {
		fmt.Printf("Using key: %s\n\n", verifyKeyFile)
		result, err = evidence.VerifyFile(verifyEvidenceFile, verifyKeyFile)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Records:          %d\n", result.TotalRecords)
	fmt.Printf("Valid signatures: %d\n", result.ValidSignatures)
	fmt.Printf("Invalid:          %d\n", result.InvalidSigs)

	if result.ChainValid {
		if result.PartialChain {
			fmt.Printf("Hash chain:       VALID (partial — starts mid-chain)\n")
		} else {
			fmt.Printf("Hash chain:       VALID (complete from genesis)\n")
		}
	} else {
		fmt.Printf("Hash chain:       BROKEN at record %d\n", result.ChainBreakAt)
	}

	if result.FirstError != "" {
		fmt.Printf("\nFirst error: %s\n", result.FirstError)
	}

	fmt.Println()

	if result.InvalidSigs == 0 && result.ChainValid && result.TotalRecords > 0 {
		fmt.Println("PASS - Evidence chain is intact and all signatures are valid.")
	} else if result.TotalRecords == 0 {
		fmt.Println("FAIL - Evidence file contains no records.")
		os.Exit(1)
	} else {
		fmt.Println("FAIL - Evidence chain has been tampered with.")
		os.Exit(1)
	}
}
