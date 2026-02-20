package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

var hashKeyCmd = &cobra.Command{
	Use:   "hash-key [api-key]",
	Short: "Generate SHA256 hash for an API key",
	Long: `Generate a SHA256 hash of an API key for use in config.

The output format is "sha256:<hex>" which can be directly used
in the auth.api_keys.key_hash field.

Example:
  sentinel-gate hash-key "my-secret-api-key"
  # Output: sha256:7d5e8c...

Security note: The key will appear in shell history.
Consider clearing history after use or using environment variable:
  sentinel-gate hash-key "$MY_API_KEY"`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		key := args[0]
		hash := sha256.Sum256([]byte(key))
		fmt.Printf("sha256:%s\n", hex.EncodeToString(hash[:]))
	},
}

func init() {
	rootCmd.AddCommand(hashKeyCmd)
}
