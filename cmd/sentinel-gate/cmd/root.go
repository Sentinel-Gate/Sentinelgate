// Package cmd provides the CLI commands for Sentinel Gate.
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Sentinel-Gate/Sentinelgate/internal/config"
)

var cfgFile string
var stateFilePath string

var rootCmd = &cobra.Command{
	Use:   "sentinel-gate",
	Short: "Sentinel Gate - MCP Security Proxy",
	Long: `Sentinel Gate is a security proxy for Model Context Protocol (MCP) servers.

It provides authentication, authorization, rate limiting, and audit logging
for MCP tool calls without requiring changes to the upstream MCP server.

Quick start:
  1. Create a config file: sentinel-gate.yaml
  2. Run: sentinel-gate start

Configuration:
  Config is loaded from sentinel-gate.yaml in the current directory,
  $HOME/.sentinel-gate/, or /etc/sentinel-gate/.

  Environment variables can override config values with the SENTINEL_GATE_ prefix.
  Example: SENTINEL_GATE_SERVER_HTTP_ADDR=:9090

Commands:
  start       Start the proxy server
  run         Run an agent with automatic security instrumentation
  stop        Stop the running server
  reset       Reset to clean state (remove state.json)
  hash-key    Generate SHA256 hash for an API key
  trust-ca    Add/remove the CA certificate to the OS trust store
  version     Print version information`,
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ./sentinel-gate.yaml)")
	rootCmd.PersistentFlags().StringVar(&stateFilePath, "state", "", "path to state.json file (default: ./state.json)")
}

func initConfig() {
	config.InitViper(cfgFile)
}
