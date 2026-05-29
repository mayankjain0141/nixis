// SPDX-License-Identifier: MIT
package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	internaldel "github.com/mayjain/aegis/internal/delegation"
	"github.com/spf13/cobra"
)

var delegationCmd = &cobra.Command{
	Use:   "delegation",
	Short: "Delegation token operations",
}

var (
	delegIssuer   string
	delegAudience string
	delegExpires  time.Duration
	delegKeyFile  string
)

var delegationIssueCmd = &cobra.Command{
	Use:   "issue",
	Short: "Issue a signed delegation token",
	RunE:  runDelegationIssue,
}

var (
	delegRevokeChainID string
	delegRevokeSocket  string
)

var delegationRevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revoke a delegation chain by ID",
	RunE:  runDelegationRevoke,
}

var delegationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active delegation chains",
	RunE:  runDelegationList,
}

var (
	delegVerifyKeyFile string
)

var delegationVerifyCmd = &cobra.Command{
	Use:   "verify <token-file>",
	Short: "Verify a delegation token file",
	Args:  cobra.ExactArgs(1),
	RunE:  runDelegationVerify,
}

func init() {
	delegationIssueCmd.Flags().StringVar(&delegIssuer, "issuer", "", "Issuer name")
	delegationIssueCmd.Flags().StringVar(&delegAudience, "audience", "", "Audience name")
	delegationIssueCmd.Flags().DurationVar(&delegExpires, "expires", time.Hour, "Token validity duration")
	delegationIssueCmd.Flags().StringVar(&delegKeyFile, "key", "", "Path to Ed25519 private key file (JSON); generated if omitted")

	delegationRevokeCmd.Flags().StringVar(&delegRevokeChainID, "chain-id", "", "Chain ID to revoke")
	delegationRevokeCmd.Flags().StringVar(&delegRevokeSocket, "socket", "", "Daemon socket path (default: $AEGIS_SOCKET_PATH or /tmp/aegis.sock)")

	delegationVerifyCmd.Flags().StringVar(&delegVerifyKeyFile, "key", "", "Path to Ed25519 public key file (JSON); read from token file if omitted")

	delegationCmd.AddCommand(delegationIssueCmd)
	delegationCmd.AddCommand(delegationRevokeCmd)
	delegationCmd.AddCommand(delegationListCmd)
	delegationCmd.AddCommand(delegationVerifyCmd)
}

// tokenFile is the on-disk JSON format for a delegation token with embedded keys.
type tokenFile struct {
	Token     internaldel.DelegationToken `json:"token"`
	PublicKey []byte                      `json:"public_key"`
	Signature []byte                      `json:"signature"`
}

func runDelegationIssue(cmd *cobra.Command, _ []string) error {
	var privKey ed25519.PrivateKey
	var pubKey ed25519.PublicKey

	if delegKeyFile != "" {
		data, err := os.ReadFile(delegKeyFile)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		var kf struct {
			PrivateKey []byte `json:"private_key"`
			PublicKey  []byte `json:"public_key"`
		}
		if err := json.Unmarshal(data, &kf); err != nil {
			return fmt.Errorf("parse key file: %w", err)
		}
		if len(kf.PrivateKey) != ed25519.PrivateKeySize {
			return fmt.Errorf("key file: private key must be %d bytes", ed25519.PrivateKeySize)
		}
		privKey = ed25519.PrivateKey(kf.PrivateKey)
		pubKey = ed25519.PublicKey(kf.PublicKey)
	} else {
		var err error
		pubKey, privKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			return fmt.Errorf("generate key pair: %w", err)
		}
	}

	tok := internaldel.DelegationToken{
		Issuer:    delegIssuer,
		Audience:  delegAudience,
		ExpiresAt: time.Now().Add(delegExpires),
		MaxDepth:  1,
		Capabilities: internaldel.CapabilitySet{
			Operations: 0xFFFF,
			Effects:    0xFFFF,
			Resources:  0xFFFF,
			MaxRisk:    0xFF,
		},
	}

	sig, err := signToken(&tok, privKey)
	if err != nil {
		return fmt.Errorf("sign token: %w", err)
	}
	tok.Signature = sig

	out := tokenFile{
		Token:     tok,
		PublicKey: []byte(pubKey),
		Signature: sig,
	}

	outBytes, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal token: %w", err)
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), string(outBytes))
	return nil
}

// signToken signs the canonical bytes of a DelegationToken using privKey.
func signToken(tok *internaldel.DelegationToken, privKey ed25519.PrivateKey) ([]byte, error) {
	msg := tok.CanonicalBytes()
	return ed25519.Sign(privKey, msg), nil
}

// daemonBaseURL returns the HTTP base URL for the daemon's management API.
// Overridable in tests.
var daemonBaseURL = func() string {
	return "http://127.0.0.1:9091"
}

func runDelegationRevoke(cmd *cobra.Command, _ []string) error {
	if delegRevokeChainID == "" {
		return fmt.Errorf("--chain-id is required")
	}
	body := fmt.Sprintf(`{"chain_id":%q}`, delegRevokeChainID)
	resp, err := http.Post(
		daemonBaseURL()+"/api/v1/delegation/revoke",
		"application/json",
		strings.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("cannot connect to daemon: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned %d", resp.StatusCode)
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "revoked chain %s\n", delegRevokeChainID)
	return nil
}

func runDelegationList(cmd *cobra.Command, _ []string) error {
	resp, err := http.Get(daemonBaseURL() + "/api/v1/delegation/list")
	if err != nil {
		return fmt.Errorf("cannot connect to daemon: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("daemon returned %d", resp.StatusCode)
	}
	var result struct {
		Chains []internaldel.ActiveChainInfo `json:"chains"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	if len(result.Chains) == 0 {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "no active delegation chains")
		return nil
	}
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-40s  %s\n", "CHAIN ID", "EXPIRES AT")
	for _, c := range result.Chains {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "%-40s  %s\n", c.ChainID, c.ExpiresAt.Format(time.RFC3339))
	}
	return nil
}

func runDelegationVerify(cmd *cobra.Command, args []string) error {
	tokenPath := args[0]

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return fmt.Errorf("read token file: %w", err)
	}

	var tf tokenFile
	if err := json.Unmarshal(data, &tf); err != nil {
		return fmt.Errorf("parse token file: %w", err)
	}

	// Resolve public key: flag overrides embedded key.
	var pubKey ed25519.PublicKey
	if delegVerifyKeyFile != "" {
		keyData, err := os.ReadFile(delegVerifyKeyFile)
		if err != nil {
			return fmt.Errorf("read key file: %w", err)
		}
		var kf struct {
			PublicKey []byte `json:"public_key"`
		}
		if err := json.Unmarshal(keyData, &kf); err != nil {
			return fmt.Errorf("parse key file: %w", err)
		}
		pubKey = ed25519.PublicKey(kf.PublicKey)
	} else {
		if len(tf.PublicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid: embedded public key is %d bytes, need %d", len(tf.PublicKey), ed25519.PublicKeySize)
		}
		pubKey = ed25519.PublicKey(tf.PublicKey)
	}

	if len(pubKey) != ed25519.PublicKeySize {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "invalid: public key is %d bytes, need %d\n",
			len(pubKey), ed25519.PublicKeySize)
		return fmt.Errorf("invalid signature")
	}

	msg := tf.Token.CanonicalBytes()
	if !ed25519.Verify(pubKey, msg, tf.Signature) {
		_, _ = fmt.Fprintln(cmd.OutOrStdout(), "invalid: signature verification failed")
		return fmt.Errorf("invalid signature")
	}

	_, _ = fmt.Fprintf(cmd.OutOrStdout(), "valid: issuer=%s audience=%s expires=%s\n",
		tf.Token.Issuer, tf.Token.Audience, tf.Token.ExpiresAt.Format(time.RFC3339))
	return nil
}
