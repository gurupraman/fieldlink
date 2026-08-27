package main

import (
	"crypto/ed25519"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/gurupraman/fieldlink/internal/grant"
)

func newGrantCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "grant",
		Short: "Generate, sign, and verify capability grants",
	}
	cmd.AddCommand(newGrantKeygenCmd())
	cmd.AddCommand(newGrantSignCmd())
	cmd.AddCommand(newGrantVerifyCmd())
	return cmd
}

func newGrantKeygenCmd() *cobra.Command {
	var outKey, outPub string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate an Ed25519 signing keypair",
		Long: "Generate an Ed25519 signing keypair. The private key must be used " +
			"offline only — copy it off this machine and never onto a FieldLink " +
			"host. Only the public key (trusted.pub) belongs on the host.",
		RunE: func(cmd *cobra.Command, args []string) error {
			pub, priv, err := grant.GenerateKeyPair()
			if err != nil {
				return fmt.Errorf("keygen: %w", err)
			}
			if err := grant.WritePrivateKeyFile(outKey, priv); err != nil {
				return fmt.Errorf("keygen: %w", err)
			}
			if err := grant.WritePublicKeyFile(outPub, pub); err != nil {
				return fmt.Errorf("keygen: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote private key: %s (fingerprint %s)\n", outKey, grant.Fingerprint(pub))
			fmt.Fprintf(cmd.OutOrStdout(), "Wrote public key:  %s\n", outPub)
			fmt.Fprintln(cmd.OutOrStdout(), "\nMove the private key offline now. Deploy only the public key to a FieldLink host, as trusted.pub.")
			return nil
		},
	}
	cmd.Flags().StringVar(&outKey, "out-key", "signing.key", "path to write the private signing key")
	cmd.Flags().StringVar(&outPub, "out-pub", "trusted.pub", "path to write the public key")
	return cmd
}

func newGrantSignCmd() *cobra.Command {
	var grantPath, keyPath, outPath string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a grant document with an offline signing key",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(grantPath)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			g, canonical, err := grant.ParseYAML(data)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}
			if err := g.Validate(); err != nil {
				return fmt.Errorf("sign: grant is invalid: %w", err)
			}

			priv, err := grant.ReadPrivateKeyFile(keyPath)
			if err != nil {
				return fmt.Errorf("sign: %w", err)
			}

			sig := grant.Sign(priv, canonical)
			if outPath == "" {
				outPath = grantPath + ".sig"
			}
			if err := grant.WriteSignatureFile(outPath, sig); err != nil {
				return fmt.Errorf("sign: %w", err)
			}

			pub := priv.Public().(ed25519.PublicKey)
			fmt.Fprintf(cmd.OutOrStdout(), "Signed %s (grant_id=%s, agent_id=%s, expires=%s)\n",
				grantPath, g.GrantID, g.AgentID, g.ExpiresAt.Format("2006-01-02"))
			fmt.Fprintf(cmd.OutOrStdout(), "Signature written to %s (key fingerprint %s)\n", outPath, grant.Fingerprint(pub))
			return nil
		},
	}
	cmd.Flags().StringVar(&grantPath, "grant", "", "path to the unsigned grant.yaml (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "path to the offline signing key (required)")
	cmd.Flags().StringVar(&outPath, "out", "", "path to write the signature (default: <grant>.sig)")
	cmd.MarkFlagRequired("grant")
	cmd.MarkFlagRequired("key")
	return cmd
}

func newGrantVerifyCmd() *cobra.Command {
	var grantPath, sigPath, pubPath string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify a grant's signature against a trusted public key",
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(grantPath)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			g, canonical, err := grant.ParseYAML(data)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			if err := g.Validate(); err != nil {
				return fmt.Errorf("verify: grant is invalid: %w", err)
			}

			if sigPath == "" {
				sigPath = grantPath + ".sig"
			}
			sig, err := grant.ReadSignatureFile(sigPath)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}
			pub, err := grant.ReadPublicKeyFile(pubPath)
			if err != nil {
				return fmt.Errorf("verify: %w", err)
			}

			if !grant.Verify(pub, canonical, sig) {
				return fmt.Errorf("verify: signature does NOT match %s under key %s", grantPath, pubPath)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "OK: %s is validly signed (grant_id=%s, agent_id=%s, expires=%s, key fingerprint %s)\n",
				grantPath, g.GrantID, g.AgentID, g.ExpiresAt.Format("2006-01-02"), grant.Fingerprint(pub))
			return nil
		},
	}
	cmd.Flags().StringVar(&grantPath, "grant", "", "path to grant.yaml (required)")
	cmd.Flags().StringVar(&sigPath, "sig", "", "path to the signature file (default: <grant>.sig)")
	cmd.Flags().StringVar(&pubPath, "pubkey", "", "path to the trusted public key (required)")
	cmd.MarkFlagRequired("grant")
	cmd.MarkFlagRequired("pubkey")
	return cmd
}
