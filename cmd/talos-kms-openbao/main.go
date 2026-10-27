// Command talos-kms-openbao is a Talos Linux KMS endpoint backed by an
// OpenBao/Vault transit key. See README.md for the threat model.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/siderolabs/kms-client/api/kms"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/fabianvaccaro/talos-kms-openbao/internal/kmsserver"
	"github.com/fabianvaccaro/talos-kms-openbao/internal/transit"
)

type config struct {
	listen     string
	tlsCert    string
	tlsKey     string
	insecure   bool
	baoAddr    string
	baoCA      string
	baoMount   string
	baoKey     string
	tokenFile  string
	renewEvery time.Duration
	allowlist  string
}

func parseFlags() config {
	var c config

	flag.StringVar(&c.listen, "listen", ":4050", "gRPC listen address")
	flag.StringVar(&c.tlsCert, "tls-cert", "", "server certificate (PEM)")
	flag.StringVar(&c.tlsKey, "tls-key", "", "server private key (PEM)")
	flag.BoolVar(&c.insecure, "insecure-no-tls", false, "serve plaintext gRPC (testing only)")
	flag.StringVar(&c.baoAddr, "bao-addr", "https://127.0.0.1:8200", "OpenBao address")
	flag.StringVar(&c.baoCA, "bao-ca", "", "CA bundle to verify OpenBao (PEM); system roots if empty")
	flag.StringVar(&c.baoMount, "bao-mount", "transit", "transit mount path")
	flag.StringVar(&c.baoKey, "bao-key", "talos-kms", "transit key name")
	flag.StringVar(&c.tokenFile, "token-file", "", "file holding the OpenBao token")
	flag.StringVar(&c.allowlist, "allowed-nodes", "", "file of node UUIDs allowed to seal/unseal, one per line (all nodes if empty)")
	flag.DurationVar(&c.renewEvery, "renew-every", time.Hour, "token self-renewal interval (0 disables)")
	flag.Parse()

	return c
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))

	if err := run(parseFlags(), log); err != nil {
		log.Error("exiting", "err", err)
		os.Exit(1)
	}
}

func run(c config, log *slog.Logger) error {
	if c.tokenFile == "" {
		return errors.New("-token-file is required")
	}

	httpClient, err := baoHTTPClient(c.baoCA)
	if err != nil {
		return err
	}

	client := transit.NewClient(httpClient, c.baoAddr, c.baoMount, c.baoKey, transit.NewFileToken(c.tokenFile))

	creds, err := serverCredentials(c)
	if err != nil {
		return err
	}

	lis, err := net.Listen("tcp", c.listen)
	if err != nil {
		return err
	}

	srv := grpc.NewServer(creds...)
	var policy kmsserver.NodePolicy = kmsserver.AllowAll{}
	if c.allowlist != "" {
		policy = kmsserver.NewFileAllowlist(c.allowlist)
	}

	kms.RegisterKMSServiceServer(srv, kmsserver.New(client, policy, log))

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	go renewLoop(ctx, client, c.renewEvery, log)

	go func() {
		<-ctx.Done()
		srv.GracefulStop()
	}()

	log.Info("listening", "addr", lis.Addr().String(), "tls", !c.insecure, "bao", c.baoAddr, "key", c.baoKey, "allowlist", c.allowlist)

	return srv.Serve(lis)
}

func serverCredentials(c config) ([]grpc.ServerOption, error) {
	if c.insecure {
		return nil, nil
	}

	if c.tlsCert == "" || c.tlsKey == "" {
		return nil, errors.New("-tls-cert and -tls-key are required (or -insecure-no-tls)")
	}

	cert, err := tls.LoadX509KeyPair(c.tlsCert, c.tlsKey)
	if err != nil {
		return nil, err
	}

	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	return []grpc.ServerOption{grpc.Creds(credentials.NewTLS(tlsCfg))}, nil
}

func baoHTTPClient(caPath string) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}

	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, err
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates in %s", caPath)
		}

		tlsCfg.RootCAs = pool
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
	}, nil
}

// renewLoop keeps a periodic token alive. A failure is logged and retried on
// the next tick; Seal/Unseal keep working until the token actually expires.
func renewLoop(ctx context.Context, r transit.TokenRenewer, every time.Duration, log *slog.Logger) {
	if every <= 0 {
		return
	}

	tick := time.NewTicker(every)
	defer tick.Stop()

	for {
		if err := r.RenewSelf(ctx); err != nil {
			log.Error("token renewal failed", "err", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}
