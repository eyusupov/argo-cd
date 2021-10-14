package apiclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	grpc_middleware "github.com/grpc-ecosystem/go-grpc-middleware"
	grpc_retry "github.com/grpc-ecosystem/go-grpc-middleware/retry"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	argogrpc "github.com/argoproj/argo-cd/v2/util/grpc"
	"github.com/argoproj/argo-cd/v2/common"
	"github.com/argoproj/argo-cd/v2/util/env"
	"github.com/argoproj/argo-cd/v2/util/io"
	argotls "github.com/argoproj/argo-cd/v2/util/tls"
	"fmt"
)

const (
	// MaxGRPCMessageSize contains max grpc message size
	MaxGRPCMessageSize = 100 * 1024 * 1024
)

// TLSConfiguration describes parameters for TLS configuration to be used by a repo server API client
type TLSConfiguration struct {
	// Whether to disable TLS for connections
	DisableTLS bool
	// Whether to enforce strict validation of TLS certificates
	StrictValidation bool
	// List of certificates to validate the peer against (if StrictCerts is true)
	Certificates *x509.CertPool
	ClientCertificates []tls.Certificate
}

// Clientset represents repository server api clients
type Clientset interface {
	NewRepoServerClient() (io.Closer, RepoServerServiceClient, error)
}

type clientSet struct {
	address        string
	timeoutSeconds int
	tlsConfig      TLSConfiguration
}

func NewTLSConfiguration(repoServerPlaintext bool, repoServerStrictTLS bool) (TLSConfiguration, error) {
	tlsConfig := TLSConfiguration{
		DisableTLS:       repoServerPlaintext,
		StrictValidation: repoServerStrictTLS,
	}
	// Load CA information to use for validating connections to the
	// repository server, if strict TLS validation was requested.
	if !repoServerPlaintext {
		if repoServerStrictTLS {
			pool, err := argotls.LoadX509CertPool(
				fmt.Sprintf("%s/reposerver/tls/tls.crt", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)),
				fmt.Sprintf("%s/reposerver/tls/ca.crt", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath)),
			)
			if err != nil {
				log.Fatalf("%v", err)
			}
			tlsConfig.Certificates = pool
		}

		clientCertPath := fmt.Sprintf("%s/reposerver-client/tls/tls.crt", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath))
		clientKeyPath := fmt.Sprintf("%s/reposerver-client/tls/tls.key", env.StringFromEnv(common.EnvAppConfigPath, common.DefaultAppConfigPath))

		tlsCertExists := false
		tlsKeyExists := false

		_, err := os.Stat(clientCertPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Warnf("could not read TLS cert from %s: %v", clientCertPath, err)
			}
		} else {
			tlsCertExists = true
		}

		_, err = os.Stat(clientKeyPath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Warnf("could not read TLS key from %s: %v", clientKeyPath, err)
			}
		} else {
			tlsKeyExists = true
		}

		if tlsKeyExists && tlsCertExists {
			certificate, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
			if err != nil {
				return TLSConfiguration{}, fmt.Errorf("Unable to initalize repo server client gRPC TLS configuration with client cert=%s and key=%s: %v", clientCertPath, clientKeyPath, err)
			}
			tlsConfig.ClientCertificates = []tls.Certificate{certificate}
		}
	}
	return tlsConfig, nil
}

func (c *clientSet) NewRepoServerClient() (io.Closer, RepoServerServiceClient, error) {
	conn, err := NewConnection(c.address, c.timeoutSeconds, &c.tlsConfig)
	if err != nil {
		return nil, nil, err
	}
	return conn, NewRepoServerServiceClient(conn), nil
}

func NewConnection(address string, timeoutSeconds int, tlsConfig *TLSConfiguration) (*grpc.ClientConn, error) {
	retryOpts := []grpc_retry.CallOption{
		grpc_retry.WithMax(3),
		grpc_retry.WithBackoff(grpc_retry.BackoffLinear(1000 * time.Millisecond)),
	}
	unaryInterceptors := []grpc.UnaryClientInterceptor{grpc_retry.UnaryClientInterceptor(retryOpts...)}
	if timeoutSeconds > 0 {
		unaryInterceptors = append(unaryInterceptors, argogrpc.WithTimeout(time.Duration(timeoutSeconds)*time.Second))
	}
	opts := []grpc.DialOption{
		grpc.WithStreamInterceptor(grpc_retry.StreamClientInterceptor(retryOpts...)),
		grpc.WithUnaryInterceptor(grpc_middleware.ChainUnaryClient(unaryInterceptors...)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(MaxGRPCMessageSize), grpc.MaxCallSendMsgSize(MaxGRPCMessageSize)),
	}

	tlsC := &tls.Config{}
	if !tlsConfig.DisableTLS {
		if !tlsConfig.StrictValidation {
			tlsC.InsecureSkipVerify = true
		} else {
			tlsC.RootCAs = tlsConfig.Certificates
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsC)))
	} else {
		if len(tlsConfig.ClientCertificates) == 0 {
			opts = append(opts, grpc.WithInsecure())
		} else {
			tlsC.Certificates = tlsConfig.ClientCertificates
		}
	}

	conn, err := grpc.Dial(address, opts...)
	if err != nil {
		log.Errorf("Unable to connect to repository service with address %s", address)
		return nil, err
	}
	return conn, nil
}

// NewRepoServerClientset creates new instance of repo server Clientset
func NewRepoServerClientset(address string, timeoutSeconds int, tlsConfig TLSConfiguration) Clientset {
	return &clientSet{address: address, timeoutSeconds: timeoutSeconds, tlsConfig: tlsConfig}
}
