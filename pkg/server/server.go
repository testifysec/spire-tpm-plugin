/*
 ** Copyright 2019 Bloomberg Finance L.P.
 **
 ** Licensed under the Apache License, Version 2.0 (the "License");
 ** you may not use this file except in compliance with the License.
 ** You may obtain a copy of the License at
 **
 **     http://www.apache.org/licenses/LICENSE-2.0
 **
 ** Unless required by applicable law or agreed to in writing, software
 ** distributed under the License is distributed on an "AS IS" BASIS,
 ** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 ** See the License for the specific language governing permissions and
 ** limitations under the License.
 */

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/google/go-attestation/attest"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	gx509 "github.com/google/certificate-transparency-go/x509"
	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
)

// TPMAttestorPlugin implements the nodeattestor Plugin interface
type TPMAttestorPlugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	config *TPMAttestorPluginConfig
}

type TPMAttestorPluginConfig struct {
	trustDomain string
	CaPath      string `hcl:"ca_path"`
	HashPath    string `hcl:"hash_path"`
}

func New() *TPMAttestorPlugin {
	return &TPMAttestorPlugin{}
}

func NewFromConfig(config *TPMAttestorPluginConfig) *TPMAttestorPlugin {
	return &TPMAttestorPlugin{config: config}
}

func (p *TPMAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := &TPMAttestorPluginConfig{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, fmt.Errorf("failed to decode configuration file: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, errors.New("core configuration is required")
	}
	if req.CoreConfiguration.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}
	if config.CaPath != "" {
		if _, err := os.Stat(config.CaPath); os.IsNotExist(err) {
			return nil, errors.New(fmt.Sprintf("ca_path '%s' does not exist", config.CaPath))
		}
	} else {
		var tryCaPath = "/opt/spire/.data/certs"
		if _, err := os.Stat(tryCaPath); !os.IsNotExist(err) {
			config.CaPath = tryCaPath
		}
	}
	if config.HashPath != "" {
		if _, err := os.Stat(config.HashPath); os.IsNotExist(err) {
			return nil, errors.New(fmt.Sprintf("hash_path '%s' does not exist", config.HashPath))
		}
	} else {
		var tryHashPath = "/opt/spire/.data/hashes"
		if _, err := os.Stat(tryHashPath); !os.IsNotExist(err) {
			config.HashPath = tryHashPath
		}
	}

	if config.CaPath == "" && config.HashPath == "" {
		return nil, errors.New("either ca_path, hash_path, or both are required")
	}

	config.trustDomain = req.CoreConfiguration.TrustDomain
	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

func (p *TPMAttestorPlugin) Attest(stream nodeattestorv1.NodeAttestor_AttestServer) error {
	if p.config == nil {
		return errors.New("plugin not configured")
	}

	req, err := stream.Recv()
	if err != nil {
		return err
	}

	attestationData := new(common.AttestationData)
	if err := json.Unmarshal(req.GetPayload(), attestationData); err != nil {
		return fmt.Errorf("failed to unmarshal attestation data: %v", err)
	}

	ek, err := common.DecodeEK(attestationData.EK)
	if err != nil {
		return err
	}

	hashEncoded, err := common.GetPubHash(ek)
	if err != nil {
		return fmt.Errorf("could not get public key hash: %v", err)
	}

	validEK := false

	if p.config.HashPath != "" {
		filename := filepath.Join(p.config.HashPath, hashEncoded)
		if _, err := os.Stat(filename); !os.IsNotExist(err) {
			validEK = true
		}
	}

	if !validEK && p.config.CaPath != "" && ek.Certificate != nil {
		files, err := ioutil.ReadDir(p.config.CaPath)
		if err != nil {
			return fmt.Errorf("could not open ca directory: %v", err)
		}

		roots := gx509.NewCertPool()
		for _, file := range files {
			filename := filepath.Join(p.config.CaPath, file.Name())
			certData, err := ioutil.ReadFile(filename)
			if err != nil {
				return fmt.Errorf("could not read cert data for '%s': %v", filename, err)
			}

			ok := roots.AppendCertsFromPEM(certData)
			if ok {
				continue
			}

			root, err := gx509.ParseCertificate(certData)
			if err == nil {
				roots.AddCert(root)
				continue
			}

			return fmt.Errorf("could not parse cert data for '%s': %v", filename, err)
		}

		opts := gx509.VerifyOptions{
			Roots: roots,
		}
		_, err = ek.Certificate.Verify(opts)
		if err != nil {
			return fmt.Errorf("could not verify cert: %v", err)
		}
		validEK = true
	}

	if !validEK {
		return fmt.Errorf("could not validate EK")
	}

	ap := attest.ActivationParameters{
		TPMVersion: attest.TPMVersion20,
		EK:         ek.Public,
		AK:         *attestationData.AK,
	}

	secret, ec, err := ap.Generate()
	if err != nil {
		return fmt.Errorf("could not generate credential challenge: %v", err)
	}

	challenge := &common.Challenge{
		EC: ec,
	}

	challengeBytes, err := json.Marshal(challenge)
	if err != nil {
		return fmt.Errorf("unable to marshal challenge: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_Challenge{
			Challenge: challengeBytes,
		},
	}); err != nil {
		return fmt.Errorf("unable to send challenge: %v", err)
	}

	challengeResp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("unable to receive challenge response: %v", err)
	}

	response := new(common.ChallengeResponse)
	if err := json.Unmarshal(challengeResp.GetChallengeResponse(), response); err != nil {
		return fmt.Errorf("unable to unmarshal challenge response: %v", err)
	}

	if !bytes.Equal(secret, response.Secret) {
		return fmt.Errorf("incorrect secret from attestor")
	}

	return stream.Send(&nodeattestorv1.AttestResponse{
		Response: &nodeattestorv1.AttestResponse_AgentAttributes{
			AgentAttributes: &nodeattestorv1.AgentAttributes{
				SpiffeId:       common.AgentID(p.config.trustDomain, hashEncoded),
				SelectorValues: buildSelectorValues(hashEncoded),
			},
		},
	})
}

func buildSelectorValues(pubHash string) []string {
	return []string{
		"pub_hash:" + pubHash,
	}
}

func containsKey(keys []string, key string) bool {
	for _, item := range keys {
		if item == key {
			return true
		}
	}
	return false
}
