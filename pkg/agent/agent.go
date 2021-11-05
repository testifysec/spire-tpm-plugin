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

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/go-attestation/attest"

	"github.com/hashicorp/hcl"
	nodeattestorv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/agent/nodeattestor/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
)

// TPMAttestorPlugin implements the nodeattestor Plugin interface
type TPMAttestorPlugin struct {
	nodeattestorv1.UnimplementedNodeAttestorServer
	configv1.UnimplementedConfigServer

	config *TPMAttestorPluginConfig
	tpm    *attest.TPM
}

type TPMAttestorPluginConfig struct {
	trustDomain string
}

func New() *TPMAttestorPlugin {
	return &TPMAttestorPlugin{}
}

func (p *TPMAttestorPlugin) Configure(ctx context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	config := &TPMAttestorPluginConfig{}
	if err := hcl.Decode(config, req.HclConfiguration); err != nil {
		return nil, fmt.Errorf("failed to decode configuration file: %v", err)
	}

	if req.CoreConfiguration == nil {
		return nil, errors.New("global configuration is required")
	}
	if req.CoreConfiguration.TrustDomain == "" {
		return nil, errors.New("trust_domain is required")
	}

	config.trustDomain = req.CoreConfiguration.TrustDomain
	p.config = config

	return &configv1.ConfigureResponse{}, nil
}

func (p *TPMAttestorPlugin) AidAttestation(stream nodeattestorv1.NodeAttestor_AidAttestationServer) error {
	if p.config == nil {
		return errors.New("plugin not configured")
	}

	attestationData, aik, err := p.generateAttestationData()
	if err != nil {
		return fmt.Errorf("failed to generate attestation data: %v", err)
	}

	attestationDataBytes, err := json.Marshal(attestationData)
	if err != nil {
		return fmt.Errorf("failed to marshal attestation data to json: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_Payload{
			Payload: attestationDataBytes,
		},
	}); err != nil {
		return fmt.Errorf("failed to send attestation data: %v", err)
	}

	resp, err := stream.Recv()
	if err != nil {
		return fmt.Errorf("failed to receive challenge: %v", err)
	}

	challenge := new(common.Challenge)
	if err := json.Unmarshal(resp.Challenge, challenge); err != nil {
		return fmt.Errorf("failed to unmarshal challenge: %v", err)
	}

	response, err := p.calculateResponse(challenge.EC, aik)
	if err != nil {
		return fmt.Errorf("failed to calculate response: %v", err)
	}

	responseBytes, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("unable to marshal challenge response: %v", err)
	}

	if err := stream.Send(&nodeattestorv1.PayloadOrChallengeResponse{
		Data: &nodeattestorv1.PayloadOrChallengeResponse_ChallengeResponse{
			ChallengeResponse: responseBytes,
		},
	}); err != nil {
		return fmt.Errorf("unable to send challenge response: %v", err)
	}

	return nil
}

func (p *TPMAttestorPlugin) calculateResponse(ec *attest.EncryptedCredential, aikBytes []byte) (*common.ChallengeResponse, error) {
	tpm := p.tpm
	if tpm == nil {
		var err error
		tpm, err = attest.OpenTPM(&attest.OpenConfig{
			TPMVersion: attest.TPMVersion20,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to connect to tpm: %v", err)
		}
		defer tpm.Close()
	}

	aik, err := tpm.LoadAK(aikBytes)
	if err != nil {
		return nil, err
	}
	defer aik.Close(tpm)

	secret, err := aik.ActivateCredential(tpm, *ec)
	if err != nil {
		return nil, fmt.Errorf("failed to activate credential: %v", err)
	}
	return &common.ChallengeResponse{
		Secret: secret,
	}, nil
}

func (p *TPMAttestorPlugin) generateAttestationData() (*common.AttestationData, []byte, error) {
	tpm := p.tpm
	if tpm == nil {
		var err error
		tpm, err = attest.OpenTPM(&attest.OpenConfig{
			TPMVersion: attest.TPMVersion20,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("failed to connect to tpm: %v", err)
		}
		defer tpm.Close()
	}

	eks, err := tpm.EKs()
	if err != nil {
		return nil, nil, err
	}
	ak, err := tpm.NewAK(nil)
	if err != nil {
		return nil, nil, err
	}
	defer ak.Close(tpm)
	params := ak.AttestationParameters()

	if len(eks) == 0 {
		return nil, nil, errors.New("no EK available")
	}

	ek := &eks[0]
	ekBytes, err := common.EncodeEK(ek)
	if err != nil {
		return nil, nil, err
	}

	aikBytes, err := ak.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return &common.AttestationData{
		EK: ekBytes,
		AK: &params,
	}, aikBytes, nil
}
