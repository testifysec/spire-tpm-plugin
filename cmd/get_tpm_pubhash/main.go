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

package main

import (
	"errors"
	"fmt"
	"github.com/bloomberg/spire-tpm-plugin/pkg/common"
	"github.com/bloomberg/spire-tpm-plugin/pkg/common_test"
	"github.com/google/go-attestation/attest"
	sim "github.com/google/go-tpm-tools/simulator"
	"log"
	"os"
)

func main() {
	args := os.Args[1:]
	seedPath := ""
	if len(args) > 0 {
		seedPath = args[0]
	}
	seed, err := common.GetSeed(seedPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	s, err := sim.GetWithFixedSeedInsecure(seed)
	tpm, err := attest.OpenTPM(&attest.OpenConfig{
		TPMVersion:     attest.TPMVersion20,
		CommandChannel: &common_test.TPMCmdChannel{ReadWriteCloser: s},
	})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer tpm.Close()

	tpmPubHash, err := getTpmPubHash(tpm)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Println(tpmPubHash)
}

func getTpmPubHash(tpm *attest.TPM) (string, error) {
	eks, err := tpm.EKs()
	if err != nil {
		return "", err
	}

	if len(eks) == 0 {
		return "", errors.New("no EK available")
	}

	ek := &eks[0]
	hashEncoded, err := common.GetPubHash(ek)
	if err != nil {
		return "", err
	}

	return hashEncoded, nil
}
