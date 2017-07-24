// +build !nopkcs11

/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package factory

import (
	"errors"
	"fmt"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/grpc11"
	"github.com/hyperledger/fabric/bccsp/sw"
)

const (
	// GRPC11BasedFactoryName is the name of the factory of the hsm-based BCCSP implementation
	GRPC11BasedFactoryName = "GRPC11"
)

// GRPC11Factory is the factory of the HSM-based BCCSP.
type GRPC11Factory struct{}

// Name returns the name of this factory
func (f *GRPC11Factory) Name() string {
	return GRPC11BasedFactoryName
}

// Get returns an instance of BCCSP using Opts.
func (f *GRPC11Factory) Get(config *FactoryOpts) (bccsp.BCCSP, error) {
	// Validate arguments
	if config == nil || config.Grpc11Opts == nil {
		return nil, errors.New("Invalid config. It must not be nil.")
	}

	p11Opts := config.Grpc11Opts

	//TODO: GRPC11 does not need a keystore, but we have not migrated all of GRPC11 BCCSP to GRPC11 yet
	var ks bccsp.KeyStore
	if p11Opts.Ephemeral == true {
		ks = sw.NewDummyKeyStore()
	} else if p11Opts.FileKeystore != nil {
		fks, err := sw.NewFileBasedKeyStore(nil, p11Opts.FileKeystore.KeyStorePath, false)
		if err != nil {
			return nil, fmt.Errorf("Failed to initialize software key store: %s", err)
		}
		ks = fks
	} else {
		// Default to DummyKeystore
		ks = sw.NewDummyKeyStore()
	}
	return grpc11.New(*p11Opts, ks)
}
