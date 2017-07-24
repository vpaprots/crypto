/*
Copyright IBM Corp. 2017 All Rights Reserved.

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
	"os"
	"testing"

	"github.com/hyperledger/fabric/bccsp/grpc11"
	server "github.com/hyperledger/fabric/bccsp/grpc11/server"
	"github.com/stretchr/testify/assert"
)

func TestGRPC11FactoryName(t *testing.T) {
	f := &GRPC11Factory{}
	assert.Equal(t, f.Name(), GRPC11BasedFactoryName)
}

func TestGRPC11FactoryGetInvalidArgs(t *testing.T) {
	f := &GRPC11Factory{}

	_, err := f.Get(nil)
	assert.Error(t, err, "Invalid config. It must not be nil.")

	_, err = f.Get(&FactoryOpts{})
	assert.Error(t, err, "Invalid config. It must not be nil.")

	opts := &FactoryOpts{
		Grpc11Opts: &grpc11.GRPC11Opts{},
	}
	_, err = f.Get(opts)
	assert.Error(t, err, "Failed initializing configuration at [0,]")
}

func TestGRPC11FactoryGet(t *testing.T) {
	server.CreateTestServer()

	f := &GRPC11Factory{}
	_, pin, label := grpc11.FindPKCS11Lib()

	opts := &FactoryOpts{
		Grpc11Opts: &grpc11.GRPC11Opts{
			SecLevel:   256,
			HashFamily: "SHA2",
			Pin:        pin,
			Label:      label,
			Address:    "localhost",
			Port:       "6789",
		},
	}
	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

	opts = &FactoryOpts{
		Grpc11Opts: &grpc11.GRPC11Opts{
			SecLevel:     256,
			HashFamily:   "SHA2",
			FileKeystore: &grpc11.FileKeystoreOpts{KeyStorePath: os.TempDir()},
			Pin:          pin,
			Label:        label,
			Address:      "localhost",
			Port:         "6789",
		},
	}
	csp, err = f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)

	opts = &FactoryOpts{
		Grpc11Opts: &grpc11.GRPC11Opts{
			SecLevel:   256,
			HashFamily: "SHA2",
			Ephemeral:  true,
			Pin:        pin,
			Label:      label,
			Address:    "localhost",
			Port:       "6789",
		},
	}
	csp, err = f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)
}
