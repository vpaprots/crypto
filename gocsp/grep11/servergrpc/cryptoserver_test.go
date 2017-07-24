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
package main

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"os"
	"testing"

	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/hyperledger/fabric/bccsp/grpc11/protos"
)

var (
	Pin, Label string
	Address    = "localhost"
	Port       = "6789"
)

func TestMain(m *testing.M) {
	CreateTestServer()
	_, Pin, Label = FindPKCS11Lib()

	ret := m.Run()
	if ret != 0 {
		fmt.Printf("Failed testing [%d]", ret)
		os.Exit(-1)
	}
}

func TestManagerLoad(t *testing.T) {
	conn, err := grpc.Dial(Address+":"+Port, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGrpc11ManagerClient(conn)

	r, err := c.Load(context.Background(), &pb.LoadInfo{Label, Pin})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}
	t.Logf("Greeting from %s", r.Address)
}

func TestServerConnect(t *testing.T) {
	conn, err := grpc.Dial(Address+":"+Port, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewGrpc11ManagerClient(conn)

	r, err := c.Load(context.Background(), &pb.LoadInfo{Label, Pin})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	conn, err = grpc.Dial(r.Address, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	t.Logf("Coonected to %s", r.Address)
	defer conn.Close()
}

func TestServerSignVerify(t *testing.T) {
	conn, err := grpc.Dial(Address+":"+Port, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	m := pb.NewGrpc11ManagerClient(conn)

	r, err := m.Load(context.Background(), &pb.LoadInfo{Label, Pin})
	if err != nil {
		t.Fatalf("could not greet: %v", err)
	}

	conn, err = grpc.Dial(r.Address, grpc.WithInsecure())
	if err != nil {
		t.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	t.Logf("Coonected to %s", r.Address)

	s := pb.NewGrpc11Client(conn)

	oidNamedCurveP256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	marshaledOID, err := asn1.Marshal(oidNamedCurveP256)
	if err != nil {
		t.Fatalf("Could not marshal OID [%s]", err.Error())
	}
	k, err := s.GenerateECKey(context.Background(), &pb.GenerateInfo{marshaledOID, true})
	if err != nil {
		t.Fatalf("Failed generating ECDSA key [%s]", err)
	}
	if k.Error != "" {
		t.Fatalf("Server returned error [%s]", k.Error)
	}

	msg := []byte("Hello World")
	digest := sha256.Sum256(msg)

	signature, err := s.SignP11ECDSA(context.Background(), &pb.SignInfo{k.Ski, digest[:]})
	if err != nil {
		t.Fatalf("Failed generating ECDSA signature [%s]", err)
	}
	if signature.Error != "" {
		t.Fatalf("Server returned error [%s]", signature.Error)
	}
	if len(signature.Sig) == 0 {
		t.Fatal("Failed generating ECDSA key. Signature must be different from nil")
	}

	verify, err := s.VerifyP11ECDSA(context.Background(), &pb.VerifyInfo{k.Ski, digest[:], signature.Sig})
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	if verify.Error != "" {
		t.Fatalf("Server returned error [%s]", verify.Error)
	}
	if !verify.Valid {
		t.Fatal("Failed verifying ECDSA signature. Signature not valid.")
	}

}
