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
	_ "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/pkcs11"
	"github.com/op/go-logging"
	"github.com/spf13/viper"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	pb "github.com/hyperledger/fabric/bccsp/grpc11/protos"
	"github.com/hyperledger/fabric/common/flogging"
)

var (
	logger = flogging.MustGetLogger("grpc11server")
)

func RunServer() {
	// For environment variables.
	viper.SetEnvPrefix("GRPC11")
	viper.SetConfigType("yaml")
	viper.AutomaticEnv()
	viper.AddConfigPath(".")
	replacer := strings.NewReplacer(".", "_")
	viper.SetEnvKeyReplacer(replacer)

	viper.SetConfigName("grpc11server")

	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		logger.Fatalf("Error when reading %s config file: %s", "grpc11server", err)
	}

	logging.SetLevel(logging.DEBUG, "grpc11server")

	lib := viper.GetString("grpc11.lib")
	sensitive := viper.GetBool("grpc11.sensitive")
	softverify := viper.GetBool("grpc11.softverify")
	sessionCacheSize := viper.GetInt("grpc11.sessioncache")
	address := viper.GetString("grpc11.address")
	port := viper.GetString("grpc11.port")

	m := &grpc11Manager{lib, sensitive, softverify, sessionCacheSize, address, port}
	m.serverStart()

	return
}

func main() {
	RunServer()
}

func (m *grpc11Manager) serverStart() {
	lis, err := net.Listen("tcp", m.address+":"+m.port)
	if err != nil {
		logger.Fatalf("failed to listen: %v", err)
	}
	logger.Infof("Listening on ", lis.Addr().String())
	grpcManager := grpc.NewServer()
	pb.RegisterGrpc11ManagerServer(grpcManager, m)
	grpcManager.Serve(lis)
}

type grpc11Manager struct {
	lib              string
	sensitive        bool
	softverify       bool
	sessionCacheSize int
	address          string
	port             string
}

func (m *grpc11Manager) Load(c context.Context, loadInfo *pb.LoadInfo) (*pb.LoadStatus, error) {
	rc := &pb.LoadStatus{}

	ctx, slot, session, err := loadLib(m.lib, loadInfo.GetPin(), loadInfo.GetLabel())
	if err != nil {
		rc.Error = fmt.Sprintf("Failed to loadLib: %v", err)
		rc.Address = ""
		return rc, fmt.Errorf(rc.Error)
	}

	sessions := make(chan pkcs11.SessionHandle, m.sessionCacheSize)
	server := &grpc11Server{ctx, sessions, slot, m.sensitive, m.softverify, nil}
	defer server.returnSession(*session)

	lis, err := net.Listen("tcp", m.address+":0")
	if err != nil {
		rc.Error = fmt.Sprintf("Failed to Listen: %v", err)
		rc.Address = ""
		return rc, fmt.Errorf(rc.Error)
	}
	grpcServer := grpc.NewServer()
	pb.RegisterGrpc11Server(grpcServer, server)
	go grpcServer.Serve(lis)

	rc.Error = ""
	rc.Address = lis.Addr().String()
	server.logger = flogging.MustGetLogger("grpc11server_" + rc.Address)

	logger.Infof("Listening on %s for token %s", rc.Address, loadInfo.GetLabel())

	return rc, nil
}

type grpc11Server struct {
	ctx      *pkcs11.Ctx
	sessions chan pkcs11.SessionHandle
	slot     uint

	noPrivImport bool
	softVerify   bool

	logger *logging.Logger
}

func loadLib(lib, pin, label string) (*pkcs11.Ctx, uint, *pkcs11.SessionHandle, error) {
	var slot uint = 0
	logger.Debugf("Loading pkcs11 library [%s]\n", lib)
	if lib == "" {
		return nil, slot, nil, fmt.Errorf("No PKCS11 library default")
	}

	ctx := pkcs11.New(lib)
	if ctx == nil {
		return nil, slot, nil, fmt.Errorf("Instantiate failed [%s]", lib)
	}

	ctx.Initialize()
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return nil, slot, nil, fmt.Errorf("Could not get Slot List [%s]", err)
	}
	found := false
	for _, s := range slots {
		info, err := ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		logger.Debugf("Looking for %s, found label %s\n", label, info.Label)
		if label == info.Label {
			found = true
			slot = s
			break
		}
	}
	if !found {
		return nil, slot, nil, fmt.Errorf("Could not find token with label %s", label)
	}

	var session pkcs11.SessionHandle
	for i := 0; i < 10; i++ {
		session, err = ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			logger.Warningf("OpenSession failed, retrying [%s]\n", err)
		} else {
			break
		}
	}
	if err != nil {
		logger.Fatalf("OpenSession [%s]\n", err)
	}
	logger.Debugf("Created new pkcs11 session %+v on slot %d\n", session, slot)

	if pin == "" {
		return nil, slot, nil, fmt.Errorf("No PIN set\n")
	}
	err = ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return nil, slot, nil, fmt.Errorf("Login failed [%s]\n", err)
		}
	}

	return ctx, slot, &session, nil
}

func (csp *grpc11Server) getSession() (session pkcs11.SessionHandle) {
	select {
	case session = <-csp.sessions:
		csp.logger.Debugf("Reusing existing pkcs11 session %+v on slot %d\n", session, csp.slot)

	default:
		// cache is empty (or completely in use), create a new session
		var s pkcs11.SessionHandle
		var err error = nil
		for i := 0; i < 10; i++ {
			s, err = csp.ctx.OpenSession(csp.slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
			if err != nil {
				csp.logger.Warningf("OpenSession failed, retrying [%s]\n", err)
			} else {
				break
			}
		}
		if err != nil {
			panic(fmt.Errorf("OpenSession failed [%s]\n", err))
		}
		csp.logger.Debugf("Created new pkcs11 session %+v on slot %d\n", s, csp.slot)
		session = s
	}
	return session
}

func (csp *grpc11Server) returnSession(session pkcs11.SessionHandle) {
	select {
	case csp.sessions <- session:
		// returned session back to session cache
	default:
		// have plenty of sessions in cache, dropping
		csp.ctx.CloseSession(session)
	}
}

func (s *grpc11Server) GetECKey(c context.Context, keyInfo *pb.GetKeyInfo) (*pb.GetKeyStatus, error) {
	rc := &pb.GetKeyStatus{}
	pub, oid, isPriv, err := s.getECKey(keyInfo.Ski)
	rc.PubKey = pub
	rc.Oid = oid
	rc.IsPriv = isPriv
	rc.Error = fmtError(err)
	return rc, err
}

// Look for an EC key by SKI, stored in CKA_ID
// This function can probably be addapted for both EC and RSA keys.
func (csp *grpc11Server) getECKey(ski []byte) (pubKey, oid []byte, isPriv bool, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)
	isPriv = true
	_, err = findKeyPairFromSKI(p11lib, session, ski, privateKeyFlag)
	if err != nil {
		isPriv = false
		csp.logger.Debugf("Private key not found [%s] for SKI [%s], looking for Public key", err, hex.EncodeToString(ski))
	}

	publicKey, err := findKeyPairFromSKI(p11lib, session, ski, publicKeyFlag)
	if err != nil {
		return nil, nil, false, fmt.Errorf("Public key not found [%s] for SKI [%s]", err, hex.EncodeToString(ski))
	}

	ecpt, marshaledOid, err := ecPoint(p11lib, session, *publicKey)
	if err != nil {
		return nil, nil, false, fmt.Errorf("Public key not found [%s] for SKI [%s]", err, hex.EncodeToString(ski))
	}

	return ecpt, marshaledOid, isPriv, nil
}

// RFC 5480, 2.1.1.1. Named Curve
//
// secp224r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 33 }
//
// secp256r1 OBJECT IDENTIFIER ::= {
//   iso(1) member-body(2) us(840) ansi-X9-62(10045) curves(3)
//   prime(1) 7 }
//
// secp384r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 34 }
//
// secp521r1 OBJECT IDENTIFIER ::= {
//   iso(1) identified-organization(3) certicom(132) curve(0) 35 }
//
var (
	oidNamedCurveP224 = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	}
	return nil
}

func oidFromNamedCurve(curve elliptic.Curve) (asn1.ObjectIdentifier, bool) {
	switch curve {
	case elliptic.P224():
		return oidNamedCurveP224, true
	case elliptic.P256():
		return oidNamedCurveP256, true
	case elliptic.P384():
		return oidNamedCurveP384, true
	case elliptic.P521():
		return oidNamedCurveP521, true
	}

	return nil, false
}

func (s *grpc11Server) GenerateECKey(c context.Context, generateInfo *pb.GenerateInfo) (*pb.GenerateStatus, error) {
	rc := &pb.GenerateStatus{}
	ski, pub, err := s.generateECKey(generateInfo.Oid, generateInfo.Ephemeral)
	rc.PubKey = pub
	rc.Ski = ski
	rc.Error = fmtError(err)
	return rc, err
}

func (csp *grpc11Server) generateECKey(marshaledOID []byte, ephemeral bool) ([]byte, []byte, error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	id := nextIDCtr()
	publabel := fmt.Sprintf("BCPUB%s", id.Text(16))
	prvlabel := fmt.Sprintf("BCPRV%s", id.Text(16))

	pubkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),

		pkcs11.NewAttribute(pkcs11.CKA_ID, publabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
	}

	prvkey_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),

		pkcs11.NewAttribute(pkcs11.CKA_ID, prvlabel),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),

		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, !csp.noPrivImport),
	}

	pub, prv, err := p11lib.GenerateKeyPair(session,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)},
		pubkey_t, prvkey_t)

	if err != nil {
		return nil, nil, fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}

	ecpt, _, _ := ecPoint(p11lib, session, pub)
	hash := sha256.Sum256(ecpt)
	ski := hash[:]

	// set CKA_ID of the both keys to SKI(public key)
	setski_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}

	logger.Infof("Generated new P11 key, SKI %x\n", ski)
	err = p11lib.SetAttributeValue(session, pub, setski_t)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: set-ID-to-SKI[public] failed [%s]\n", err)
	}

	err = p11lib.SetAttributeValue(session, prv, setski_t)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: set-ID-to-SKI[private] failed [%s]\n", err)
	}

	if logger.IsEnabledFor(logging.DEBUG) {
		listAttrs(p11lib, session, prv)
		listAttrs(p11lib, session, pub)
	}

	return ski, ecpt, nil
}

func (s *grpc11Server) SignP11ECDSA(c context.Context, signInfo *pb.SignInfo) (*pb.SignStatus, error) {
	rc := &pb.SignStatus{}
	sig, err := s.signP11ECDSA(signInfo.Ski, signInfo.Msg)
	rc.Sig = sig
	rc.Error = fmtError(err)
	return rc, err
}

func (csp *grpc11Server) signP11ECDSA(ski []byte, msg []byte) ([]byte, error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	privateKey, err := findKeyPairFromSKI(p11lib, session, ski, privateKeyFlag)
	if err != nil {
		return nil, fmt.Errorf("Private key not found [%s]\n", err)
	}

	err = p11lib.SignInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}, *privateKey)
	if err != nil {
		return nil, fmt.Errorf("Sign-initialize  failed [%s]\n", err)
	}

	var sig []byte

	sig, err = p11lib.Sign(session, msg)
	if err != nil {
		return nil, fmt.Errorf("P11: sign failed [%s]\n", err)
	}

	return sig, nil
}

func (s *grpc11Server) VerifyP11ECDSA(c context.Context, verifyInfo *pb.VerifyInfo) (*pb.VerifyStatus, error) {
	rc := &pb.VerifyStatus{}
	valid, err := s.verifyP11ECDSA(verifyInfo.Ski, verifyInfo.Msg, verifyInfo.Sig)
	rc.Valid = valid
	rc.Error = fmtError(err)
	return rc, err
}

func (csp *grpc11Server) verifyP11ECDSA(ski, msg, sig []byte) (valid bool, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	logger.Debugf("Verify ECDSA\n")

	publicKey, err := findKeyPairFromSKI(p11lib, session, ski, publicKeyFlag)
	if err != nil {
		return false, fmt.Errorf("Public key not found [%s]\n", err)
	}

	err = p11lib.VerifyInit(session, []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)},
		*publicKey)
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify-initialize [%s]\n", err)
	}
	err = p11lib.Verify(session, msg, sig)
	if err == pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify failed [%s]\n", err)
	}

	return true, nil
}

func (s *grpc11Server) ImportECKey(c context.Context, importInfo *pb.ImportInfo) (*pb.ImportStatus, error) {
	rc := &pb.ImportStatus{}
	ski, err := s.importECKey(importInfo.Oid, importInfo.PrivKey, importInfo.EcPt, importInfo.Ephemeral, importInfo.KeyType)
	rc.Ski = ski
	rc.Error = fmtError(err)
	return rc, err
}

func (csp *grpc11Server) importECKey(marshaledOID, privKey, ecPt []byte, ephemeral bool, keyType bool) (ski []byte, err error) {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	id := nextIDCtr()

	var keyTemplate []*pkcs11.Attribute
	if keyType == publicKeyFlag {
		logger.Debug("Importing Public EC Key")
		publabel := fmt.Sprintf("BCPUB%s", id.Text(16))

		hash := sha256.Sum256(ecPt)
		ski = hash[:]

		// Add DER encoding for the CKA_EC_POINT
		ecPt = append([]byte{0x04, byte(len(ecPt))}, ecPt...)

		keyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

			pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, publabel),
			pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecPt),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
		}
	} else { // isPrivateKey
		ski, err = csp.importECKey(marshaledOID, nil, ecPt, ephemeral, publicKeyFlag)
		if err != nil {
			return nil, fmt.Errorf("Failed importing private EC Key [%s]\n", err)
		}

		logger.Debugf("Importing Private EC Key [%d]\n%s\n", len(privKey)*8, hex.Dump(privKey))
		prvlabel := fmt.Sprintf("BCPRV%s", id.Text(16))
		keyTemplate = []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
			pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
			pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral),
			pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, marshaledOID),

			pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
			pkcs11.NewAttribute(pkcs11.CKA_LABEL, prvlabel),
			pkcs11.NewAttribute(pkcs11.CKR_ATTRIBUTE_SENSITIVE, false),
			pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKey),
		}
	}

	keyHandle, err := p11lib.CreateObject(session, keyTemplate)
	if err != nil {
		return nil, fmt.Errorf("P11: keypair generate failed [%s]\n", err)
	}

	if logger.IsEnabledFor(logging.DEBUG) {
		listAttrs(p11lib, session, keyHandle)
	}

	return ski, nil
}

const (
	privateKeyFlag = true
	publicKeyFlag  = false
)

func findKeyPairFromSKI(mod *pkcs11.Ctx, session pkcs11.SessionHandle, ski []byte, keyType bool) (*pkcs11.ObjectHandle, error) {
	ktype := pkcs11.CKO_PUBLIC_KEY
	if keyType == privateKeyFlag {
		ktype = pkcs11.CKO_PRIVATE_KEY
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ktype),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ski),
	}
	if err := mod.FindObjectsInit(session, template); err != nil {
		return nil, err
	}

	// single session instance, assume one hit only
	objs, _, err := mod.FindObjects(session, 1)
	if err != nil {
		return nil, err
	}
	if err = mod.FindObjectsFinal(session); err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("Key not found [%s]", hex.Dump(ski))
	}

	return &objs[0], nil
}

// Fairly straightforward EC-point query, other than opencryptoki
// mis-reporting length, including the 04 Tag of the field following
// the SPKI in EP11-returned MACed publickeys:
//
// attr type 385/x181, length 66 b  -- SHOULD be 1+64
// EC point:
// 00000000  04 ce 30 31 6d 5a fd d3  53 2d 54 9a 27 54 d8 7c
// 00000010  d9 80 35 91 09 2d 6f 06  5a 8e e3 cb c0 01 b7 c9
// 00000020  13 5d 70 d4 e5 62 f2 1b  10 93 f7 d5 77 41 ba 9d
// 00000030  93 3e 18 3e 00 c6 0a 0e  d2 36 cc 7f be 50 16 ef
// 00000040  06 04
//
// cf. correct field:
//   0  89: SEQUENCE {
//   2  19:   SEQUENCE {
//   4   7:     OBJECT IDENTIFIER ecPublicKey (1 2 840 10045 2 1)
//  13   8:     OBJECT IDENTIFIER prime256v1 (1 2 840 10045 3 1 7)
//        :     }
//  23  66:   BIT STRING
//        :     04 CE 30 31 6D 5A FD D3 53 2D 54 9A 27 54 D8 7C
//        :     D9 80 35 91 09 2D 6F 06 5A 8E E3 CB C0 01 B7 C9
//        :     13 5D 70 D4 E5 62 F2 1B 10 93 F7 D5 77 41 BA 9D
//        :     93 3E 18 3E 00 C6 0A 0E D2 36 CC 7F BE 50 16 EF
//        :     06
//        :   }
//
// as a short-term workaround, remove the trailing byte if:
//   - receiving an even number of bytes == 2*prime-coordinate +2 bytes
//   - starting byte is 04: uncompressed EC point
//   - trailing byte is 04: assume it belongs to the next OCTET STRING
//
// [mis-parsing encountered with v3.5.1, 2016-10-22]
//
// SoftHSM reports extra two bytes before the uncrompressed point
// 0x04 || <Length*2+1>
//                 VV< Actual start of point
// 00000000  04 41 04 6c c8 57 32 13  02 12 6a 19 23 1d 5a 64  |.A.l.W2...j.#.Zd|
// 00000010  33 0c eb 75 4d e8 99 22  92 35 96 b2 39 58 14 1e  |3..uM..".5..9X..|
// 00000020  19 de ef 32 46 50 68 02  24 62 36 db ed b1 84 7b  |...2FPh.$b6....{|
// 00000030  93 d8 40 c3 d5 a6 b7 38  16 d2 35 0a 53 11 f9 51  |..@....8..5.S..Q|
// 00000040  fc a7 16                                          |...|
func ecPoint(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (ecpt, oid []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	}

	attr, err := p11lib.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, nil, fmt.Errorf("PKCS11: get(EC point) [%s]\n", err)
	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_EC_POINT {
			logger.Debugf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			// workarounds, see above
			if (0 == (len(a.Value) % 2)) &&
				(byte(0x04) == a.Value[0]) &&
				(byte(0x04) == a.Value[len(a.Value)-1]) {
				logger.Debugf("Detected opencryptoki bug, trimming trailing 0x04")
				ecpt = a.Value[0 : len(a.Value)-1] // Trim trailing 0x04
			} else if byte(0x04) == a.Value[0] && byte(0x04) == a.Value[2] {
				logger.Debugf("Detected SoftHSM bug, trimming leading 0x04 0xXX")
				ecpt = a.Value[2:len(a.Value)]
			} else {
				ecpt = a.Value
			}
		} else if a.Type == pkcs11.CKA_EC_PARAMS {
			logger.Debugf("EC point: attr type %d/0x%x, len %d\n%s\n", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))

			oid = a.Value
		}
	}
	if oid == nil || ecpt == nil {
		return nil, nil, fmt.Errorf("CKA_EC_POINT not found, perhaps not an EC Key?")
	}

	return ecpt, oid, nil
}

func listAttrs(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, obj pkcs11.ObjectHandle) {
	var cktype, ckclass uint
	var ckaid, cklabel []byte

	if p11lib == nil {
		return
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, ckclass),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, cktype),
		pkcs11.NewAttribute(pkcs11.CKA_ID, ckaid),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, cklabel),
	}

	// certain errors are tolerated, if value is missing
	attr, err := p11lib.GetAttributeValue(session, obj, template)
	if err != nil {
		logger.Debugf("P11: get(attrlist) [%s]\n", err)
	}

	for _, a := range attr {
		// Would be friendlier if the bindings provided a way convert Attribute hex to string
		logger.Debugf("ListAttr: type %d/0x%x, length %d\n%s", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))
	}
}

func (csp *grpc11Server) getSecretValue(ski []byte) []byte {
	p11lib := csp.ctx
	session := csp.getSession()
	defer csp.returnSession(session)

	keyHandle, err := findKeyPairFromSKI(p11lib, session, ski, privateKeyFlag)

	var privKey []byte
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, privKey),
	}

	// certain errors are tolerated, if value is missing
	attr, err := p11lib.GetAttributeValue(session, *keyHandle, template)
	if err != nil {
		logger.Warningf("P11: get(attrlist) [%s]\n", err)
	}

	for _, a := range attr {
		// Would be friendlier if the bindings provided a way convert Attribute hex to string
		logger.Debugf("ListAttr: type %d/0x%x, length %d\n%s", a.Type, a.Type, len(a.Value), hex.Dump(a.Value))
		return a.Value
	}
	logger.Warningf("No Key Value found!", err)
	return nil
}

var (
	bigone   = new(big.Int).SetInt64(1)
	id_ctr   = new(big.Int)
	id_mutex sync.Mutex
)

func nextIDCtr() *big.Int {
	id_mutex.Lock()
	id_ctr = new(big.Int).Add(id_ctr, bigone)
	id_mutex.Unlock()
	return id_ctr
}

func fmtError(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%+v", err)
}

// THIS IS ONLY USED FOR TESTING
// This is a convenience function. Useful to self-configure, for tests where usual configuration is not
// available
func FindPKCS11Lib() (lib, pin, label string) {
	//FIXME: Till we workout the configuration piece, look for the libraries in the familiar places
	lib = os.Getenv("PKCS11_LIB")
	if lib == "" {
		pin = "98765432"
		label = "ForFabric"
		possibilities := []string{
			"/usr/lib/softhsm/libsofthsm2.so",                            //Debian
			"/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",           //Ubuntu
			"/usr/lib/s390x-linux-gnu/softhsm/libsofthsm2.so",            //Ubuntu
			"/usr/lib/powerpc64le-linux-gnu/softhsm/libsofthsm2.so",      //Power
			"/usr/local/Cellar/softhsm/2.1.0/lib/softhsm/libsofthsm2.so", //MacOS
		}
		for _, path := range possibilities {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				lib = path
				break
			}
		}
	} else {
		pin = os.Getenv("PKCS11_PIN")
		label = os.Getenv("PKCS11_LABEL")
	}
	return lib, pin, label
}

func CreateTestServer() {
	var lib string
	lib, _, _ = FindPKCS11Lib()
	sensitive := true
	softverify := false
	sessionCacheSize := 10
	address := "localhost"
	port := "6789"

	m := &grpc11Manager{lib, sensitive, softverify, sessionCacheSize, address, port}
	lis, err := net.Listen("tcp", m.address+":"+m.port)
	if err != nil {
		logger.Warningf("Failed to listen, continuing in hope that server is already running: %v", err)
		return
	}
	logger.Infof("Listening on ", lis.Addr().String())
	grpcManager := grpc.NewServer()
	pb.RegisterGrpc11ManagerServer(grpcManager, m)
	go grpcManager.Serve(lis)

	time.Sleep(1000 * time.Microsecond)
}
