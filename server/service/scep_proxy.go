package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"regexp"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	scepclient "github.com/fleetdm/fleet/v4/server/mdm/scep/client"
	scepserver "github.com/fleetdm/fleet/v4/server/mdm/scep/server"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/go-kit/log"
	"github.com/smallstep/scep"
)

var privateKey *rsa.PrivateKey
var signingCert *x509.Certificate
var signingCaCerts []*x509.Certificate

const scepServerURL = "https://example.com/certsrv/mscep/mscep.dll"
const rsaKeySize = 2048

// TODO: Also retrieve the MD-5? hash of the CA cert
var challengeRegex = regexp.MustCompile(`(?i)The enrollment challenge password is: <B> (?P<password>\S*)`)
var adminUsername = "Username@example.com"
var adminPassword = "password"

func init() {
	// certPath := "/Users/victor/work/fleet/ndes-csr.pfx"
	certPath := "/Users/victor/work/fleet/random-cert.pfx"
	b, err := os.ReadFile(certPath)
	if err != nil {
		panic(err)
	}

	// The PFX may contain intermediate certificates
	password := adminPassword
	var pk interface{}
	pk, signingCert, signingCaCerts, err = pkcs12.DecodeChain(b, password)
	if err != nil {
		panic(err)
	}
	var ok bool
	privateKey, ok = pk.(*rsa.PrivateKey)
	if !ok {
		panic("private key not in RSA format")
	}

	// certText, err := certinfo.CertificateShortText(cert)
	// if err != nil {
	// 	panic(err)
	// }
	// fmt.Printf("Cert is: %s\n", certText)
	// if pk != nil {
	// 	fmt.Println("Private key is not nil")
	// }
	// for i, caCert := range caCerts {
	// 	caCertText, err := certinfo.CertificateShortText(caCert)
	// 	if err != nil {
	// 		panic(err)
	// 	}
	// 	fmt.Printf("CA Cert %d is: %s\n", i, caCertText)
	// }
}

var _ scepserver.Service = (*scepProxyService)(nil)

type scepProxyService struct {
	// info logging is implemented in the service middleware layer.
	debugLogger log.Logger
}

func (svc *scepProxyService) GetCACaps(_ context.Context) ([]byte, error) {
	fmt.Printf("GetCACaps\n")
	// Do not support SHA-512
	defaultCaps := []byte("SHA-1\nSHA-256\nDES3\nPOSTPKIOperation")
	return defaultCaps, nil
}

func (svc *scepProxyService) GetCACert(_ context.Context, _ string) ([]byte, int, error) {
	fmt.Printf("GetCACert\n")
	return signingCert.Raw, 1, nil
}

func (svc *scepProxyService) PKIOperation(_ context.Context, data []byte) ([]byte, error) {
	fmt.Printf("PKIOperation\n")
	if len(data) == 0 {
		return nil, &fleet.BadRequestError{Message: "missing data for PKIOperation"}
	}
	msg, err := scep.ParsePKIMessage(data, scep.WithLogger(svc.debugLogger))
	if err != nil {
		return nil, err
	}

	fmt.Printf("PKIOperation before decrypt\n")
	if err := msg.DecryptPKIEnvelope(signingCert, privateKey); err != nil {
		return nil, err
	}
	// TODO: Check that this is a PCSReq message -- that's the only one we support.

	fmt.Printf("PKIOperation %s\n", msg.String())
	fmt.Printf("PKIOperation ChallengePassword:%s\n", msg.ChallengePassword)
	// TODO: Test for invalid subject here -- empty or lowercased (need to confirm that NDES fails with lowercase)
	fmt.Printf("PKIOperation CSR Subject:%s\n", msg.CSR.Subject.String())

	// Get the challenge from NDES
	// client := &http.Client{
	// 	Transport: ntlmssp.Negotiator{
	// 		RoundTripper: &http.Transport{},
	// 	},
	// }
	// req, err := http.NewRequest(http.MethodGet, "https://example.com/certsrv/mscep_admin/", http.NoBody)
	// if err != nil {
	// 	return nil, ctxerr.Wrap(context.Background(), err, "creating request")
	// }
	// req.SetBasicAuth(adminUsername, adminPassword)
	// resp, err := client.Do(req)
	// if err != nil {
	// 	return nil, ctxerr.Wrap(context.Background(), err, "sending request")
	// }
	// // Make a transformer that converts MS-Win default to UTF8:
	// win16be := unicode.UTF16(unicode.BigEndian, unicode.IgnoreBOM)
	// // Make a transformer that is like win16be, but abides by BOM:
	// utf16bom := unicode.BOMOverride(win16be.NewDecoder())
	//
	// // Make a Reader that uses utf16bom:
	// unicodeReader := transform.NewReader(resp.Body, utf16bom)
	// bodyText, err := io.ReadAll(unicodeReader)
	// htmlString := string(bodyText)
	//
	// matches := challengeRegex.FindStringSubmatch(htmlString)
	// challenge := ""
	// if matches != nil {
	// 	challenge = matches[challengeRegex.SubexpIndex("password")]
	// }
	// if challenge == "" {
	// 	return nil, errors.New("no challenge found")
	// }

	// Now we send the request to the actual CA server
	cert, err := svc.requestCert(context.Background(), msg)
	if err != nil {
		return nil, err
	}

	if err := os.WriteFile("/Users/victor/work/fleet/client-cert.pem", pemCert(cert.Raw), 0o666); err != nil { // nolint:gosec
		return nil, ctxerr.Wrap(context.Background(), err, "writing client cert")
	}

	certRep, err := msg.Success(signingCert, privateKey, cert)
	if certRep == nil {
		return nil, errors.New("no signed certificate")
	}
	return certRep.Raw, err
}

func pemCert(derBytes []byte) []byte {
	pemBlock := &pem.Block{
		Type:    "CERTIFICATE",
		Headers: nil,
		Bytes:   derBytes,
	}
	out := pem.EncodeToMemory(pemBlock)
	return out
}

func (svc *scepProxyService) GetNextCACert(ctx context.Context) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func (svc *scepProxyService) requestCert(ctx context.Context, incomingMsg *scep.PKIMessage) (*x509.Certificate, error) {

	fmt.Printf("VICTOR 1\n")
	client, err := scepclient.New(scepServerURL, svc.debugLogger)
	if err != nil {
		return nil, err
	}

	fmt.Printf("VICTOR 2\n")
	resp, certNum, err := client.GetCACert(ctx, "")
	if err != nil {
		return nil, err
	}
	var caCerts []*x509.Certificate
	if certNum > 1 {
		caCerts, err = scep.CACerts(resp)
		if err != nil {
			return nil, err
		}
	} else {
		caCerts, err = x509.ParseCertificates(resp)
		if err != nil {
			return nil, err
		}
	}

	// TODO: Pick the right CA cert -- EnciphermentCertsSelector seems to work
	// if len(caCerts) != 3 {
	// 	return nil, errors.New("expected 3 CA certs from my NDES server")
	// }
	// caCerts = caCerts[1:2]

	fmt.Printf("VICTOR 3\n")
	msgType := incomingMsg.MessageType

	selfSignKey, err := newRSAKey(rsaKeySize)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "creating new RSA key")
	}

	if incomingMsg.CSR == nil {
		return nil, errors.New("CSR is nil")
	}

	// csrTemplate := x509util.CertificateRequest{
	// 	CertificateRequest: x509.CertificateRequest{
	// 		Subject:            incomingMsg.CSR.Subject,
	// 		SignatureAlgorithm: x509.SHA256WithRSA,
	// 		DNSNames:           incomingMsg.CSR.DNSNames,
	// 	},
	// 	ChallengePassword: challenge,
	// }
	//
	// derBytes, err := x509util.CreateCertificateRequest(rand.Reader, &csrTemplate, selfSignKey)
	// if err != nil {
	// 	return nil, ctxerr.Wrap(ctx, err, "creating certificate request")
	// }
	// csr, err := x509.ParseCertificateRequest(derBytes)
	// if err != nil {
	// 	return nil, ctxerr.Wrap(ctx, err, "parsing certificate request")
	// }

	selfSignCert, err := selfSign(selfSignKey, incomingMsg.CSR)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "self signing certificate")
	}

	pkiTemplate := &scep.PKIMessage{
		MessageType: msgType,
		Recipients:  caCerts,
		SignerKey:   selfSignKey,
		SignerCert:  selfSignCert,
	}

	fmt.Printf("VICTOR 3.5\n")
	outgoingMsg, err := scep.NewCSRRequest(incomingMsg.CSR, pkiTemplate, scep.WithLogger(svc.debugLogger),
		scep.WithCertsSelector(scep.EnciphermentCertsSelector()))
	if err != nil {
		// TODO: Use ctxerr.Wrap
		return nil, errors.Join(err, errors.New("creating csr pkiMessage"))
	}

	fmt.Printf("VICTOR 4\n")
	var respMsg *scep.PKIMessage

	for {
		// loop in case we get a PENDING response which requires
		// a manual approval.

		respBytes, err := client.PKIOperation(ctx, outgoingMsg.Raw)
		if err != nil {
			return nil, errors.Join(err, fmt.Errorf("PKIOperation for %s", msgType))
		}

		fmt.Printf("VICTOR 5\n")
		respMsg, err = scep.ParsePKIMessage(respBytes, scep.WithLogger(svc.debugLogger), scep.WithCACerts(caCerts))
		if err != nil {
			return nil, errors.Join(err, fmt.Errorf("parsing pkiMessage response %s", msgType))
		}

		fmt.Printf("VICTOR 6\n")
		switch respMsg.PKIStatus {
		case scep.FAILURE:
			return nil, fmt.Errorf("%s request failed, failInfo: %s", msgType, respMsg.FailInfo)
		case scep.PENDING:
			svc.debugLogger.Log("pkiStatus", "PENDING", "msg", "sleeping for 5 seconds, then trying again.")
			time.Sleep(5 * time.Second)
			continue
		}
		svc.debugLogger.Log("pkiStatus", "SUCCESS", "msg", "server returned a certificate.")
		break // on scep.SUCCESS
	}

	fmt.Printf("VICTOR 7\n")
	if err := respMsg.DecryptPKIEnvelope(selfSignCert, selfSignKey); err != nil {
		return nil, errors.Join(err, fmt.Errorf("decrypt pkiEnvelope, msgType: %s, status %s", msgType, respMsg.PKIStatus))
	}

	fmt.Printf("VICTOR 8\n")
	respCert := respMsg.CertRepMessage.Certificate
	return respCert, nil
}

// newRSAKey creates a new RSA private key
func newRSAKey(bits int) (*rsa.PrivateKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return private, nil
}

func selfSign(priv *rsa.PrivateKey, csr *x509.CertificateRequest) (*x509.Certificate, error) {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %s", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(time.Hour * 1)
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "SCEP SIGNER", // TODO: Make this configurable or use Fleet SCEP proxy signer
			Organization: csr.Subject.Organization,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(derBytes)
}

// NewSCEPProxyService creates a new scep proxy service
func NewSCEPProxyService(logger log.Logger) scepserver.Service {
	return &scepProxyService{
		debugLogger: logger,
	}
}
