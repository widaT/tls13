// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c            *Conn
	clientHello  *clientHelloMsg
	hello        *serverHelloMsg
	suite        *cipherSuite
	ecdheOk      bool
	ecSignOk     bool
	rsaDecryptOk bool
	rsaSignOk    bool
	finishedHash finishedHash
	masterSecret []byte
	cert         *Certificate
}

// serverHandshake performs a TLS handshake as a server.
func (c *Conn) serverHandshake() error {
	if c.handshaker == nil {
		c.config.serverInitOnce.Do(func() { c.config.serverInit(nil) })
		clientHello, err := c.readClientHello()
		if err != nil {
			return err
		}
		if c.vers != VersionTLS13 {
			c.sendAlert(alertProtocolVersion)
			return errors.New("protocol version not supported")
		}
		c.handshaker = &serverHandshakeStateTLS13{
			c:           c,
			clientHello: clientHello,
		}
	}
	return c.handshaker.handshake()
}

func (c *Conn) readClientHello() (*clientHelloMsg, error) {
	msg, err := c.readHandshake()
	if err != nil {
		return nil, err
	}
	clientHello, ok := msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return nil, unexpectedMessageError(clientHello, msg)
	}

	if c.config.GetConfigForClient != nil {
		chi := clientHelloInfo(c, clientHello)
		if newConfig, err := c.config.GetConfigForClient(chi); err != nil {
			c.sendAlert(alertInternalError)
			return nil, err
		} else if newConfig != nil {
			newConfig.serverInitOnce.Do(func() { newConfig.serverInit(c.config) })
			c.config = newConfig
		}
	}

	clientVersions := clientHello.supportedVersions
	if len(clientHello.supportedVersions) == 0 {
		clientVersions = supportedVersionsFromMax(clientHello.vers)
	}
	c.vers, ok = c.config.mutualVersion(clientVersions)
	if !ok {
		c.sendAlert(alertProtocolVersion)
		return nil, fmt.Errorf("tls: client offered only unsupported versions: %x", clientVersions)
	}
	c.haveVers = true
	c.in.version = c.vers
	c.out.version = c.vers

	return clientHello, nil
}

func supportsECDHE(c *Config, supportedCurves []CurveID, supportedPoints []uint8) bool {
	supportsCurve := false
	for _, curve := range supportedCurves {
		if c.supportsCurve(curve) {
			supportsCurve = true
			break
		}
	}

	supportsPointFormat := false
	for _, pointFormat := range supportedPoints {
		if pointFormat == pointFormatUncompressed {
			supportsPointFormat = true
			break
		}
	}

	return supportsCurve && supportsPointFormat
}

func (c *Conn) processCertsFromClient(certificate Certificate) error {
	certificates := certificate.Certificate
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to parse client certificate: " + err.Error())
		}
	}

	if len(certs) == 0 && requiresClientCert(c.config.ClientAuth) {
		c.sendAlert(alertBadCertificate)
		return errors.New("tls: client didn't provide a certificate")
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: failed to verify client certificate: " + err.Error())
		}

		c.verifiedChains = chains
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return err
		}
	}

	if len(certs) == 0 {
		return nil
	}

	switch certs[0].PublicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey:
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return fmt.Errorf("tls: client certificate contains an unsupported public key of type %T", certs[0].PublicKey)
	}

	c.peerCertificates = certs
	c.ocspResponse = certificate.OCSPStaple
	c.scts = certificate.SignedCertificateTimestamps
	return nil
}

func clientHelloInfo(c *Conn, clientHello *clientHelloMsg) *ClientHelloInfo {
	supportedVersions := clientHello.supportedVersions
	if len(clientHello.supportedVersions) == 0 {
		supportedVersions = supportedVersionsFromMax(clientHello.vers)
	}

	return &ClientHelloInfo{
		CipherSuites:      clientHello.cipherSuites,
		ServerName:        clientHello.serverName,
		SupportedCurves:   clientHello.supportedCurves,
		SupportedPoints:   clientHello.supportedPoints,
		SignatureSchemes:  clientHello.supportedSignatureAlgorithms,
		SupportedProtos:   clientHello.alpnProtocols,
		SupportedVersions: supportedVersions,
		Conn:              c.conn,
		config:            c.config,
	}
}
