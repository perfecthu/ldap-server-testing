// Copyright 2019 VMware, Inc. All Rights Reserved.
//
package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"strings"

	goldap "gopkg.in/ldap.v2"
)

func main() {
	var ldapConfig AuthConfig
	//ldapConfig.LdapURL = "ldap://192.168.199.187:389"
	ldapConfig.LdapURL = "ldaps://192.168.199.187:636"
	ldapConfig.LdapPassword = "admin"
	ldapConfig.LdapUsername = "cn=admin,dc=example,dc=com"

	// harbor_ca.crt
	/*	ldapConfig.LdapCert = `-----BEGIN CERTIFICATE-----
		MIIFczCCA1ugAwIBAgIBATANBgkqhkiG9w0BAQsFADCBjDELMAkGA1UEBhMCQ04x
		EDAOBgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0JlaWppbmcxDzANBgNVBAoMBlZN
		V2FyZTEOMAwGA1UECwwFQ05BQlUxFDASBgNVBAMMC2V4YW1wbGUuY29tMSIwIAYJ
		KoZIhvcNAQkBFhNwZW5nZmVpaEB2bXdhcmUuY29tMB4XDTIwMDIxMDEzMzkzN1oX
		DTMwMDIwNzEzMzkzN1owWDELMAkGA1UEBhMCQ04xEDAOBgNVBAgMB0JlaWppbmcx
		EDAOBgNVBAcMB0JlaWppbmcxDzANBgNVBAoMBlZNV2FyZTEUMBIGA1UEAwwLZXhh
		bXBsZS5jb20wggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCYpggNgw2I
		26kUJyKHLjJ6nZw1WewGnCYK2nXuUlmH7PY17tHL0jPk1EhdzskitCGU8CPmdEmw
		nRb+Jt2dKVQ4SDCmzfRoTNc8y7Y6b1Tjy+KcUygl6P/GWF7IW/tQ7EGtH8RNinVu
		dX+Rh6NtWkQCGaSH/45Mwb+tO33D+/QoDYU9pjJKGst1kl+6iuj461yazwo2G1g1
		9Vh837+yd1x0E/4fe/aoGZVJA5LcKNOiPGrwNU2Kc/kOnmfUgCQGzWXmR+s6eZjs
		gmFXdy4zal4rQTWKQsMYP5PoSOg+VOtpdBfpRd/0n2r+gMHA5JG0A56F3pX77Dhk
		JsUVjCDAFs+yW+M2SnZtvXm/x6g5TNw49zu+E+EXmkwALVRaFWTnCOcq4EHVxgcS
		eqJELezR64abwyUhS6HaFqPV4BsJ1lZs2cDCkva767bj1uuAY/GofT0HBWGMuFOr
		ZpLT5hdZi5mp5lELeKZX3ThPinA7oEi+w23+IXFRSwPo7lSgGS/Rh5mEagmLSpKl
		w0DwqWtMNGLRnx8ro2BBYZA/2pE5JOQtlkSQ6kXBFYJjmJ4srqJrNe5kD34Tp1T8
		g2Yjto3lDRYAULv0L1CvVeqzu2fwx6zwjtKuZt6Zvlemc3Bpy3Q7o4nwHloLZZSW
		cyph1FzjuaBWZyjbXxaUvbIPbhJyI35R3QIDAQABoxMwETAPBgNVHREECDAGhwTA
		qMe7MA0GCSqGSIb3DQEBCwUAA4ICAQBIxLZ4QWaEyqKQ0J8nsMLJDmVRvGWepHm+
		U4U+SCwID2IDl3M88e72kced4MZ9SJpnyfJICgrniMAooe5dGL7gdnkfKbPVeoPa
		qethAAccEU5dquXMliZMT8tR5XaECAA9CnUnLdRvuUR/PAZ0DdOA4ncxk7LGBoAZ
		AS86u4ON4EXKKXyCIjRtiI78+NftD4q437Jt659Ok/xdnQ7KlQv9AjtIaEziQERT
		cYGbcT/4P6fQN7k4MIq98VdH53uZ6Avj2MsVBdMsexpfOKC+iYq8kosbhhB1qoD+
		R7273dC72BYzp8yF/AwoEgRd1KJKGUh/BtnNBUOZ/k9YSbEyosmUmbvVnjxGpYNk
		GQ4sBqUU6SJKPG7g/ASmnkVm0c71Ee6aoa0VcDfNP8MQ8UX74VWUsAV15/CEyJol
		8sPEil+YW/g9LzuzhW0PfuiRZXpe7/PRsRkZKsLQRAk1mjECQNrdt6lnDlGITsj7
		0xYZx79CsUupERmoyLdqyK+B/1qjP5Bmu63hYpwS/LhXHZkC8ZpStiRiZY6sqM4D
		+fJWojeFK7zUof/fW++BIn2zIPxyl4zU81eIIfyYovpHIAmQbb9Ykz8iSn8iRJoV
		SxaGFEIfa1wBlinhtajeLd1LyhvcbOKkzhYI1kM5dD6SJbc4cga0nbKGH+tLuCe3
		x3Za+OSm6g==
		-----END CERTIFICATE-----`*/
	ldapConfig.LdapCert = `-----BEGIN CERTIFICATE-----
MIIF+zCCA+OgAwIBAgIUddgT33SZ7BSc3Lj2L6W7GZGEBH0wDQYJKoZIhvcNAQEL
BQAwgYwxCzAJBgNVBAYTAkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdC
ZWlqaW5nMQ8wDQYDVQQKDAZWTVdhcmUxDjAMBgNVBAsMBUNOQUJVMRQwEgYDVQQD
DAtleGFtcGxlLmNvbTEiMCAGCSqGSIb3DQEJARYTcGVuZ2ZlaWhAdm13YXJlLmNv
bTAeFw0yMDAyMTAxMzI3MjNaFw0zMDAyMDcxMzI3MjNaMIGMMQswCQYDVQQGEwJD
TjEQMA4GA1UECAwHQmVpamluZzEQMA4GA1UEBwwHQmVpamluZzEPMA0GA1UECgwG
Vk1XYXJlMQ4wDAYDVQQLDAVDTkFCVTEUMBIGA1UEAwwLZXhhbXBsZS5jb20xIjAg
BgkqhkiG9w0BCQEWE3BlbmdmZWloQHZtd2FyZS5jb20wggIiMA0GCSqGSIb3DQEB
AQUAA4ICDwAwggIKAoICAQDRWu64ci/KgecLBKB7HnS5v9Xx7Vz3jY2CgwjCaoDp
B7WHx5CHjFsYzy5qAO+rrZ2LslLzbm0NtUwDs+TUcJS38bHPcoradboJSfoeVGS7
ZjR4lib4kMRS/XHqFxKReO84jJMJV7C9Xw4PiKJTsSHu443/mJezOxZWKFEBfHHk
/M72J2KgS6+Xi/kqoOsnuLtMUqQNA9f5PWGmUaDL4WgBlW3bY/knYT2CPYScyJpe
umg1Q20pUh3Ro9ihAYF1vRAmjCKlII8h1aDuHnTN6PNRsm5qTO9TnXAZTWg254vj
9divRqoK/VYRqloGvnbP+QTbUhaq1ADlNeFmxboFkq8a/JEZvSTF02Y5xWHbQVqh
sKVfPLHXc4XRfYa1bvPFyJ0a0O6xQGJrwtkNnKPrEaC+5ocSkY7SAQzg3jS28Ztt
Rig/+VbUdfaytVkqzGud+IX+D2vYQXIDFDqdf6LoSzpDTnfHLWvKoRMnbYg2atCS
qfINEFGm//7YEp6D1jl/BMMBEPKaeCX9sHoM5I0ky5skbyy6v1tjdfqlfT+2Oqf2
dY2pco5zkykeZiPjShSsXcmqVX65vP14TbJ2gISYJLWMhq7H4x+AqG4NH/Bvnn19
tE21OJGC7GAL7OoO75YISikEmllfom2lMzPYK76d3sz/KhRL+IZV8M2zIhOLiFu1
wQIDAQABo1MwUTAdBgNVHQ4EFgQUs8h9qISYiWeZeFwiMGoGncPzNeIwHwYDVR0j
BBgwFoAUs8h9qISYiWeZeFwiMGoGncPzNeIwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQsFAAOCAgEAhiEQ2wiKK5OT19tI/Nm6XPfY4AsbeIH9fYmiq0qDKqYK
vwmFvq4l4Oy4IK9lQx9OUlBxmfVnARVTfogKRUZCWud2R6PW+55ym4wyBz1aFLOZ
MrhM1Mo9Tbn0oYf4L2WoCIESAvreveLlNY1oSfWHq6fQ9VuxZw6m9dkmRvNyczSK
W7I+xlLlicE9Kq8DRDKNIb9HAl5LhMjWVPypPIQVqL8VmoHhJnCgr7TBxbTNyJuM
bL12EVQDosG7hXHgL+B9CoBbft1Dfno0bOri2nglouEP1MDFwvTnNYmPgs66P0ZR
Px4x1HCTRhTcmcfMa5nk7s7QebFG+s0MfVrhXrgqJmrKqvZLt/WTfBBWn9efw2Xm
G7pKhntyqbb50vIvqsrRzrYfe9AvfWhRM2aABtpZcHsLW9OI4t9kAhhpdbU+aFyB
Nvidk+B64cFPfQH2or18ma0iLEP8GFk+Vi/EmZofa64UikzS7ginEm/JL8zrZQ4H
Ma3Y6utR2MenOAGRWvau0M/mZlvw0jyRil/L9B1t/JB74RFmdic+j9oqbzt2QU5R
JWoHOJHQxNvI0SZAGvfC2gy1pyJ95JmOLVr1LX8J3VDMVdx4VNViXpFc+PMR6x/F
UV2v7e+oQO0aiJPdIedX80k95mgR48dWUm0qV073VjGyukiJVNFEnrrf2rIPr1k=
-----END CERTIFICATE-----`

	/*	ldapConfig.LdapCert = `
		-----BEGIN CERTIFICATE-----
		MIIFhTCCA22gAwIBAgIUBWPUOcl5wyYV18FraR9cayN1F1UwDQYJKoZIhvcNAQEL
		BQAwUjELMAkGA1UEBhMCQ04xDDAKBgNVBAgMA1BFSzERMA8GA1UEBwwIQmVpIEpp
		bmcxDzANBgNVBAoMBlZNd2FyZTERMA8GA1UEAwwISGFyYm9yQ0EwHhcNMTkwODEz
		MDMyMjUwWhcNMjAwODEyMDMyMjUwWjBSMQswCQYDVQQGEwJDTjEMMAoGA1UECAwD
		UEVLMREwDwYDVQQHDAhCZWkgSmluZzEPMA0GA1UECgwGVk13YXJlMREwDwYDVQQD
		DAhIYXJib3JDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALjlYE0c
		16ZsTVBpr2s48QXxuc0IcddfyWqpBGwiWTGG3/LS/ebkiFfKVViBicK2A5IofI4X
		6UBuu+hb3FZjJtpqNPFMrOK0K0eiheBQVxeCQavtoTpF7dtuWyv2bAgmvVagBxtU
		sWWWzSO1vanO4Acs/ijfZjUdxN9JQk6xDj5Q+CLo0ikjFPTTD5DT40Z89qf440VU
		019b70ZYUd61ZAGflfJNDQZ14GqGuG7pUTXMS76cuCbpGldhgILkBmKS/B3gm1ex
		YzB6omKDbgGTOK4HiJpKsC0xWfYjY9LaTTmaJ+q8XVzv6oJu5u5RWSx2TEXy72Hv
		E8rYLo1zKXQ+O03/XbPiK/bgsYEsPIxumMPKEOZJ3vdUxWOnYIssVqQgqpAByo4k
		+ErBuQUwZz22NraV2nDqyiP+feuzD2nCKLAslEx2QWOvqfhvGgeyv0ViOdtyVFbf
		XvOAq9FbY5w+i0MLBb0tcU+f8xzKbecsTbJDTLd0Fy7Sx2sT5ywfG1SDeNwRr8ar
		QCBWUgim8Lc7U3OgrrjzMJGfKD/RgMWSjOxV1LXbjgOFhnh7/wvRxf87fURHigt0
		26ZLCKm2i2YStL4S2yNSm206SXMkHUMZV/mFMHc/JK/EuDU9xXsK2P1d1H3SNrgK
		axU7fcXnwIM9gcDrIlm+8MblrJWvGTe6GDn1AgMBAAGjUzBRMB0GA1UdDgQWBBSd
		0G4mm1Ui8glxkvq5fcJflnlxCDAfBgNVHSMEGDAWgBSd0G4mm1Ui8glxkvq5fcJf
		lnlxCDAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4ICAQBDYYDcmjwy
		5fmCzBcMYEh7XMiFhS3UkojgB7LB6R41o6GmXvJOgaDobQC78We3I3Y8r8vVbAY+
		Jh42tRRwKMIRUywkDLr5tfyiDUcGvSxpfysTYSNNknsctsowI6yCcRIsY0XqZEE9
		Y3GMSaljAcxG++gR2XSxSPwYQ/TKDiM1Fyv3YNhnmoycBQItcIz29hYVXRgBkNkx
		Cap8MDERJKlHiAgopoXtxnSbgZn4pZa6bVRF/UUYRmRLKO8tyKd8ZXHfQvvso1HU
		e+Wcy3EoADr3aYCytPppo33zDHBX4+lcL2rKAH2+K5JOhnxZuRR4dWoczkI5mYRi
		qZ809uHnXoV4yJ14NWnoil6kUF3YxU9hWzjEaVcZfp7WUw0BeTZ9M0VqkjxSiSuz
		QvSzoPqZ2ajfxawf1fdttU6YUewBkjMOTC2C8qoA8m7HNRTznoZbfFITG1gJlnFT
		y8oWY+ZrEsG7lID2zMaZopSAwDzuBoqLGE66LK+RtFSrAcGHSr3Xlp0R6hX4FeyN
		flTTBxE6eNoEiV56x9RuSDvWnw/l38B/y9q9wMNkI+kb2d8QNkWFz9q1W01Vdceo
		ZzTA/fNcErZ0YiE/wY9VEW+DRoO3ntMN8lEsNLr04kUG7RJ6EOu6kQPHQuJ3Bujy
		rnAVXLxzOqGPfKD6gBQS2pTikQCYpqtaFg==
		-----END CERTIFICATE-----`*/

	// server cert 10.92.233.156.crt
	//    ldapConfig.LdapCert = `
	//-----BEGIN CERTIFICATE-----
	//MIIFSjCCAzKgAwIBAgIUY7f2ECRISPMeb1iVNvV5iQsIErUwDQYJKoZIhvcNAQEL
	//BQAwUjELMAkGA1UEBhMCQ04xDDAKBgNVBAgMA1BFSzERMA8GA1UEBwwIQmVpIEpp
	//bmcxDzANBgNVBAoMBlZNd2FyZTERMA8GA1UEAwwISGFyYm9yQ0EwHhcNMjAwMjEw
	//MDkzOTE4WhcNMjEwMjA5MDkzOTE4WjBXMQswCQYDVQQGEwJDTjEMMAoGA1UECAwD
	//UEVLMREwDwYDVQQHDAhCZWkgSmluZzEPMA0GA1UECgwGVk13YXJlMRYwFAYDVQQD
	//DA1IYXJib3JNYW5hZ2VyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA
	//tOB5uvFNpQ6L59Vbiaskj07FouAXSzlmO42ff4c1B/bkNq+a/IL3dxInfebMDgsi
	//8GUQ71g7mppAuoRqJfvXImJ6zDb0vRyy39M6ZhWV3hdqTikT8AskJD8LN0xfVAzT
	//Nnkibqyd1iAHGJBs/rx5WmF+sxecxIQ9znbH8+o+pC5YGFXmMIbwLvw0AVtz+496
	//2tAT2gBmnUNTSsEgdP60a0GW5HxnV1l9NT1Zbu11DN66ljf77YQBGFtZA/62iRPn
	//23eQjtG4WpciA2DChxdWHG9TMjM22NILqlk1U2GDDv+OV1ot713telnxNfXBKj91
	//hfD+IVx16YjvDVEkWplqBMeQtAUsIHVmhF9aTLhxrEfSaDSCkFx/C3n29Nbb0vG2
	//XD/7sLd5Dyt6fRx6BZV3aeDMamWx0djl0/MyK49/FCpWq2y4ES1sqn8LfedsP2+x
	//Yj715OPs6PnnLdgKxTeu8TThApdyhQY6NzmjZfby4XpiFdClRRLxPM4mSpedBdOY
	//Ssk99/qzrRpFsqyfXw2tT6DVSMzq/+Zcn6IhuGjd89ib6W7p4IFB/eSIwfH232HY
	//ubjR7dDvfgMhuqvkdUwI9oX/dZbnvGXMrds5qaZk9n6lUtP1lYdop38th63OXMPd
	//AaJXZVPgvTZMZMhrNb7axIscShad7+dE6C1qgLvh8yECAwEAAaMTMBEwDwYDVR0R
	//BAgwBocEClzpnDANBgkqhkiG9w0BAQsFAAOCAgEAsBHLTuuK50unyjQKAF/Jeicr
	//Qp9jzNMv1Sx2pV3HH1eWdbZwegki1FkoulEwf9no5Y688zMme+pwsLtSlZrwLgM4
	//GwxT+wPqyXOsn/a2DTwvmRxJqSvDPqN0gVy5kYgGWWSYSgYk2S4nfMuy79AzEmzN
	//tKxGuuF6e2qxPTolACGrQ5zWzNcVCufKL3TleHDamDeLvVrcQye5L+N+VMVr8PQQ
	//+kFVY0euIKdjRG8J4ygk3N1kW5OKcsgzuOhRj2d8qK+tvK3NQbymwG6f/sQa7f/8
	//CHgfXCTnZEVedrvo8BBK7b0T9GDuol3Qp98jIP/5Ps8+q26E0rkrmvofOl4j5uKl
	//1kiEN/0LqqG+U4mhSBse059d1nijNgtCSvmRaUQ0zktt5TMPOUuQOjb2xdU2GzGP
	//q2VhLHCnpdgeJfK0Y2usUjeAEDG/7AwWThnS85vIT2jvaFwbOaxEGH9XqaT6SKfl
	//WxCy435jzJSRglRI8/O4douyduETMLuNfmwQ/ypWDbI1pR7/fYDuydEJpFjipozo
	//IZGi9ip1f5Fmwcj/8i0UdMZTGqJVC43o6IkiDpseSp+6j2wRvKhTuLNZU2svKdtL
	//Sd+1xtW4pcWbzQKUQjPFA1d4ge8xQLivk1narMq44c34Qv3sRSrS7wXeV7WKpegs
	//THg0+gbnnTqlmQiNeDU=
	//-----END CERTIFICATE-----`

	if err := ConnectionTest(ldapConfig); err != nil {
		fmt.Println(err)
	}
}

type AuthConfig struct {
	// ldap cert
	LdapCert string `json:"ldap_cert" yaml:"ldap_cert"`

	// ldap cert altname
	LdapCertAltname string `json:"ldap_cert_altname" yaml:"ldap_cert_altname"`

	// ldap password
	LdapPassword string `json:"ldap_password" yaml:"ldap_password"`

	// ldap url
	// Format: uri
	LdapURL string `json:"ldap_url" yaml:"ldap_url"`

	// ldap username
	LdapUsername string `json:"ldap_username" yaml:"ldap_username"`
}

// ConnectionTestWithAllConfig - test ldap session connection, out of the scope of normal session create/close
func ConnectionTest(ldapConfig AuthConfig) error {
	var session Session
	session.ldapConfig = ldapConfig

	if err := session.Open(); err != nil {
		return err
	}

	defer session.Close()

	if session.ldapConfig.LdapUsername != "" {
		if err := session.Bind(session.ldapConfig.LdapUsername, session.ldapConfig.LdapPassword); err != nil {
			return err
		}
	}

	return nil
}

// Session - define a LDAP session
type Session struct {
	ldapConfig AuthConfig
	ldapConn   *goldap.Conn
}

// Bind with specified DN and password, used in authentication
func (session *Session) Bind(dn string, password string) error {
	return session.ldapConn.Bind(dn, password)
}

// Open - open Session
func (session *Session) Open() error {
	splitLdapURL := strings.Split(string(session.ldapConfig.LdapURL), "://")
	protocol, hostport := splitLdapURL[0], splitLdapURL[1]
	host := strings.Split(hostport, ":")[0]

	switch protocol {
	case "ldap":
		log.Printf("Start to dial ldap")
		ldap, err := goldap.Dial("tcp", hostport)
		if err != nil {
			return err
		}
		session.ldapConn = ldap
	case "ldaps":
		// Get the SystemCertPool, continue with an empty pool on error
		rootCAs, _ := x509.SystemCertPool()
		if rootCAs == nil {
			rootCAs = x509.NewCertPool()
		}
		// Append our cert to the system pool
		serverSslCert := []byte(session.ldapConfig.LdapCert)
		if ok := rootCAs.AppendCertsFromPEM(serverSslCert); !ok {
			log.Println("Using system certs only")
		}

		log.Printf("Start to dial ldaps")
		ldap, err := goldap.DialTLS("tcp", hostport, &tls.Config{ServerName: host, RootCAs: rootCAs})
		if err != nil {
			return err
		}
		session.ldapConn = ldap
	}

	return nil

}

// Close - close current session
func (session *Session) Close() {
	if session.ldapConn != nil {
		session.ldapConn.Close()
	}
}
