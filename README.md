# Generate CA certificate
- Generate CA key
	```
	openssl genrsa -out ca.key 4096
	```
	
	You will get a file `ca.key`
	
- Genrate CA certificate
	```
	openssl req -new -x509 -days 3650 -key ca.key -out ca.crt
	```
	You will get a file `ca.crt` which is the CA certificate.

# Generate LDAP Server certificate
- Generate LDAP server key
	```
	openssl genrsa -out private.key 4096
	```
		
- Generate LDAP Certificate Signing Request (**CSR**)
	* download the **ssl.conf** to local, and change the **IP** in *[alt_names]* setction to *your_ldap_ip_address*. 
	* Generate a Certificate Signing Request
		```
		openssl req -new -sha256 -out private.csr -key private.key -config ssl.conf
		```
		You will get a file `private.csr`
		
	* check the CSR:
		```
		openssl req -text -noout -in private.csr
		```
		**Note**: You should see this:
`X509v3 Subject Alternative Name: IP Address: your_ldap_server_ip_address`
	* Generate LDAP server ceritificate base on the CSR 
		```
		openssl x509 -req -days 3650 -in private.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out private.crt -extensions req_ext -extfile ssl.conf
		```
		You will get a file `private.crt` which will be used as LDAP server's certificate.
		
	* View the certificate
		```
		openssl x509 -in private.crt -text -noout
		```

# Start the LDAP server
```
docker run --hostname example.com --volume /home/perfecthu/workspace/ldap_test:/container/service/slapd/assets/certs \
--env LDAP_DOMAIN="example.com" \
--env LDAP_ADMIN_PASSWORD="admin" \
-p 389:389 \
-p 636:636 \
--env LDAP_TLS_CRT_FILENAME=private.crt \
--env LDAP_TLS_KEY_FILENAME=private.key \
--env LDAP_TLS_CA_CRT_FILENAME=private.crt \
--env LDAP_TLS_VERIFY_CLIENT=try \
--detach osixia/openldap:1.3.0
```

# Testing with the code

Please replace the ldap certificate in the code with the previous generated `ca.crt`.


