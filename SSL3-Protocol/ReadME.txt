generate_certificate.txt: Convert to shell script.
Creates server/client certificate using key tool and RSA key pairs, with SHA256 signatures.

CertificateAuthority.txt: convert to .java
Calls generate_certificate.sh and stores certificates and keys for both client/server.

SSLRecordHeader: convert to .java
Is essentially a struct for the record header in the SSL protocol. Used by both server/client.

Server: convert to .java
Server runs handshake protocol and data transfer using TCP sockets for connections. Ultimately uses
shared secret to generate an AES encryption key and HMAC signature key.

Client: convert to .java
Client connects to server through TCP and runs through the handshake protocol, using
RSA to initially encrypt/decrypt nonces (found through certificates), then calculates
shared secret that is used to generate AES encryption key and HMAC signature key.

test.txt: Leave as .txt
This is the file being transferred during the data transfer stage. File is 50Kb of random input.

copy_test.txt: File is generated when client receives the transferred test.txt file from Server.

Open two terminals:
1. Ensure generate_certificate.sh is executable (chmod a=rx generate_certificate.sh)
Terminal 1: 
2. Input the following on the command line:
$ javac Server.java Client.java SSLRecordHeader.java CertificateAuthority.java
3. Ensure all classes compiled (look for .class extensions)
4. input the following on the command line:
$ Java Server
Terminal 2:
5. Wait until server terminal states "waiting for connection"
6. input the following on the command line:
$ Java Client

