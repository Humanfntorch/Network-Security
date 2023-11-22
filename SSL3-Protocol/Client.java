import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.logging.Logger;


public class Client
{
    // RSA pub/priv key pair for client
    private PrivateKey privateKey;
    private PublicKey publicKey;
    // Client's certificate
    private Certificate clientCert;
    // Server's certificate
    private Certificate serverCert;
    // Servers's public RSA Key
    private PublicKey serverKey;
    // Encryption Cipher using server's public RSA key
    private Cipher encRSACipher;
    // Decryption Cipher using client's private RSA key
    private Cipher decRSACipher;
    // Server's port for tcp connection
    private final int SERVERPORT = 8080;
    // Logger for error handling
    private static final Logger LOGGER = Logger.getLogger(Server.class.getName());
    // aes key generated from premaster secret (used for enc and dec)
    private SecretKey aesKey;
    // Hmac key generated from premaster secret (used for Integrity protection)
    private SecretKey hmacKey;

    public Client()
    {
        // Load the client's certificate from a JKS file
        try
        {
            KeyStore keystore = KeyStore.getInstance("JKS");
            keystore.load(new FileInputStream("clientkeystore.jks"),
                    "clientPassword".toCharArray());

            // Get private RSA key
            this.privateKey =
                    (PrivateKey) keystore.getKey("clientKey", "clientPassword".toCharArray());
            // Get the certificate
            this.clientCert = keystore.getCertificate("clientKey");
            // Get public RSA key
            this.publicKey = clientCert.getPublicKey();

            // Get the certificate chain
            Certificate[] certChain = keystore.getCertificateChain("clientKey");
        }
        catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException
                | UnrecoverableKeyException e)
        {
            e.printStackTrace();
        }

        // print certificate by field values
        printCertContents(this.clientCert);

        // Initialize encryption cipher using private key
        try
        {
            this.encRSACipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            this.encRSACipher.init(Cipher.ENCRYPT_MODE, this.privateKey);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e)
        {
            e.printStackTrace();
        }
    }

    /*
     * Accepts an object argument and calculates the total size of the object in bytes using a
     * ByteArrayOutputStream and ObjectOutputStream. Object out stream serializes the object, writes
     * it to the Byte array stream and returns the total size in bytes written to the Byte Array
     * Stream. If Object serialization/writing to stream fails, returns -1, else: size of object as
     * type byte
     */
    public static long getObjectSize(Object obj)
    {
        try
        {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            // oos writes to the baos
            ObjectOutputStream oos = new ObjectOutputStream(baos);
            // Serializes object using oos and writes to baos
            oos.writeObject(obj);
            oos.close();
            // Convert int to byte (hopefully no truncation) and return
            return (long) baos.size();
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return -1;
        }
    }

    /*
     * Generates an AES key from the premaster secret that was computed during the SSL handshake
     * phase. premasterSecret is forced to a fix-sized number of bytes (256) using SHA256 to compute
     * a message digest. The bytes of the premaster secret (updated through SHA256) are then used to
     * exponentiate a generated AES key's bytes to form a new set of bytes that are encoded to the
     * AES key
     */
    public static SecretKey generateAESKey(byte[] premasterSecret) throws NoSuchAlgorithmException
    {
        // Use PBKDF2 to derive an AES key from the shared secret
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec =
                new PBEKeySpec(new String(premasterSecret, StandardCharsets.UTF_8).toCharArray(),
                        "salt".getBytes(), 65536, 256);
        SecretKey tmp;
        try
        {
            tmp = factory.generateSecret(spec);
            SecretKey aesKey = new SecretKeySpec(tmp.getEncoded(), "AES");
            return aesKey;
        }
        catch (InvalidKeySpecException e)
        {
            e.printStackTrace();
        }
        return null;

    }

    /*
     * Generates an HMAC key using the premaster secret formed during the SSL handshake. Premaster
     * secret is passed through SHA-256 to fix the byte size to a predefined limit (256) and is used
     * to generate the HMAC secret key.
     */
    public static SecretKey generateHMACKey(byte[] premasterSecret) throws NoSuchAlgorithmException
    {
        // Use SHA-256 to derive a fixed-length key from the premaster secret
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] keyBytes = digest.digest(premasterSecret);

        // Create a new HMAC key from the derived key bytes
        SecretKey hmacKey = new SecretKeySpec(keyBytes, "HmacSHA256");
        return hmacKey;
    }

    /*
     * Prints the meaningful contents of the given Certificate argument. Ensures certificate is a
     * valid x509Certificate and prints the following fields to the console: Subject Distinguished
     * Name (DN) Issuer Distinguished Name (DN) Serial Number Validity date (date of notBefore thru
     * date of notAfter) Signature algorithm used Public key algorithm used Certificate version
     * Number
     */
    public static void printCertContents(Certificate certificate)
    {
        if (certificate instanceof X509Certificate)
        {
            X509Certificate x509Cert = (X509Certificate) certificate;
            System.out.println("Subject: " + x509Cert.getSubjectDN());
            System.out.println("Issuer: " + x509Cert.getIssuerDN());
            System.out.println("Serial number: " + x509Cert.getSerialNumber());
            System.out.println(
                    "Validity: " + x509Cert.getNotBefore() + " to " + x509Cert.getNotAfter());
            System.out.println("Signature algorithm: " + x509Cert.getSigAlgName());
            System.out.println("Public key algorithm: " + x509Cert.getPublicKey().getAlgorithm());
            System.out.println("Version: " + x509Cert.getVersion());
        }
    }

    /*
     * Validates the given receivedCert argument (on client side, so certificate originator is
     * expected to be Server). Validation of certificate depends on: Integrity protection of the
     * certificate: Matches the signature of the certificate (used by Server's private RSA key) to
     * the public RSA key. Certificate Issuer: Expected certificate issuer should be Server,
     * distinguished name is parsed to find the certificate issuer name (CN) and ensures match
     * between expected "Server" Certificate validity date: Certificate's issuance date is ensured
     * to valid by analyzing certificate's not before date and not after date relative to the
     * current date of this function's invocation. Assuming certificate is validated, server's
     * public RSA key and certificate is cached. Otherwise: System report terminating error and
     * terminates.
     */
    public void validateCertificate(Certificate receivedCert)
    {
        // cast certificate for easy manipulation
        receivedCert = (X509Certificate) receivedCert;
        System.out.println("Received certificate has given contents: ");
        printCertContents(receivedCert);
        System.out.println();

        // Ensure proper signature and integrity protection of certificate
        System.out.println("Validating signature of certificate using embedded public key.");
        try
        {
            receivedCert.verify(receivedCert.getPublicKey());
            System.out.println("Certificate has confirmed signature and has been untampered with.");
        }
        catch (InvalidKeyException | CertificateException | NoSuchAlgorithmException
                | NoSuchProviderException | SignatureException e)
        {
            e.printStackTrace();
        }
        System.out.println();

        // Validate CN of certificate
        System.out.println(
                "Expecting certificate issuer name to match name: \"Server\", validating CN on certificate.");

        String subjectDN = ((X509Certificate) receivedCert).getSubjectDN().getName();
        String[] subjectFields = subjectDN.split(",");
        String cnField = null;
        // Search DN fields until certificate issuer name is found
        for (String field : subjectFields)
        {
            if (field.trim().startsWith("CN="))
            {
                cnField = field.trim();
                break;
            }
        }
        if (cnField != null)
        {
            // extract the value after "CN="
            String cnValue = cnField.substring(3);
            System.out.println("CN of certificate found as: " + cnValue);
            // Validate issuer name with expected name
            if (cnValue.equals("Server"))
            {
                System.out.println("Issuer of certificate authenticated.");
            }
            else
            {
                System.out.println(
                        "Issuer of certificate does not match expected issuer. Terminating session.");
                // REPLACE WITH FAILED HANDSHAKE
                System.exit(0);
            }
        }
        else
        {
            System.out.println(
                    "CN field not found in the subject distinguished name. Terminating session.");
            // REPLACE WITH FAILED HANDSHAKE
            System.exit(0);
        }
        System.out.println();

        // before date
        String certBeforeDate = ((X509Certificate) receivedCert).getNotBefore().toString();
        // not after date
        String certAfterDate = ((X509Certificate) receivedCert).getNotAfter().toString();
        SimpleDateFormat format = new SimpleDateFormat("EEE MMM dd HH:mm:ss zzz yyyy", Locale.US);
        // Ensure validity of certificate issuance date.
        try
        {
            // Current date to validate certificate date issuance
            Date currentDate = new Date();
            System.out.println("Current date: " + currentDate.toString());
            // certificate's not before date
            Date beforeDate = format.parse(certBeforeDate);
            System.out.println(
                    "Certificate is valid after the following date: " + beforeDate.toString());
            // certificate validity must have a before date after current date
            if (currentDate.after(beforeDate))
            {
                // certificate's not after date
                Date afterDate = format.parse(certAfterDate);
                System.out.println(
                        "Certificate invalid after the following date: " + afterDate.toString());
                // certificate validity must have a not after date before the current date
                if (currentDate.before(afterDate))
                {
                    System.out.println(
                            "Certificate issuance data has been validated as current and acceptable.");
                }
                else
                {
                    System.out.println(
                            "Certificate issuance date indicates certificate expired. Terminating session.");
                    System.exit(0);
                }
            }
            else
            {
                System.out.println(
                        "Certificate before validity date is after current date. Terminating session.");
                System.exit(0);
            }

        }
        catch (ParseException e)
        {
            e.printStackTrace();
        }
        System.out.println();
        System.out.println("Client certificate has been validated successfully.");
        // Cache server cert and key
        this.serverCert = receivedCert;
        this.serverKey = this.serverCert.getPublicKey();
        // initialize decryption cipher using server key
        try
        {
            this.decRSACipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            this.decRSACipher.init(Cipher.DECRYPT_MODE, this.serverKey);
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e)
        {
            e.printStackTrace();
        }
    }

    public void sslHandshakeSuccess()
    {
        // List contains all sent/received messages for MD computation
        ArrayList<Object> mdList = new ArrayList<Object>();

        // Connect to Server
        try
        {
            InetAddress host = InetAddress.getByName("localhost");
            // Connect client to the server
            Socket serverSocket = new Socket(host, SERVERPORT);
            System.out.println("Client: Connected to server");

            // in/out streams for communication with server
            ObjectInputStream inStream =
                    new ObjectInputStream(serverSocket.getInputStream());
            ObjectOutputStream outStream =
                    new ObjectOutputStream(serverSocket.getOutputStream());
            System.out.println();


            System.out.println("Client: Sending Handshake Hello to Server.");
            System.out.println();

            // MESSAGE 1
            System.out.println("Message 1 (SSL3_MT_CLIENT_HELLO): ");
            // Send server encryption and I/G algo suite (enforced)
            String m1String = "AES:256 bit. HMAC:SHA256";
            System.out.println("Client: Cipher suite being sent: " + m1String);

            // find byte size of cipher suite
            long m1StringSize = getObjectSize(m1String);
            System.out.println("Client: size of cipher suite message: " + m1StringSize);
            // Size of first message being sent to server
            long[] m1ContentLength = {m1StringSize};

            // initial Client Hello header.
            SSLRecordHeader m1Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CLIENT_HELLO, m1ContentLength);
            // Transmit header and payload to server
            outStream.writeObject(m1Header);
            outStream.writeObject(m1String);
            outStream.flush();
            // Write all m1 messages to mdList
            mdList.add(m1Header);
            mdList.add(m1String);
            System.out.println();


            // MESSAGE 2
            System.out.println();
            System.out.println("Message 2 (SSL3_MT_SERVER_HELLO): ");
            // M2Header and Cipher suite string received next
            // Header received first
            SSLRecordHeader m2Header;
            try
            {
                m2Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 2 header received. Header contents:");
                m2Header.printHeader();
                // Cipher suite string received next
                String m2String = (String) inStream.readObject();
                System.out.println("Message 2 Cipher suite Accepted. Cipher suite contents:");
                System.out.println(m2String);
                // Write all m2 messages to mdList
                mdList.add(m2Header);
                mdList.add(m2String);
            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }
            System.out.println();

            // MESSAGE 3
            System.out.println();
            System.out.println("Message 3 (SSL3_MT_CERTIFICATE): ");
            // Receive cert etc
            Certificate m3Certificate = null;
            SSLRecordHeader m3Header = null;
            try
            {
                // Header received first
                m3Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 3 header received. Header contents:");
                m3Header.printHeader();

                // Certificate received next
                m3Certificate = (Certificate) inStream.readObject();
                System.out.println(
                        "Message 3 Server certificate received. Server certificate contents:");
                printCertContents(m3Certificate);
                // Add m3Header and m3Certificate to mdList
                mdList.add(m3Header);
                mdList.add(m3Certificate);

            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }
            System.out.println();

            // MESSAGE 4
            System.out.println();
            System.out.println("Message 4 (SSL3_MT_CERTIFICATE_REQUEST): ");
            // M2Header and Cipher suite string received next
            // Header received first
            SSLRecordHeader m4Header;
            try
            {
                m4Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 4 header received. Header contents:");
                m4Header.printHeader();
                // Cipher suite string received next
                String m4String = (String) inStream.readObject();
                System.out.println("Message 4 Request received. Request from server:");
                System.out.println(m4String);
                // Write all m4 messages to mdList
                mdList.add(m4Header);
                mdList.add(m4String);
            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }


            // MESSAGE 5
            System.out.println();
            System.out.println("Message 5 (SSL3_MT_CERTIFICATE): ");
            // find byte size of server's certificate
            long m5ServerCertSize = getObjectSize(this.clientCert);
            System.out.println("Client: size of certificate being sent: " + m5ServerCertSize);
            System.out.println();
            long[] m5ContentLength = {m5ServerCertSize};
            SSLRecordHeader m5Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CERTIFICATE, m5ContentLength);
            // Transmit header and payload to client
            outStream.writeObject(m5Header);
            outStream.writeObject(this.clientCert);
            outStream.flush();
            // Add m5Header and cert to mdList
            mdList.add(m5Header);
            mdList.add(this.clientCert);


            // VALIDATE CERTIFICATE
            System.out.println();
            System.out.println("Client: Validating received certificate: ");
            validateCertificate(m3Certificate);
            System.out.println();

            // MESSAGE 6
            System.out.println();
            System.out.println("Message 6 (SSL3_MT_SERVER_KEY_EXCHANGE): ");
            // Placeholder for nonce
            byte[] m6Nonce = null;
            SSLRecordHeader m6Header = null;
            // Receive cert etc
            try
            {
                m6Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 6 header received. Header contents:");
                m6Header.printHeader();
                // Receive server's nonce
                m6Nonce = (byte[]) inStream.readObject();
                System.out.println("Message 6 Nonce received. Encrypted nonce contents:");
                System.out.println(ByteBuffer.wrap(m6Nonce).getLong());

                // Add all messages to mdList
                mdList.add(m6Header);
                mdList.add(m6Nonce);

                // Decrypt nonce:
                m6Nonce = this.decRSACipher.doFinal(m6Nonce);
                System.out.println("Message 6 Decrypted nonce contents:");
                System.out.println(ByteBuffer.wrap(m6Nonce).getLong());
            }
            catch (ClassNotFoundException | IllegalBlockSizeException | BadPaddingException e)
            {
                e.printStackTrace();
            }
            System.out.println();

            // MESSAGE 7
            System.out.println();
            System.out.println("Message 7 (SSL3_MT_CLIENT_KEY_EXCHANGE): ");
            // generate random nonce:
            SecureRandom random = new SecureRandom();
            // 8 bits in 1 byte, therefore 8 bytes = 64 bit challenge
            byte[] m7Nonce = new byte[8];
            random.nextBytes(m7Nonce);
            System.out.println(
                    "Client: Nonce generated: " + ByteBuffer.wrap(m7Nonce).getLong());

            // PREMASTER SECRET
            // Calculate premaster secret from nonces (before encrypting m7!)
            long premasterSecret =
                    ByteBuffer.wrap(m6Nonce).getLong() ^ ByteBuffer.wrap(m7Nonce).getLong();
            // Convert premaster secret to byte[]
            byte[] preMasterSecret =
                    ByteBuffer.allocate(Long.BYTES).putLong(premasterSecret).array();

            // Encrypt nonce from message 7
            try
            {
                // Encrypt nonce using RSA key
                m7Nonce = this.encRSACipher.doFinal(m7Nonce);
                System.out.println(
                        "Client: Encrypted Nonce being sent to server: "
                                + ByteBuffer.wrap(m7Nonce).getLong());
            }
            catch (IllegalBlockSizeException | BadPaddingException e)
            {
                e.printStackTrace();
            }
            // Generate header for nonce being sent
            long m7NonceSize = getObjectSize(m7Nonce);
            System.out.println("Client: size of encrypted nonce being sent: " + m7NonceSize);
            long[] m7ContentLength = {m7NonceSize};
            SSLRecordHeader m7Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CLIENT_KEY_EXCHANGE, m7ContentLength);

            // transmit nonce to server
            outStream.writeObject(m7Header);
            outStream.writeObject(m7Nonce);
            outStream.flush();
            // add nonce to md list
            mdList.add(m7Header);
            mdList.add(m7Nonce);


            // MESSAGE 8 (PREMASTER SECRET)
            System.out.println();
            System.out.println("Client: PremasterSecret was calculated: " + premasterSecret);
            long premasterSecretSize = getObjectSize(premasterSecret);
            System.out.println("Client: PremasterSecret size: " + premasterSecretSize);
            try
            {
                // Use premaster secret to generate keys for AES and HMAC
                this.aesKey = generateAESKey(preMasterSecret);
                this.hmacKey = generateHMACKey(preMasterSecret);
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }

            // Encrypt premaster secret
            try
            {
                // Encrypt secret using RSA key
                preMasterSecret = this.encRSACipher.doFinal(preMasterSecret);
                System.out.println(
                        "Client: Encrypted premaster secret being sent to server: "
                                + ByteBuffer.wrap(preMasterSecret).getLong());
            }
            catch (IllegalBlockSizeException | BadPaddingException e)
            {
                e.printStackTrace();
            }
            // Generate header for secret being sent
            long m8SecretSize = getObjectSize(preMasterSecret);
            System.out.println("Client: size of encrypted secret being sent: " + m8SecretSize);
            long[] m8ContentLength = {m8SecretSize};
            SSLRecordHeader m8Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CLIENT_KEY_EXCHANGE, m8ContentLength);

            // Transmit to server
            outStream.writeObject(m8Header);
            outStream.writeObject(preMasterSecret);
            outStream.flush();
            // add preMaster secret to md list
            mdList.add(m8Header);
            mdList.add(preMasterSecret);

            // MESSAGE DIGEST COMP
            // Create a list to store all computed MD
            ArrayList<byte[]> byteList = new ArrayList<>();
            // Compute message digest using sha-1
            try
            {
                String id = "CLIENT";
                byte[] key = new byte[preMasterSecret.length + id.getBytes().length];
                // Set the key for the hash
                SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA1");

                // Initialize the Mac with the secret key
                Mac mac = Mac.getInstance("HmacSHA1");
                mac.init(secretKeySpec);
                // Baos for serializing objects in mdList
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                for (Object o : mdList)
                {
                    // Serialize object
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    // write serialized obj to baos
                    oos.writeObject(o);
                    oos.flush();
                    byte[] serialized = baos.toByteArray();
                    baos.reset();
                    byte[] hash = mac.doFinal(serialized);
                    byteList.add(hash);

                }
            }
            catch (NoSuchAlgorithmException | InvalidKeyException e)
            {
                e.printStackTrace();
            }
            // Print out message digest
            System.out.println();
            System.out.println("Message digest computed using keyed SHA-1: ");
            for (byte[] byteArray : byteList)
            {
                System.out.println(Arrays.toString(byteArray));
            }
            System.out.println();

            // Compute expected server MD
            // Create a list to store all computed MD
            ArrayList<byte[]> byteList2 = new ArrayList<byte[]>();
            String id = "SERVER";
            byte[] key = new byte[preMasterSecret.length + id.getBytes().length];
            // Set the key for the hash
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA1");

            // Initialize the Mac with the secret key
            Mac mac;
            try
            {
                mac = Mac.getInstance("HmacSHA1");
                mac.init(secretKeySpec);
                // Baos for serializing objects in mdList
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                for (Object o : mdList)
                {
                    // Serialize object
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    // write serialized obj to baos
                    oos.writeObject(o);
                    oos.flush();
                    byte[] serialized = baos.toByteArray();
                    baos.reset();
                    byte[] hash = mac.doFinal(serialized);
                    byteList2.add(hash);
                }
            }
            catch (NoSuchAlgorithmException | InvalidKeyException e)
            {
                e.printStackTrace();
            }

            // Receive mac from server
            try
            {
                SSLRecordHeader m9Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 9 header received. Header contents:");
                m9Header.printHeader();

                System.out.println("Client: Server's MD received. Validating now.");
                ArrayList<byte[]> serverMd = (ArrayList<byte[]>) inStream.readObject();

                // Compare received md with expected results
                if (compareArrayLists(serverMd, byteList2))
                {
                    System.out.println("Client: Server's MD has been validated. Thanks server!");
                }
                else
                {
                    System.out.println("Client: Server's MD has been compromise. Abort!");
                }
            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }

            // MESSAGE 10
            System.out.println();
            System.out.println("Message 10 (SSL3_MT_FINISHED): ");
            // Create header for mac
            long m10MacSize = getObjectSize(byteList);
            System.out.println("Server: size of mac being sent: " + m10MacSize);
            long[] m10ContentLength = {m10MacSize};
            SSLRecordHeader m10Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_FINISHED, m10ContentLength);

            // Transmit mac to server
            outStream.writeObject(m10Header);
            outStream.writeObject(byteList);

            System.out.println();
            // HANDSHAKE PROTOCOL FINISHED

            System.out.println("Client: Waiting for data transfer to begin");

            // DATA TRANSFER MESSAGE
            System.out.println();
            System.out.println("Data Transfer (SSL3_RT_APPLICATION_DATA): ");

            // Read in messages from server
            SSLRecordHeader fileHeader = null;
            byte[] fileBytes = null;
            SSLRecordHeader hmacHeader = null;
            byte[] hmacSigRec = null;
            try
            {
                // Read in file header first
                fileHeader = (SSLRecordHeader) inStream.readObject();
                System.out.println("File header received. Header contents:");
                fileHeader.printHeader();
                System.out.println();

                // Read in all bytes of the file being transferred from server
                fileBytes = inStream.readAllBytes();
                System.out.println();


                // Read in hmac header next
                hmacHeader = (SSLRecordHeader) inStream.readObject();
                System.out.println("HMAC header received. Header contents:");
                hmacHeader.printHeader();
                System.out.println();

                // read in hmac sig
                hmacSigRec = (byte[]) inStream.readObject();

                // test validity of hmac
                // Sign file with hmac key
                mac = Mac.getInstance("HmacSHA256");
                mac.init(this.hmacKey);
                mac.update(fileBytes);
                byte[] hmacSig = mac.doFinal();


                if (Arrays.compare(hmacSig, hmacSigRec) == 0)
                {
                    System.out.println("Client: signature on file validated.");
                }
                else
                {
                    System.out.println("Client: File has been tampered with. Abort");
                }
                System.out.println();

                // Decrypt file
                Cipher cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.DECRYPT_MODE, this.aesKey);
                fileBytes = cipher.doFinal(fileBytes);
            }
            catch (ClassNotFoundException | NoSuchAlgorithmException | InvalidKeyException
                    | NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e)
            {
                e.printStackTrace();
            }


            // Write received bytes into a copy file
            Files.write(Paths.get("test_copy.txt"), fileBytes);

            System.out.println("Client: Performing diff on files now");
            int diffCount = 0;
            // Iterate through each file line by line and compare the two
            try (BufferedReader br1 = new BufferedReader(new FileReader("test.txt"));
                    BufferedReader br2 = new BufferedReader(new FileReader("test_copy.txt")))
            {
                String line1, line2;
                while ((line1 = br1.readLine()) != null && (line2 = br2.readLine()) != null)
                {
                    // If a diff is found, increment count and continue comparing
                    if (!line1.equals(line2))
                    {
                        diffCount++;
                    }
                }
            }
            catch (IOException e)
            {
                e.printStackTrace();
            }
            // Report result of diff
            if (diffCount == 0)
            {
                System.out.println("Client: Yay! No diff was found!!");
            }
            else
            {
                System.out.println("Client: diff between files found. Num diffs: " + diffCount);

            }

            // close server socket and in/out streams
            serverSocket.close();
            inStream.close();
            outStream.close();
        }
        catch (

        UnknownHostException ex)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, ex);
        }
        catch (IOException e)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
    }


    public void sslHandshakeFail()
    {
        // List contains all sent/received messages for MD computation
        ArrayList<Object> mdList = new ArrayList<Object>();

        // Connect to Server
        try
        {
            InetAddress host = InetAddress.getByName("localhost");
            // Connect client to the server
            Socket serverSocket = new Socket(host, SERVERPORT);
            System.out.println("Client: Connected to server");

            // in/out streams for communication with server
            ObjectInputStream inStream =
                    new ObjectInputStream(serverSocket.getInputStream());
            ObjectOutputStream outStream =
                    new ObjectOutputStream(serverSocket.getOutputStream());
            System.out.println();


            System.out.println("Client: Sending Handshake Hello to Server.");
            System.out.println();

            // MESSAGE 1
            System.out.println("Message 1 (SSL3_MT_CLIENT_HELLO): ");
            // Send server encryption and I/G algo suite (enforced)
            String m1String = "AES:256 bit. HMAC:SHA256";
            System.out.println("Client: Cipher suite being sent: " + m1String);

            // find byte size of cipher suite
            long m1StringSize = getObjectSize(m1String);
            System.out.println("Client: size of cipher suite message: " + m1StringSize);
            // Size of first message being sent to server
            long[] m1ContentLength = {m1StringSize};

            // initial Client Hello header.
            SSLRecordHeader m1Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CLIENT_HELLO, m1ContentLength);
            // Transmit header and payload to server
            outStream.writeObject(m1Header);
            outStream.writeObject(m1String);
            outStream.flush();
            // Write all m1 messages to mdList
            mdList.add(m1Header);
            mdList.add(m1String);
            System.out.println();


            // MESSAGE 2
            System.out.println();
            System.out.println("Message 2 (SSL3_MT_SERVER_HELLO): ");
            // M2Header and Cipher suite string received next
            // Header received first
            SSLRecordHeader m2Header;
            try
            {
                m2Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 2 header received. Header contents:");
                m2Header.printHeader();
                // Cipher suite string received next
                String m2String = (String) inStream.readObject();
                System.out.println("Message 2 Cipher suite Accepted. Cipher suite contents:");
                System.out.println(m2String);
                // Write all m2 messages to mdList
                mdList.add(m2Header);
                mdList.add(m2String);
            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }
            System.out.println();

            // MESSAGE 3
            System.out.println();
            System.out.println("Message 3 (SSL3_MT_CERTIFICATE): ");
            // Receive cert etc
            Certificate m3Certificate = null;
            SSLRecordHeader m3Header = null;
            try
            {
                // Header received first
                m3Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 3 header received. Header contents:");
                m3Header.printHeader();

                // Certificate received next
                m3Certificate = (Certificate) inStream.readObject();
                System.out.println(
                        "Message 3 Server certificate received. Server certificate contents:");
                printCertContents(m3Certificate);
                // Add m3Header and m3Certificate to mdList
                mdList.add(m3Header);
                mdList.add(m3Certificate);

            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }
            System.out.println();

            // MESSAGE 4
            System.out.println();
            System.out.println("Message 4 (SSL3_MT_CERTIFICATE_REQUEST): ");
            // M2Header and Cipher suite string received next
            // Header received first
            SSLRecordHeader m4Header;
            try
            {
                m4Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 4 header received. Header contents:");
                m4Header.printHeader();
                // Cipher suite string received next
                String m4String = (String) inStream.readObject();
                System.out.println("Message 4 Request received. Request from server:");
                System.out.println(m4String);
                // Write all m4 messages to mdList
                mdList.add(m4Header);
                mdList.add(m4String);
            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }


            // MESSAGE 5
            System.out.println();
            System.out.println("Message 5 (SSL3_MT_CERTIFICATE): ");
            // find byte size of server's certificate
            long m5ServerCertSize = getObjectSize(this.clientCert);
            System.out.println("Client: size of certificate being sent: " + m5ServerCertSize);
            System.out.println();
            long[] m5ContentLength = {m5ServerCertSize};
            SSLRecordHeader m5Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CERTIFICATE, m5ContentLength);
            // Transmit header and payload to client
            outStream.writeObject(m5Header);
            outStream.writeObject(this.clientCert);
            outStream.flush();
            // Add m5Header and cert to mdList
            mdList.add(m5Header);
            mdList.add(this.clientCert);


            // VALIDATE CERTIFICATE
            System.out.println();
            System.out.println("Client: Validating received certificate: ");
            validateCertificate(m3Certificate);
            System.out.println();

            // MESSAGE 6
            System.out.println();
            System.out.println("Message 6 (SSL3_MT_SERVER_KEY_EXCHANGE): ");
            // Placeholder for nonce
            byte[] m6Nonce = null;
            SSLRecordHeader m6Header = null;
            // Receive cert etc
            try
            {
                m6Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 6 header received. Header contents:");
                m6Header.printHeader();
                // Receive server's nonce
                m6Nonce = (byte[]) inStream.readObject();
                System.out.println("Message 6 Nonce received. Encrypted nonce contents:");
                System.out.println(ByteBuffer.wrap(m6Nonce).getLong());

                // Add all messages to mdList
                mdList.add(m6Header);
                mdList.add(m6Nonce);

                // Decrypt nonce:
                m6Nonce = this.decRSACipher.doFinal(m6Nonce);
                System.out.println("Message 6 Decrypted nonce contents:");
                System.out.println(ByteBuffer.wrap(m6Nonce).getLong());
            }
            catch (ClassNotFoundException | IllegalBlockSizeException | BadPaddingException e)
            {
                e.printStackTrace();
            }
            System.out.println();

            // MESSAGE 7
            System.out.println();
            System.out.println("Message 7 (SSL3_MT_CLIENT_KEY_EXCHANGE): ");
            // generate random nonce:
            SecureRandom random = new SecureRandom();
            // 8 bits in 1 byte, therefore 8 bytes = 64 bit challenge
            byte[] m7Nonce = new byte[8];
            random.nextBytes(m7Nonce);
            System.out.println(
                    "Client: Nonce generated: " + ByteBuffer.wrap(m7Nonce).getLong());

            // PREMASTER SECRET
            // Calculate premaster secret from nonces (before encrypting m7!)
            long premasterSecret =
                    ByteBuffer.wrap(m6Nonce).getLong() ^ ByteBuffer.wrap(m7Nonce).getLong();
            // Convert premaster secret to byte[]
            byte[] preMasterSecret =
                    ByteBuffer.allocate(Long.BYTES).putLong(premasterSecret).array();

            // Encrypt nonce from message 7
            try
            {
                // Encrypt nonce using RSA key
                m7Nonce = this.encRSACipher.doFinal(m7Nonce);
                System.out.println(
                        "Client: Encrypted Nonce being sent to server: "
                                + ByteBuffer.wrap(m7Nonce).getLong());
            }
            catch (IllegalBlockSizeException | BadPaddingException e)
            {
                e.printStackTrace();
            }
            // Generate header for nonce being sent
            long m7NonceSize = getObjectSize(m7Nonce);
            System.out.println("Client: size of encrypted nonce being sent: " + m7NonceSize);
            long[] m7ContentLength = {m7NonceSize};
            SSLRecordHeader m7Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CLIENT_KEY_EXCHANGE, m7ContentLength);

            // transmit nonce to server
            outStream.writeObject(m7Header);
            outStream.writeObject(m7Nonce);
            outStream.flush();
            // add nonce to md list
            mdList.add(m7Header);
            mdList.add(m7Nonce);


            // MESSAGE 8 (PREMASTER SECRET)
            System.out.println();
            System.out.println("Client: PremasterSecret was calculated: " + premasterSecret);
            long premasterSecretSize = getObjectSize(premasterSecret);
            System.out.println("Client: PremasterSecret size: " + premasterSecretSize);
            try
            {
                // Use premaster secret to generate keys for AES and HMAC
                this.aesKey = generateAESKey(preMasterSecret);
                this.hmacKey = generateHMACKey(preMasterSecret);
            }
            catch (NoSuchAlgorithmException e)
            {
                e.printStackTrace();
            }

            // Encrypt premaster secret
            try
            {
                // Encrypt secret using RSA key
                preMasterSecret = this.encRSACipher.doFinal(preMasterSecret);
                System.out.println(
                        "Client: Encrypted premaster secret being sent to server: "
                                + ByteBuffer.wrap(preMasterSecret).getLong());
            }
            catch (IllegalBlockSizeException | BadPaddingException e)
            {
                e.printStackTrace();
            }
            // Generate header for secret being sent
            long m8SecretSize = getObjectSize(preMasterSecret);
            System.out.println("Client: size of encrypted secret being sent: " + m8SecretSize);
            long[] m8ContentLength = {m8SecretSize};
            SSLRecordHeader m8Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.SSL3_MT_CLIENT_KEY_EXCHANGE, m8ContentLength);

            // Transmit to server
            outStream.writeObject(m8Header);
            outStream.writeObject(preMasterSecret);
            outStream.flush();
            // add preMaster secret to md list
            mdList.add(m8Header);

            // *FORGET* TO ADD PREMASTER SECRET TO MESSAGE DIGEST. CAUSING HANDSHAKE TO FAIL!
            // mdList.add(preMasterSecret);

            // MESSAGE DIGEST COMP
            // Create a list to store all computed MD
            ArrayList<byte[]> byteList = new ArrayList<>();
            // Compute message digest using sha-1
            try
            {
                String id = "CLIENT";
                byte[] key = new byte[preMasterSecret.length + id.getBytes().length];
                // Set the key for the hash
                SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA1");

                // Initialize the Mac with the secret key
                Mac mac = Mac.getInstance("HmacSHA1");
                mac.init(secretKeySpec);
                // Baos for serializing objects in mdList
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                for (Object o : mdList)
                {
                    // Serialize object
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    // write serialized obj to baos
                    oos.writeObject(o);
                    oos.flush();
                    byte[] serialized = baos.toByteArray();
                    baos.reset();
                    byte[] hash = mac.doFinal(serialized);
                    byteList.add(hash);

                }
            }
            catch (NoSuchAlgorithmException | InvalidKeyException e)
            {
                e.printStackTrace();
            }
            // Print out message digest
            System.out.println();
            System.out.println("Message digest computed using keyed SHA-1: ");
            for (byte[] byteArray : byteList)
            {
                System.out.println(Arrays.toString(byteArray));
            }
            System.out.println();

            // Compute expected server MD
            // Create a list to store all computed MD
            ArrayList<byte[]> byteList2 = new ArrayList<byte[]>();
            String id = "SERVER";
            byte[] key = new byte[preMasterSecret.length + id.getBytes().length];
            // Set the key for the hash
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacSHA1");

            // Initialize the Mac with the secret key
            Mac mac;
            try
            {
                mac = Mac.getInstance("HmacSHA1");
                mac.init(secretKeySpec);
                // Baos for serializing objects in mdList
                ByteArrayOutputStream baos = new ByteArrayOutputStream();

                for (Object o : mdList)
                {
                    // Serialize object
                    ObjectOutputStream oos = new ObjectOutputStream(baos);
                    // write serialized obj to baos
                    oos.writeObject(o);
                    oos.flush();
                    byte[] serialized = baos.toByteArray();
                    baos.reset();
                    byte[] hash = mac.doFinal(serialized);
                    byteList2.add(hash);
                }
            }
            catch (NoSuchAlgorithmException | InvalidKeyException e)
            {
                e.printStackTrace();
            }

            // Receive mac from server
            try
            {
                SSLRecordHeader m9Header = (SSLRecordHeader) inStream.readObject();
                System.out.println("Message 9 header received. Header contents:");
                m9Header.printHeader();

                System.out.println("Client: Server's MD received. Validating now.");
                ArrayList<byte[]> serverMd = (ArrayList<byte[]>) inStream.readObject();

                // Compare received md with expected results
                if (compareArrayLists(serverMd, byteList2))
                {
                    System.out.println("Client: Server's MD has been validated. Thanks server!");
                }
                else
                {
                    System.out.println("Client: Server's MD has been compromised. Abort!");
                }
            }
            catch (ClassNotFoundException e)
            {
                e.printStackTrace();
            }

            // MESSAGE 10
            System.out.println();
            System.out.println("Message 10 (TLS1_AD_DECRYPTION_FAILED ): ");
            String errString = "MAC received doesn't match expected MAC. Ending session.";
            System.out.println("Client: Error message being sent to server: " + errString);
            // Create header for errMessage
            long errStringSize = getObjectSize(errString);
            System.out.println("Client: Size of error being sent: " + errStringSize);
            long[] m10ContentLength = {errStringSize};
            SSLRecordHeader m10Header = new SSLRecordHeader(SSLRecordHeader.TLS1_3_VERSION,
                    SSLRecordHeader.TLS1_AD_DECRYPTION_FAILED, m10ContentLength);

            // Transmit error to server
            outStream.writeObject(m10Header);
            outStream.writeObject(errString);

            System.out.println();
            // HANDSHAKE PROTOCOL FINISHED

            // close server socket and in/out streams
            serverSocket.close();
            inStream.close();
            outStream.close();
        }
        catch (UnknownHostException ex)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, ex);
        }
        catch (IOException e)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
    }

    /*
     * Compares to array lists that could be in any order. If the lists contain the same elements,
     * they are determined equal and method returns true. If they do not contain the same elements,
     * returns false.
     */
    public static boolean compareArrayLists(ArrayList<byte[]> list1, ArrayList<byte[]> list2)
    {
        if (list1.size() != list2.size())
        {
            return false;
        }
        // Sort the lists
        Collections.sort(list1, Comparator.comparing(Arrays::hashCode));
        Collections.sort(list2, Comparator.comparing(Arrays::hashCode));
        // Compare the lists
        for (int i = 0; i < list1.size(); i++)
        {
            byte[] arr1 = list1.get(i);
            byte[] arr2 = list2.get(i);
            if (!Arrays.equals(arr1, arr2))
            {
                return false;
            }
        }
        return true;
    }

    public static void main(String[] args) throws Exception
    {
        Client c = new Client();
        // c.sslHandshakeSuccess();
        c.sslHandshakeFail();
    }
}
