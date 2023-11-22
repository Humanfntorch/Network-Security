import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

/*
 * Bob acts as both server (Alice) and client (Kdc) in the NHS protocol
 */
public class Bob
{
    // Logger for error handling
    private static final Logger LOGGER = Logger.getLogger(Bob.class.getName());
    // RSA key pair used to transmit Bob's 3DES key to KDC
    private PublicKey publicRSAKey;
    private PrivateKey privateRSAKey;
    // Bob's unique ID for verification with KDC
    private final int bobID = 01;

    // Symmetric key for KDC
    private SecretKey myKdcKey;
    // Shared 3DES key between Alice/Bob
    private SecretKey aliceBobKey;
    // ID used to verify Alice
    private final int aliceID = 02;

    // port to connect to KDC
    private final int kdcPort = 8080;
    // port to connect Bob from Alice
    private final int serverPort = 9020;
    // port to connect to Bob for reflection attack
    private final int bobPortReflection = 8000;
    // Cipher used in encrypting/decrypting messages to KDC and Alice
    private Cipher kdcCipher;


    /*
     * Constructor for Bob. Initializes a symmetric key to be used with the KDC. Keys are generated
     * using Java.security package with the RSA algorithm and a key size of 2048 bits. After key
     * construction, connects to KDC to transmit + key for storage.
     */
    public Bob()
    {

        // Generate Bob's public/private RSA key pair
        KeyPairGenerator keyPairGen;
        try
        {
            keyPairGen = KeyPairGenerator.getInstance("RSA");
            // Initialize the key pair to generate keys with 2048-bit security
            keyPairGen.initialize(2048);
            // Generate the key pair
            KeyPair keyPair = keyPairGen.generateKeyPair();

            // Get the public and private keys
            this.publicRSAKey = keyPair.getPublic();
            this.privateRSAKey = keyPair.getPrivate();
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Bob: RSA Key Generation failed.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }

        // Generate 3DES key
        this.myKdcKey = null;
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
            this.myKdcKey = keyGen.generateKey();
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Bob's symmetric key generation failed.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }

        try
        {
            this.kdcCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Error generating KDC cipher obj");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
        catch (NoSuchPaddingException e)
        {
            System.out.println("Error generating KDC cipher obj");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
        // Transmit keys to kdc using helper
        kdcTransmit();
    }

    public void kdcTransmit()
    {
        try
        {
            InetAddress host = InetAddress.getByName("localhost");

            // Connect Bob to the KDC server
            Socket kdcSocket = new Socket(host, this.kdcPort);
            System.out.println("Bob: I've connected to KDC.");

            // Allows Bob to transmit key to KDC
            ObjectOutputStream kdcOutStream =
                    new ObjectOutputStream(kdcSocket.getOutputStream());
            // Transmit key to kdc
            System.out.println("Bob: Transmitting RSA key to KDC now.");
            kdcOutStream.writeObject(this.publicRSAKey);
            kdcOutStream.flush();
            System.out.println("Bob: RSA key transmitted. Sending encrypted ID now. Unencrypted ID: " + this.bobID);

            Cipher encryptCipher = null;
            try
            {
                // Encrypt id and transmit to kdc
                encryptCipher = Cipher.getInstance("RSA");
                encryptCipher.init(Cipher.ENCRYPT_MODE, this.privateRSAKey);
                byte[] encryptedID = encryptCipher.doFinal(ByteBuffer.allocate(4)
                        .putInt(this.bobID).array());
                System.out.println("Bob: Transmitting encrypted ID now: " + encryptedID + ".");
                kdcOutStream.writeObject(encryptedID);
                kdcOutStream.flush();

                // KDC now read to accept encrypted 3DES Key
                System.out.println("Bob: Great. Transmitting 3DES key now.");
                // enc key
                byte[] encEdesKey =
                        encryptCipher.doFinal(this.myKdcKey.getEncoded());
                System.out.println("Bob: Encrypted key sent to KDC: " + encEdesKey);

                // Transmit to kdc
                kdcOutStream.writeObject(encEdesKey);
                kdcOutStream.flush();

            }
            catch (InvalidKeyException | NoSuchAlgorithmException
                    | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e)
            {
                System.out.println(
                        "Bob: Error transmitting encrypted ID and 3DES key to KDC.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            // Key transmission complete. End transmission
            System.out.println("Bob: Ending communication with KDC.");
            System.out.println();
            kdcOutStream.close();
            kdcSocket.close();
        }
        catch (IOException e)
        {
            System.out.println("Bob: Error connecting to KDC");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }

    }

    public void extendedNHS()
    {
        // Setup server
        try
        {
            // Open server
            ServerSocket serverSocket = new ServerSocket(this.serverPort);
            // Indicates when a client is still communicating with server
            boolean openSocket = true;

            while (openSocket)
            {
                System.out.println("Bob: Waiting for connection...");
                // Accept in client and report to console
                Socket client = serverSocket.accept();
                byte[] initNonce = Kdc.generateNonce();
                System.out.println(
                        "Bob: Connection established. Speak to KDC first. Transmitting Nonce: " + ByteBuffer.wrap(initNonce).getLong());

                // Encrypt Bob's nonce
                try
                {
                    this.kdcCipher.init(Cipher.ENCRYPT_MODE, this.myKdcKey);
                    initNonce = this.kdcCipher.doFinal(initNonce);
                    System.out.println("Bob: Encrypted Nonce sent to Alice: " + ByteBuffer.wrap(initNonce).getLong());

                }
                catch (InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }

                // Send Alice 1st challenge
                ObjectOutputStream outStream =
                        new ObjectOutputStream(client.getOutputStream());
                outStream.writeObject(initNonce);

                // Receive ticket from Alice
                System.out.println("Bob: Awaiting response for my ticket.");
                ObjectInputStream inStream =
                        new ObjectInputStream(client.getInputStream());
                try
                {
                    byte[] receivedNonce = (byte[]) inStream.readObject();
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    try
                    {
                        // Receive nonce from Alice
                        receivedNonce = this.kdcCipher
                                .doFinal(receivedNonce);
                        initNonce = this.kdcCipher.doFinal(initNonce);


                        // Validate initial nonce
                        if (!Arrays.equals(initNonce, receivedNonce))
                        {
                            System.out.println(
                                    "Nonce provided isn't Nonce sent. Terminating session.");
                        }
                        System.out.println("Bob: Initial Nonce Validated. Received nonce: " + ByteBuffer.wrap(receivedNonce).getLong() + " Ready to receive key.");

                        // Receive shared key
                        byte[] encKey = (byte[]) inStream.readObject();
                        // Decrypt key
                        encKey = this.kdcCipher.doFinal(encKey);
                        System.out.println("Bob: 3DES key received from Alice (created by KDC): " + encKey);

                        // Convert byte[] to SecretKey
                        SecretKeyFactory factory = SecretKeyFactory
                                .getInstance("DESede");
                        KeySpec spec = new DESedeKeySpec(encKey);
                        this.aliceBobKey = factory.generateSecret(spec);
                    }
                    catch (IllegalBlockSizeException | NoSuchAlgorithmException
                            | InvalidKeySpecException | BadPaddingException e)
                    {
                        System.out.println("Bob: Failed to authenticate KDC Ticket. Terminating");
                        LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                    }
                }
                catch (ClassNotFoundException | InvalidKeyException e)
                {
                    System.out.println(
                            "Bob: Failed to receive ticket. Aborting.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }

                // Receive challenge from Alice.
                System.out.println("Bob: Key received. Ready to receive nonce for authentication.");
                byte[] nonceTwo = null;
                try
                {
                    nonceTwo = (byte[]) inStream.readObject();
                    System.out.println("Bob: Nonce received, encrypted nonce: " + ByteBuffer.wrap(nonceTwo).getLong() + ".");
                }
                catch (ClassNotFoundException e)
                {
                    System.out.println(
                            "Bob: Failed to receive second challenge");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Nonce received, beginning authentication exchange.");

                // decrypt nonce, update, then encrypt
                try
                {
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, aliceBobKey);
                    nonceTwo = this.kdcCipher.doFinal(nonceTwo);
                    System.out.println("Bob: Decrypted nonce: " + ByteBuffer.wrap(nonceTwo).getLong() + ".");

                    // convert nonce to long, then subtract 1 off
                    long updateNonce = ByteBuffer.wrap(nonceTwo).getLong();
                    updateNonce--;
                    System.out.println("Bob: Updated nonce: " + updateNonce + ".");
                    // convert back to byte[]
                    nonceTwo = ByteBuffer.allocate(Long.BYTES)
                            .putLong(updateNonce).array();
                    this.kdcCipher.init(Cipher.ENCRYPT_MODE, aliceBobKey);
                    nonceTwo = this.kdcCipher.doFinal(nonceTwo);
                }
                catch (InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                // transmit nonce to Alice
                System.out.println("Bob: Transmitting updated nonce now.");
                outStream.writeObject(nonceTwo);
                outStream.flush();

                // Generate third nonce, encrypt and transmit to Alice
                byte[] nonceThree = Kdc.generateNonce();
                try
                {
                    System.out.println("Bob: Third and final nonce generated: " + ByteBuffer.wrap(nonceThree).getLong());
                    this.kdcCipher.init(Cipher.ENCRYPT_MODE, aliceBobKey);
                    nonceThree = this.kdcCipher.doFinal(nonceThree);
                    System.out.println("Bob: Encrypted third nonce: " + ByteBuffer.wrap(nonceThree).getLong());
                }
                catch (InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Transmitting third and final nonce now.");
                outStream.writeObject(nonceThree);
                outStream.flush();
                System.out.println("Bob: Awaiting for updated nonce for validation.");

                // Receive third nonce
                try
                {
                    byte[] receivedNonce = (byte[]) inStream.readObject();
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, aliceBobKey);
                    // Decrypt both nonces, then compare
                    receivedNonce = this.kdcCipher.doFinal(receivedNonce);
                    nonceThree = this.kdcCipher.doFinal(nonceThree);
                    System.out.println("Bob: Nonce received, validating now.");

                    // Validate nonce to confirm alice
                    if (ByteBuffer.wrap(nonceThree).getLong() - 1 == ByteBuffer
                            .wrap(receivedNonce).getLong())
                    {
                        System.out.println("Bob: Nonce validated. Nonce received: " + ByteBuffer.wrap(receivedNonce).getLong());
                    }
                    else
                    {
                        System.out.println(
                                "Bob: Challenge failed. terminating");
                    }
                }
                catch (ClassNotFoundException | InvalidKeyException
                        | IllegalBlockSizeException | BadPaddingException e)
                {
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.print("Bob: Alice has been authenticated. Protocol complete.");

                // Report protocol is completed
                System.out.println("Bob: Ending communication with Alice.");
                System.out.println();
                openSocket = false;
                client.close();
            }
            serverSocket.close();
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
     * Method details the reflection attack created by Trudy, who is understood to have intercepted
     * the final three message in the original NHS protocol, and mysteriously has access to Bob's
     * ticket, which allows her to accomplish the reflection attack. Protocol is assumed to begin
     * after the exchange Alice/KDC and Alice/Bob and that the primary protocol is the standard
     * (original) NHS, rather than the extended version
     */
    public void ecbTrudy()
    {
        // Setup server
        try
        {
            System.out.println("Original Needham Schroeder Successful Reflection Attack");
            // Open server
            ServerSocket serverSocket = new ServerSocket(this.bobPortReflection);
            // Indicates when a client is still communicating with server
            boolean openSocket = true;

            while (openSocket)
            {
                System.out.println("Bob: Waiting for connection...");
                // Accept in client and report to console
                Socket client = serverSocket.accept();
                System.out.println("Bob: Client received. Ready to receive KDC ticket");
                // Initialize obj's for communication
                ObjectInputStream inStream = new ObjectInputStream(client.getInputStream());
                System.out.println("Bob: Awaiting initial nonce.");

                // receive shared key
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encKey = (byte[]) inStream.readObject();
                    // Decrypt key
                    encKey = this.kdcCipher.doFinal(encKey);
                    System.out.println("Bob: Key received: " + encKey);
                    // Convert byte[] to SecretKey
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
                    KeySpec spec = new DESedeKeySpec(encKey);
                    this.aliceBobKey = factory.generateSecret(spec);
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | NoSuchAlgorithmException
                        | InvalidKeySpecException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Key received and processed succesfully.");

                // receive Alice's ID and verify
                System.out.println("Bob: Determining client's ID now.");
                int id = -1;
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encId = (byte[]) inStream.readObject();
                    // Decrypt key
                    encId = this.kdcCipher.doFinal(encId);
                    // Convert byte[] to int
                    id = ByteBuffer.wrap(encId).getInt();
                    if (id == this.aliceID)
                    {
                        System.out.println("Bob: Verified ID as Alice. ID deciphered: " + id);
                    }
                    else
                    {
                        System.out.println("Bob: Unknown ID. Ending communication");
                    }
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Ticket processed succesfully. Thank's Alice.");

                // Begin protocol with "Alice"
                System.out.println("Bob: Awaiting nonce challenge.");
                byte[] nonceOne = null;
                try
                {
                    // Decrypt nonce
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.aliceBobKey);
                    byte[] decNonce = (byte[]) inStream.readObject();
                    System.out.println("Bob: Nonce received. Encrypted nonce: " + ByteBuffer.wrap(decNonce).getLong());

                    // Decrypt key
                    decNonce = this.kdcCipher.doFinal(decNonce);
                    System.out.println("Bob: Decrypted nonce: " + ByteBuffer.wrap(decNonce).getLong());

                    // Convert byte[] to long and update
                    long updateNonce = ByteBuffer.wrap(decNonce).getLong();
                    updateNonce--;
                    System.out.println("Bob: Updated nonce: " + updateNonce);

                    // convert back to byte[]
                    decNonce = ByteBuffer.allocate(Long.BYTES)
                            .putLong(updateNonce).array();
                    nonceOne = decNonce;
                    // encrypt nonce
                    this.kdcCipher.init(Cipher.ENCRYPT_MODE, aliceBobKey);
                    nonceOne = this.kdcCipher.doFinal(nonceOne);
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    System.out.println("Bob: Could not receive nonce.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }

                // Transmit response back to "Alice"
                System.out.println("Bob: Transmitting response to challenge now.");
                // Obj Out stream to send messages
                ObjectOutputStream outStream = new ObjectOutputStream(client.getOutputStream());
                outStream.writeObject(nonceOne);

                // Generate last challenge
                byte[] lastNonce = Kdc.generateNonce();
                // Encrypt nonce
                try
                {
                    System.out.println("Bob: Last challenge generated: " + ByteBuffer.wrap(lastNonce).getLong());

                    this.kdcCipher.init(Cipher.ENCRYPT_MODE, aliceBobKey);
                    lastNonce = this.kdcCipher.doFinal(lastNonce);
                    System.out.println("Bob: Last challenge encrypted: " + ByteBuffer.wrap(lastNonce).getLong());

                }
                catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
                {
                    System.out.println("Bob: Failure to encrypt final nonce");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                // Transmit final challenge to "Alice"
                System.out.println("Bob: Transmitting final challenge.");
                outStream.writeObject(lastNonce);

                // Receive response to challenge from "Alice"
                System.out.println("Bob: Awaiting final response");
                System.out.println();

                // This is super hacky, should be handled by multiple threads, but works
                // Accept client 2 for Trudy to perform attack...
                Socket client2 = serverSocket.accept();
                System.out.println();
                System.out.println("Session 2:");
                System.out.println("Bob: Client received. Ready to receive KDC ticket");
                // Initialize obj's for communication
                ObjectInputStream inStream2 = new ObjectInputStream(client2.getInputStream());
                System.out.println("Bob: Awaiting initial nonce.");

                // receive shared key
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encKey = (byte[]) inStream2.readObject();
                    // Decrypt key
                    encKey = this.kdcCipher.doFinal(encKey);
                    System.out.println("Bob: Key received: " + encKey);

                    // Convert byte[] to SecretKey
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
                    KeySpec spec = new DESedeKeySpec(encKey);
                    this.aliceBobKey = factory.generateSecret(spec);
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | NoSuchAlgorithmException
                        | InvalidKeySpecException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Key received and processed succesfully.");

                // receive Alice's ID and verify
                System.out.println("Bob: Determining client's ID now.");
                int id2 = -1;
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encId = (byte[]) inStream2.readObject();
                    // Decrypt key
                    encId = this.kdcCipher.doFinal(encId);
                    // Convert byte[] to int
                    id2 = ByteBuffer.wrap(encId).getInt();
                    if (id2 == this.aliceID)
                    {
                        System.out.println("Bob: Verified ID as Alice. ID deciphered: " + id2);
                    }
                    else
                    {
                        System.out.println("Bob: Unknown ID. Ending communication");
                    }
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Ticket processed succesfully. Thank's Alice.");

                // Begin protocol with "Alice"
                System.out.println("Bob: Awaiting nonce challenge.");
                byte[] nonceOne2 = null;
                try
                {   
                    // Decrypt nonce
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.aliceBobKey);
                    byte[] decNonce = (byte[]) inStream2.readObject();
                    System.out.println("Bob: Nonce received. Encrypted nonce: " + ByteBuffer.wrap(decNonce).getLong());
                    // Decrypt key
                    decNonce = this.kdcCipher.doFinal(decNonce);
                    System.out.println("Bob: Decrypted nonce: " + ByteBuffer.wrap(decNonce).getLong());
                    // Convert byte[] to long and update
                    long updateNonce = ByteBuffer.wrap(decNonce).getLong();
                    updateNonce--;
                    System.out.println("Bob: Updated nonce: " + updateNonce);
                    // convert back to byte[]
                    decNonce = ByteBuffer.allocate(Long.BYTES)
                            .putLong(updateNonce).array();
                    nonceOne2 = decNonce;
                    // encrypt updated nonce
                    this.kdcCipher.init(Cipher.ENCRYPT_MODE, this.aliceBobKey);
                    nonceOne2 = this.kdcCipher.doFinal(nonceOne2);
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    System.out.println("Bob: Could not receive nonce.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }

                // Transmit response back to "Alice"
                System.out.println("Bob: Transmitting response to challenge now. Encrypted response: " + ByteBuffer.wrap(nonceOne2).getLong());
                // Obj Out stream to send messages 
                ObjectOutputStream outStream2 = new ObjectOutputStream(client2.getOutputStream());
                outStream2.writeObject(nonceOne2);
                System.out.println();
                System.out.println("Session 1:");

                byte[] lastEncNonce = null;
                try
                {
                    lastEncNonce = (byte[]) inStream.readObject();
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.aliceBobKey);
                    System.out.println(
                            "Bob: Final response received. Encrypted response: " + ByteBuffer.wrap(lastEncNonce).getLong());
                    lastNonce = this.kdcCipher.doFinal(lastNonce);
                    // decrypt response
                    lastEncNonce = this.kdcCipher.doFinal(lastEncNonce);
                    System.out.println(
                        "Bob: Decrypted response: " + ByteBuffer.wrap(lastEncNonce).getLong());

                    // Validate received nonce with generated challenge
                    if (ByteBuffer.wrap(lastNonce).getLong() - 1 == ByteBuffer
                            .wrap(lastEncNonce).getLong())
                    {
                        System.out.println("Bob: Nonce validated.");
                    }
                    else
                    {
                        System.out.println(
                                "Bob: Challenge failed. terminating");
                        System.exit(1);
                    }
                }
                catch (ClassNotFoundException | IllegalBlockSizeException
                        | BadPaddingException | InvalidKeyException e)
                {
                    System.out.println(
                            "Bob: Failure to receive final challenge. Terminating session.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.print("Bob: Alice has been authenticated. Protocol complete.");

                // Report protocol is completed
                System.out.println("Bob: Ending communication with Alice.");
                System.out.println();
                openSocket = false;
                client.close();
                client2.close();
                openSocket = false;
            }
            serverSocket.close();
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
     * Method details the reflection attack created by Trudy, who is understood to have intercepted
     * the final three message in the original NHS protocol, and mysteriously has access to Bob's
     * ticket, which allows her to accomplish the reflection attack. Protocol is assumed to begin
     * after the exchange Alice/KDC and Alice/Bob and that the primary protocol is the standard
     * (original) NHS, rather than the extended version. Method uses EBC, which blocks Trudy's
     * attack.
     */
    public void cbcTrudy()
    {

        // Create new cipher to use CBC mode
        Cipher cbcCipher = null;
        // iv used in cbc algorithm
        IvParameterSpec iv = Kdc.generateIV();
        try
        {
            cbcCipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            System.out.println("Bob: Trouble converting cipher to CBC.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }

        // Setup server
        try
        {
            System.out.println("Original Needham Schroeder Failed Reflection Attack");
            // Open server
            ServerSocket serverSocket = new ServerSocket(this.bobPortReflection);
            // Indicates when a client is still communicating with server
            boolean openSocket = true;

            while (openSocket)
            {
                System.out.println("Bob: Waiting for connection...");
                // Accept in client and report to console
                Socket client = serverSocket.accept();
                System.out.println("Bob: Client received. Ready to receive KDC ticket");
                System.out.println("Bob: Generated IV for CBC session: " + iv + ".");
                // Initialize obj's for communication
                ObjectInputStream inStream = new ObjectInputStream(client.getInputStream());
                System.out.println("Bob: Awaiting initial nonce.");

                // receive shared key
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encKey = (byte[]) inStream.readObject();
                    // Decrypt key
                    encKey = this.kdcCipher.doFinal(encKey);
                    System.out.println("Bob: Key received: " + encKey + ".");

                    // Convert byte[] to SecretKey
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
                    KeySpec spec = new DESedeKeySpec(encKey);
                    this.aliceBobKey = factory.generateSecret(spec);
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | NoSuchAlgorithmException
                        | InvalidKeySpecException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Key received and processed succesfully.");

                // receive Alice's ID and verify
                System.out.println("Bob: Determining client's ID now.");
                int id = -1;
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encId = (byte[]) inStream.readObject();
                    // Decrypt key
                    encId = this.kdcCipher.doFinal(encId);
                    // Convert byte[] to int
                    id = ByteBuffer.wrap(encId).getInt();
                    if (id == this.aliceID)
                    {
                        System.out.println("Bob: Verified ID as Alice. ID deciphered: " + id);
                    }
                    else
                    {
                        System.out.println("Bob: Unknown ID. Ending communication");
                        System.exit(1);
                    }
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Ticket processed succesfully. Thank's Alice.");

                // Begin protocol with "Alice"
                System.out.println("Bob: Awaiting nonce challenge.");
                byte[] nonceOne = null;
                try
                {
                    // Decrypt nonce
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.aliceBobKey);
                    byte[] decNonce = (byte[]) inStream.readObject();
                    System.out.println("Bob: First nonce received. Encrypted nonce: " + ByteBuffer.wrap(decNonce).getLong());

                    // Decrypt key
                    decNonce = this.kdcCipher.doFinal(decNonce);
                    System.out.println("Bob: Decrypted nonce: " + decNonce);

                    // Convert byte[] to long and update
                    long updateNonce = ByteBuffer.wrap(decNonce).getLong();
                    updateNonce--;
                    System.out.println("Bob: Updated nonce: " + updateNonce);

                    // convert back to byte[]
                    decNonce = ByteBuffer.allocate(Long.BYTES)
                            .putLong(updateNonce).array();
                    nonceOne = decNonce;
                    // cbc encrypt nonce
                    cbcCipher.init(Cipher.ENCRYPT_MODE, this.aliceBobKey, iv);
                    nonceOne = cbcCipher.doFinal(nonceOne);
                    System.out.println("Bob: Encrypted nonce to send to Alice: " + ByteBuffer.wrap(nonceOne).getLong());

                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | InvalidAlgorithmParameterException e)
                {
                    System.out.println("Bob: Could not receive nonce.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }

                // Transmit response back to "Alice"
                System.out.println("Bob: Transmitting response to challenge now.");
                // Obj Out stream to send messages
                ObjectOutputStream outStream = new ObjectOutputStream(client.getOutputStream());
                outStream.writeObject(nonceOne);

                // Generate last challenge
                byte[] lastNonce = Kdc.generateNonce();
                // Encrypt nonce
                try
                {
                    System.out.println("Bob: Generated last challenge: " + ByteBuffer.wrap(lastNonce).getLong() + ".");

                    lastNonce = cbcCipher.doFinal(lastNonce);
                    System.out.println("Bob: Generated last challenge encrypted: " + ByteBuffer.wrap(lastNonce).getLong() + ".");
                }
                catch (IllegalBlockSizeException | BadPaddingException e)
                {
                    System.out.println("Bob: Failure to encrypt final nonce");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                // Transmit final challenge to "Alice"
                System.out.println("Bob: Transmitting final challenge.");
                outStream.writeObject(lastNonce);

                // Receive response to challenge from "Alice"
                System.out.println("Bob: Awaiting final response");
                System.out.println();

                // This is super hacky, should be handled by multiple threads, but works
                // Accept client 2 for Trudy to perform attack...
                Socket client2 = serverSocket.accept();
                System.out.println();
                System.out.println("Session 2:");
                System.out.println("Bob: Client received. Ready to receive KDC ticket");
                // Requires a second IV for a new session
                IvParameterSpec iv2 = Kdc.generateIV();
                System.out.println("Bob: IV generated for encryption: " + iv2);

                // Initialize obj's for communication
                ObjectInputStream inStream2 = new ObjectInputStream(client2.getInputStream());
                System.out.println("Bob: Awaiting initial nonce.");

                // receive shared key
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encKey = (byte[]) inStream2.readObject();
                    // Decrypt key
                    encKey = this.kdcCipher.doFinal(encKey);
                    // Convert byte[] to SecretKey
                    SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
                    KeySpec spec = new DESedeKeySpec(encKey);
                    this.aliceBobKey = factory.generateSecret(spec);
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | NoSuchAlgorithmException
                        | InvalidKeySpecException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Key received and processed succesfully.");

                // receive Alice's ID and verify
                System.out.println("Bob: Determining client's ID now.");
                int id2 = -1;
                try
                {
                    // Set cipher to decrypt using init kdc key
                    this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                    byte[] encId = (byte[]) inStream2.readObject();
                    // Decrypt key
                    encId = this.kdcCipher.doFinal(encId);
                    // Convert byte[] to int
                    id2 = ByteBuffer.wrap(encId).getInt();
                    if (id2 == this.aliceID)
                    {
                        System.out.println("Bob: Verified ID as Alice. ID deciphered: " + id);
                    }
                    else
                    {
                        System.out.println("Bob: Unknown ID. Ending communication");
                        System.exit(1);
                    }
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException e)
                {
                    System.out.println("Bob: Could not receive key.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.println("Bob: Ticket processed succesfully. Thank's Alice.");

                // Begin protocol with "Alice"
                System.out.println("Bob: Awaiting nonce challenge.");
                byte[] nonceOne2 = null;
                try
                {
                    
                    // Decrypt nonce
                    cbcCipher.init(Cipher.DECRYPT_MODE, aliceBobKey, iv);
                    byte[] decNonce = (byte[]) inStream2.readObject();
                    System.out.println("Bob: First nonce received. Encrypted nonce: " + ByteBuffer.wrap(decNonce).getLong());

                    // Decrypt key
                    decNonce = cbcCipher.doFinal(decNonce);
                    System.out.println("Bob: Decrypted nonce: " + ByteBuffer.wrap(decNonce).getLong());

                    // Convert byte[] to long and update
                    long updateNonce = ByteBuffer.wrap(decNonce).getLong();
                    updateNonce--;
                    System.out.println("Bob: Updated nonce: " + updateNonce);

                    // convert back to byte[]
                    decNonce = ByteBuffer.allocate(Long.BYTES)
                            .putLong(updateNonce).array();
                    nonceOne2 = decNonce;

                    // cbc encrypt nonceOne

                    cbcCipher.init(Cipher.ENCRYPT_MODE, this.aliceBobKey, iv2);
                    nonceOne2 = cbcCipher.doFinal(nonceOne2);
                    System.out.println("Bob: Encrypted nonce to send to Alice: " + ByteBuffer.wrap(nonceOne2).getLong());

                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | InvalidAlgorithmParameterException e)
                {
                    System.out.println("Bob: Could not receive nonce.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }

                // Transmit response back to "Alice"
                System.out.println("Bob: Transmitting response to challenge now.");
                // Obj Out stream to send messages
                ObjectOutputStream outStream2 = new ObjectOutputStream(client2.getOutputStream());
                outStream2.writeObject(nonceOne2);
                System.out.println();
                System.out.println("Session 1:");

                byte[] lastEncNonce = null;
                try
                {
                    lastEncNonce = (byte[]) inStream.readObject();
                    // decrypt challenge
                    cbcCipher.init(Cipher.DECRYPT_MODE, aliceBobKey, iv);
                    System.out.println("Bob: Encrypted nonce received: " + ByteBuffer.wrap(lastEncNonce).getLong());

                    lastNonce = cbcCipher.doFinal(lastNonce);
                    // decrypt response
                    lastEncNonce = cbcCipher.doFinal(lastEncNonce);
                    System.out.println("Bob: Decrypted nonce: " + ByteBuffer.wrap(lastEncNonce).getLong());

                    // Validate received nonce with generated challenge
                    if (ByteBuffer.wrap(lastNonce).getLong() - 1 == ByteBuffer
                            .wrap(lastEncNonce).getLong())
                    {
                        System.out.println("Bob: Nonce validated.");
                    }
                    else
                    {
                        System.out.println(
                                "Bob: Challenge failed. You are not Alice! Aborting communication.");
                        System.out.println("Bob: Encrypted nonce received: " + ByteBuffer.wrap(lastEncNonce).getLong() + " Nonce expected: " + (ByteBuffer.wrap(lastNonce).getLong() - 1));
                        System.exit(1);

                    }
                }
                catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                        | BadPaddingException | InvalidAlgorithmParameterException e)
                {
                    System.out.println(
                            "Bob: Failure to receive final challenge. Terminating session.");
                    LOGGER.log(java.util.logging.Level.SEVERE, null, e);
                }
                System.out.print("Bob: Alice has been authenticated. Protocol complete.");

                // Report protocol is completed
                System.out.println("Bob: Ending communication with Alice.");
                System.out.println();
                openSocket = false;
                client.close();
                client2.close();
                openSocket = false;
            }
            serverSocket.close();
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

    public static void main(String[] args)
    {
        System.out.println("Extended Needham Schroeder Mediated-Authentication Scheme");
        Bob bob = new Bob();
        bob.extendedNHS();
        System.out.println();
        bob.ecbTrudy();
        bob.cbcTrudy();
    }
}