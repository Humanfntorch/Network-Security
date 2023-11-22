import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
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

/*
 * Client side 'Alice' used to communicate with the server KDC, and
 * Bob in NHS protocol.
 */ 
public class Alice
{
    // Logger for error handling
    private static final Logger LOGGER = Logger.getLogger(Alice.class.getName());
    // Symmetric key for KDC
    private SecretKey myKdcKey;
    // Symmetric key for Bob
    private SecretKey aliceBobKey;
    // the recipient Alice wants to contact
    // Cipher used in encrypting/decrypting messages to KDC and Bob
    private Cipher kdcCipher;

    // Alices unique ID for verification with KDC
    private final int aliceID = 02;
    // RSA key pair to transmit Alice's 3DES key to KDC.
    private PrivateKey privateRSAKey;
    private PublicKey publicRSAKey;

    // port to connect to KDC
    private final int kdcPort = 8080;
    // port to connect to Bob
    private final int bobPort = 9020;
    // port to connect to Bob for reflection attack
    private final int bobPortReflection = 8000;


    // Bob's initially sent nonce
    byte[] bobsNonce;
    // Bob's encrypted shared key
    byte[] bobsSecretKey;
    // Bob's encrypted Alice ID
    byte[] bobEncAliceID;

    // Trudy's 1st intercepted message
    byte[] ecbNonceOne;
    // Trudy's 1st intercepted message in hex
    String ecbNonceOneHex;
    // Trudy's 2nd intercepted message
    byte[] ecbNonceTwo;
    // Trudy's 2nd intercepted message in hex
    String ecbNonceTwoHex;


    // Trudy's 1st intercepted message in hex
    String cbcNonceOneHex;
    // Trudy's 2nd intercepted message in hex
    String cbcNonceTwoHex;


    /*
     * Constructor for Alice. Initializes a symmetric key to be used with the KDC. Keys are
     * generated using Java.security package with the RSA algorithm and a key size of 2048 bits
     */
    public Alice()
    {

        // Generate Alice's public/private RSA key pair
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
            System.out.println("Alice: RSA Key Generation failed.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }

        // Generate Alice's 3DES key
        this.myKdcKey = null;
        try
        {
            KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
            this.myKdcKey = keyGen.generateKey();
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("Alice: symmetric key generation failed.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }

        try
        {
            this.kdcCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        }
        catch (NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            System.out.println("Alice: Error generating KDC cipher obj");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
    }

    public void kdcTransmit(byte[] bobsCipher)
    {
        try
        {
            InetAddress host = InetAddress.getByName("localhost");
            // Connect Alice to the KDC server
            Socket kdcSocket = new Socket(host, this.kdcPort);
            System.out.println("Alice: I've connected to KDC.");

            // Allows Alice to transmit key to KDC
            ObjectOutputStream kdcOutStream = new ObjectOutputStream(kdcSocket.getOutputStream());
            // Transmit key to kdc

            System.out.println("Alice: Transmitting RSA key to KDC now.");
            kdcOutStream.writeObject(this.publicRSAKey);
            kdcOutStream.flush();
            System.out.println("Alice: RSA key transmitted. Sending encrypted ID now.");

            Cipher encryptCipher = null;
            try
            {
                // Encrypt id and transmit to kdc
                encryptCipher = Cipher.getInstance("RSA");
                encryptCipher.init(Cipher.ENCRYPT_MODE, this.privateRSAKey);
                byte[] encryptedID = encryptCipher.doFinal(ByteBuffer.allocate(4)
                        .putInt(this.aliceID).array());
                System.out.println("Alice: Transmitting unique KDC ID: " + this.aliceID + " with encrypted form: " + encryptedID + ".");
                kdcOutStream.writeObject(encryptedID);
                kdcOutStream.flush();

                // KDC now read to accept encrypted 3DES Key
                System.out.println("Alice: Great, ID was accepted by KDC. Transmitting 3DES key now.");
                // enc key
                byte[] encEdesKey =
                        encryptCipher.doFinal(this.myKdcKey.getEncoded());
                System.out.println("Alice: Encrypted key sent to KDC: " + encEdesKey);

                // Transmit to kdc
                kdcOutStream.writeObject(encEdesKey);
                kdcOutStream.flush();

            }
            catch (InvalidKeyException | NoSuchAlgorithmException
                    | NoSuchPaddingException | IllegalBlockSizeException
                    | BadPaddingException e)
            {
                System.out.println(
                        "Alice: Error transmitting encrypted ID and 3DES key to KDC.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            System.out.println("Alice: Continuing NHS protocol now.");
            // Generate nonce to confirm kdc
            byte[] nonce = Kdc.generateNonce();
            System.out.println(
                    "Alice: Transmitting nonce: " + ByteBuffer.wrap(nonce).getLong() + " to KDC.");
            try
            {
                this.kdcCipher.init(Cipher.ENCRYPT_MODE, this.myKdcKey);
                nonce = this.kdcCipher.doFinal(nonce);
            }
            catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
            {
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }
            System.out.println("Alice: Encrypted form of nonce: " + nonce);


            System.out.println("Alice: Sending nonce to KDC.");
            kdcOutStream.writeObject(nonce);
            kdcOutStream.flush();

            // Transmit Bob's encrypted nonce
            System.out.println("Alice: Sending Bob's encrypted nonce to KDC: " + bobsCipher + ".");
            kdcOutStream.writeObject(bobsCipher);
            kdcOutStream.flush();

            // Obtain Alice's encrypted messages from KDC
            ObjectInputStream inStream = new ObjectInputStream(kdcSocket.getInputStream());
            try
            {
                // Alice's nonce
                byte[] encNonce = (byte[]) inStream.readObject();
                // Decrypt cipher using Alice's key
                this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                byte[] kdcNonce = this.kdcCipher.doFinal(encNonce);
                nonce = this.kdcCipher.doFinal(nonce);

                // Verify KDC idenitity through nonce comparison
                if (!Arrays.equals(nonce, kdcNonce))
                {
                    System.out.println("Alice: This isn't KDC! Abort!!!!");
                }
                else
                {
                    System.out.println(
                            "Alice: KDC was authenticated with nonce received:" + ByteBuffer.wrap(kdcNonce).getLong() + ". Awaiting further data transmission from KDC.");
                }

                // Alice/Bob key
                byte[] encKey = (byte[]) inStream.readObject();
                // Decrypt cipher using Alice's key
                encKey = this.kdcCipher.doFinal(encKey);

                // Convert byte[] to SecretKey
                SecretKeyFactory factory = SecretKeyFactory.getInstance("DESede");
                KeySpec spec = new DESedeKeySpec(encKey);
                this.aliceBobKey = factory.generateSecret(spec);
                System.out.println("Alice: 3DES key was received from KDC: " + this.aliceBobKey + ". Awaiting Bob's ticket");

                // Receive Bob's Nonce
                byte[] encBobNonce = (byte[]) inStream.readObject();
                // Decrypt cipher using Alice's key
                this.kdcCipher.init(Cipher.DECRYPT_MODE, this.myKdcKey);
                this.bobsNonce = this.kdcCipher.doFinal(encBobNonce);
                System.out.println("Alice: Bob's nonce received from KDC: " + this.bobsNonce + ".");


                // Receive Bob's secret key
                byte[] bobEncKey = (byte[]) inStream.readObject();
                // Decrypt cipher using Alice's key
                this.bobsSecretKey = this.kdcCipher.doFinal(bobEncKey);
                System.out.println("Alice: Bob's key received from KDC: " + this.bobsSecretKey + ".");


                // Receive Bob's encrypted Alice ID
                byte[] bobEncAliceID = (byte[]) inStream.readObject();
                // Decrypt cipher using Alice's key
                this.bobEncAliceID = this.kdcCipher.doFinal(bobEncAliceID);
                System.out.println("Alice: Bob's encrypted version of my id received from KDC: " + this.bobEncAliceID + ".");


                // Transmit confirmation to KDC then end kdc init protocol
                kdcOutStream.writeObject("Alice: Bob's ticket was received. Thank you KDC!");
                System.out.println("Alice: Bob's ticket was received. Thank you KDC!");
                System.out.println("Alice: Ending communication with KDC.");
                System.out.println();

                // Close all open streams
                kdcOutStream.flush();
                kdcOutStream.close();
                inStream.close();
                kdcSocket.close();
            }
            catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                    | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException e)
            {
                System.out.println("Alice: Cipher message could not be received.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }
        }
        catch (UnknownHostException ex)
        {
            System.out.println("Alice: Could not connect to KDC.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, ex);
        }
        catch (IOException e)
        {
            System.out.println("Alice: Could not connect to KDC.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
    }

    public void extendedNHS()
    {
        // Connect to Bob
        try
        {
            InetAddress host = InetAddress.getByName("localhost");
            // Connect Alice to the KDC server
            Socket bobSocket = new Socket(host, this.bobPort);
            System.out.println("Alice: Hey Bob!");
            System.out.println("Alice: Okay, Bob, connecting with KDC now.");

            // in/out streams for communication with Bob
            ObjectInputStream inStream =
                    new ObjectInputStream(bobSocket.getInputStream());
            ObjectOutputStream outStream =
                    new ObjectOutputStream(bobSocket.getOutputStream());
            // Receive nonce from Bob, initiate kdc protocol
            try
            {
                byte[] bobsNonce = (byte[]) inStream.readObject();
                System.out.println("Alice: Nonce received from Bob: " + ByteBuffer.wrap(bobsNonce).getLong() + ".");
                kdcTransmit(bobsNonce);
            }
            catch (ClassNotFoundException e)
            {
                System.out.println("Alice: Failed to receive Bob's nonce!");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            // Send Bob ticket received from KDC
            System.out.println("Alice: KDC protocol finished succesfully.");
            System.out.println("Alice: Transmitting Bob's ticket now.");

            // Transmit nonce first
            outStream.writeObject(this.bobsNonce);
            outStream.flush();
            // Transmit key next
            outStream.writeObject(this.bobsSecretKey);
            outStream.flush();
            System.out.println("Alice: Bob's ticket has been sent");


            // Generate nonce challenge to Bob
            byte[] initNonce = Kdc.generateNonce();
            // enc nonce
            try
            {
                System.out.println("Alice: Sending nonce challenge to Bob. Nonce generated: " + ByteBuffer.wrap(initNonce).getLong());
                this.kdcCipher.init(Cipher.ENCRYPT_MODE, this.aliceBobKey);
                initNonce = this.kdcCipher.doFinal(initNonce);
                System.out.println("Alice: Encrypted nonce: " + ByteBuffer.wrap(initNonce).getLong());

                // Trudy intercepts fist nonce from Alice
                this.ecbNonceOne = initNonce;
            }
            catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
            {
                System.out.println("Alice: Failed to encrypt nonce one to Bob");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }
            outStream.writeObject(initNonce);
            System.out.println("Alice: Submitting Nonce challenge to Bob now.");

            // Receive challenge back from Bob
            try
            {
                // Decrypt nonce for comparison
                this.kdcCipher.init(Cipher.DECRYPT_MODE, this.aliceBobKey);
                initNonce = this.kdcCipher.doFinal(initNonce);
                // Receive nonce from Bob
                byte[] receivedNonce = (byte[]) inStream.readObject();

                // Trudy must intercept the second message in the protocol.
                this.ecbNonceTwo = receivedNonce;
                // decrypt received nonce
                receivedNonce = this.kdcCipher.doFinal(receivedNonce);

                // Validate Bob
                if (ByteBuffer.wrap(initNonce).getLong() - 1 == ByteBuffer.wrap(receivedNonce)
                        .getLong())
                {
                    System.out.println("Alice: Received nonce was valid. Nonce received from Bob: " + ByteBuffer.wrap(receivedNonce).getLong());
                }
                else
                {
                    System.out.println("Alice: Challenge failed. terminating");
                }
            }
            catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                    | BadPaddingException e)
            {
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            // Receive last nonce from Bob
            System.out.println("Alice: Ready to accept final nonce.");
            byte[] thirdNonce = null;
            try
            {
                thirdNonce = (byte[]) inStream.readObject();
            }
            catch (ClassNotFoundException e)
            {
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            // Decrypt, update, encrypt third nonce
            System.out.println("Alice: Received final nonce. Beginning last protocol exchange.");
            try
            {
                System.out.println("Alice: Encrypted third nonce: " + ByteBuffer.wrap(thirdNonce).getLong());
                this.kdcCipher.init(Cipher.DECRYPT_MODE, aliceBobKey);
                thirdNonce = this.kdcCipher.doFinal(thirdNonce);
                // convert nonce to long, then subtract 1 off
                long updateNonce = ByteBuffer.wrap(thirdNonce).getLong();
                updateNonce--;
                System.out.println("Alice: Updated third nonce: " + updateNonce);
                // convert back to byte[]
                thirdNonce = ByteBuffer.allocate(Long.BYTES)
                        .putLong(updateNonce).array();
                // encrypt it
                this.kdcCipher.init(Cipher.ENCRYPT_MODE, aliceBobKey);
                thirdNonce = this.kdcCipher.doFinal(thirdNonce);
            }
            catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e)
            {
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }
            // Transmit nonce back to Bob
            System.out.println("Alice: Transmitting updated nonce now.");
            outStream.writeObject(thirdNonce);

            // Protocol complete. report and end communication
            System.out.println("Alice: Bob has been authenticated. Protocol complete.");
            System.out.println("Alice: Ending communication with Bob.");
            System.out.println();
            bobSocket.close();
        }
        catch (UnknownHostException ex)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, ex);
        }
        catch (IOException e)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
        // pause thread for Bob to reset and call Trudy/setup server first
        try
        {
            Thread.sleep(500);
        }
        catch (InterruptedException e)
        {
            System.out.println("Alice: Error sleeping.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
    }

    /*
     * Method details the reflection attack created by Trudy, who is understood to have intercepted
     * the final three message in the original NHS protocol, and mysteriously has access to Bob's
     * ticket, which allows her to accomplish the reflection attack. Protocol is assumed to begin
     * after the exchange between Alice/KDC and Alice/Bob and that the primary protocol is the
     * standard (original) NHS, rather than the extended version
     */
    private void ecbTrudy()
    {
        System.out.println("Original Needham Schroeder Successful Reflection Attack");

        // Connect to Bob
        try
        {
            System.out.println("Tudy: Beginning session 1 with Bob. ");
            InetAddress host = InetAddress.getByName("localhost");
            // Connect Trudy to the KDC server
            Socket bobSocket1 = new Socket(host, this.bobPortReflection);
            System.out.println("Trudy: Hey Bob, it's Alice!");
            System.out.println("Trudy: Ready to receive the KDC ticket?");

            // Initialize obj's for communication
            ObjectOutputStream outStream = new ObjectOutputStream(bobSocket1.getOutputStream());

            // Trudy sends Bob's ticket
            System.out.println("Trudy: Sending KDC ticket now.");
            // Send Bob's shared 3DES key
            outStream.writeObject(this.bobsSecretKey);
            outStream.flush();
            // send Bob's enc version of Alice's ID
            outStream.writeObject(this.bobEncAliceID);
            outStream.flush();

            System.out.println(
                    "Trudy: Ticket has been sent. Beginning attack now, with first message.");

            // Transmit first message to Bob
            outStream.writeObject(this.ecbNonceOne);
            System.out.println("Trudy: Challenge has been sent. Challenge: " + ByteBuffer.wrap(this.ecbNonceOne).getLong() + " Awaiting response...");
            // Receive Bob's response to message one
            byte[] nonceOneAnswr = null;
            // obj for reading in data
            ObjectInputStream inStream = new ObjectInputStream(bobSocket1.getInputStream());
            try
            {
                nonceOneAnswr = (byte[]) inStream.readObject();
                System.out.println("Trudy: Response to first challenge received: " + ByteBuffer.wrap(nonceOneAnswr).getLong());
                // save hex of responce for ecb/cbc comparison
                this.ecbNonceOneHex = new BigInteger(1, nonceOneAnswr).toString(16);
            }
            catch (ClassNotFoundException e)
            {
                System.out.println("Trudy: Failed to receive Response to message 1.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            // Receive second Bob's challenge
            System.out.println("Trudy: Awaiting final challenge...");
            byte[] bobsChallenge = null;
            try
            {
                bobsChallenge = (byte[]) inStream.readObject();
                System.out.println("Trudy: Bob's challenge received: " + ByteBuffer.wrap(bobsChallenge).getLong());

            }
            catch (ClassNotFoundException e)
            {
                System.out.println("Trudy: Failed to receive Response to message 1.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }
            // Lie
            System.out.println("Trudy: Challenge received. Performing update now.");

            // Second Session
            // Open second socket and connect to Bob.
            System.out.println();
            System.out.println("Tudy: Beginning session 2 with Bob. ");
            // Connect Trudy to Bob

            Socket bobSocket2 = new Socket(host, this.bobPortReflection);
            System.out.println("Trudy: Hey Bob, it's Alice!");
            System.out.println("Trudy: Ready to receive the KDC ticket?");

            // Initialize obj's for communication
            ObjectOutputStream outStream2 = new ObjectOutputStream(bobSocket2.getOutputStream());

            // Trudy sends Bob's ticket
            System.out.println("Trudy: Sending KDC ticket now.");
            // Send Bob's shared 3DES key
            outStream2.writeObject(this.bobsSecretKey);
            // send Bob's enc version of Alice's ID
            outStream2.writeObject(this.bobEncAliceID);

            System.out.println(
                    "Trudy: Ticket has been sent. Beginning attack now, with first message: " + ByteBuffer.wrap(bobsChallenge).getLong());

            // Transmit the response generated by Bob in session 1
            outStream2.writeObject(bobsChallenge);
            System.out.println("Trudy: Challenge has been sent. Awaiting response...");

            // Receive Bob's response to Bob's challenge. Lol
            byte[] bobsAnswer = null;
            // obj for reading in data
            ObjectInputStream inStream2 = new ObjectInputStream(bobSocket2.getInputStream());
            try
            {
                bobsAnswer = (byte[]) inStream2.readObject();
                System.out.println("Trudy: Bob's response to Bob's challenge: " + ByteBuffer.wrap(bobsChallenge).getLong());
            }
            catch (ClassNotFoundException e)
            {
                System.out.println("Trudy: Failed to receive Response to message 1.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            System.out.println(
                    "Trudy: I got Bob's answer to Bob's challenge, from Bob! Hahaha, sucker!");
            System.out.println();
            System.out.println("Session 1:");

            // Send Bob, Bob's response
            System.out.println("Trudy: Transmitting response to challenge now: " + ByteBuffer.wrap(bobsAnswer).getLong());
            outStream.writeObject(bobsAnswer);
            outStream.flush();

            // save last message as hex for ecb cbc comparison
            this.ecbNonceTwoHex = new BigInteger(1, bobsAnswer).toString(16);

            // Report final response and close streams/socket
            System.out.println("Trudy: Thanks Bob. It was pleasure doin' business with ya.");
            System.out.println("Trudy: Ending transmission with Bob.");
            System.out.println();
            inStream.close();
            outStream.close();
            bobSocket1.close();
            // Close streams and second socket
            inStream2.close();
            outStream2.close();
            bobSocket2.close();
        }
        catch (UnknownHostException ex)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, ex);
        }
        catch (IOException e)
        {
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
        // pause thread for Bob to reset and call Trudy/setup server first
        try
        {
            Thread.sleep(500);
        }
        catch (InterruptedException e)
        {
            System.out.println("Alice: Error sleeping.");
            LOGGER.log(java.util.logging.Level.SEVERE, null, e);
        }
    }

    /*
     * Method details the reflection attack created by Trudy, who is understood to have intercepted
     * the final three message in the original NHS protocol, and mysteriously has access to Bob's
     * ticket, which allows her to accomplish the reflection attack. Protocol is assumed to begin
     * after the exchange between Alice/KDC and Alice/Bob and that the primary protocol is the
     * standard (original) NHS, rather than the extended version
     */
    private void cbcTrudy()
    {
        System.out.println("Original Needham Schroeder Failed Reflection Attack");

        // Connect to Bob
        try
        {
            System.out.println("Tudy: Beginning session 1 with Bob. ");
            InetAddress host = InetAddress.getByName("localhost");
            // Connect Trudy to the KDC server
            Socket bobSocket1 = new Socket(host, this.bobPortReflection);
            System.out.println("Trudy: Hey Bob, it's Alice!");
            System.out.println("Trudy: Ready to receive the KDC ticket?");

            // Initialize obj's for communication
            ObjectOutputStream outStream = new ObjectOutputStream(bobSocket1.getOutputStream());

            // Trudy sends Bob's ticket
            System.out.println("Trudy: Sending KDC ticket now.");
            // Send Bob's shared 3DES key
            outStream.writeObject(this.bobsSecretKey);
            outStream.flush();
            // send Bob's enc version of Alice's ID
            outStream.writeObject(this.bobEncAliceID);
            outStream.flush();

            System.out.println(
                    "Trudy: Ticket has been sent. Beginning attack now, with first message: " + ByteBuffer.wrap(this.ecbNonceOne));

            // Transmit first message to Bob
            outStream.writeObject(this.ecbNonceOne);
            System.out.println("Trudy: Challenge has been sent. Awaiting response...");
            // Receive Bob's response to message one
            byte[] nonceOneAnswr = null;
            // obj for reading in data
            ObjectInputStream inStream = new ObjectInputStream(bobSocket1.getInputStream());
            try
            {
                nonceOneAnswr = (byte[]) inStream.readObject();
                System.out.println("Trudy: Response received: " + nonceOneAnswr);

                // save hex of first ecb response for cbc/ecb comparison
                this.cbcNonceOneHex = new BigInteger(1, nonceOneAnswr).toString(16);
            }
            catch (ClassNotFoundException e)
            {
                System.out.println("Trudy: Failed to receive Response to message 1.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            // Receive second Bob's challenge
            System.out.println("Trudy: Awaiting final challenge...");
            byte[] bobsChallenge = null;
            try
            {
                bobsChallenge = (byte[]) inStream.readObject();
                System.out.println("Trudy: Challenge received: " + bobsChallenge);

            }
            catch (ClassNotFoundException e)
            {
                System.out.println("Trudy: Failed to receive Response to message 1.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }
            // Lie
            System.out.println("Trudy: Challenge received. Performing update now.");

            // Second Session

            // Open second socket and connect to Bob.
            System.out.println();
            System.out.println("Tudy: Beginning session 2 with Bob. ");
            // Connect Trudy to Bob

            Socket bobSocket2 = new Socket(host, this.bobPortReflection);
            System.out.println("Trudy: Hey Bob, it's Alice!");
            System.out.println("Trudy: Ready to receive the KDC ticket?");

            // Initialize obj's for communication
            ObjectOutputStream outStream2 = new ObjectOutputStream(bobSocket2.getOutputStream());

            // Trudy sends Bob's ticket
            System.out.println("Trudy: Sending KDC ticket now.");
            // Send Bob's shared 3DES key
            outStream2.writeObject(this.bobsSecretKey);
            // send Bob's enc version of Alice's ID
            outStream2.writeObject(this.bobEncAliceID);

            System.out.println(
                    "Trudy: Ticket has been sent. Beginning attack now, with first message: " + bobsChallenge);

            // Transmit the response generated by Bob in session 1
            outStream2.writeObject(bobsChallenge);
            System.out.println("Trudy: Challenge has been sent. Awaiting response...");

            // Receive Bob's response to Bob's challenge. Lol
            byte[] bobsAnswer = null;
            // obj for reading in data
            ObjectInputStream inStream2 = new ObjectInputStream(bobSocket2.getInputStream());
            try
            {
                bobsAnswer = (byte[]) inStream2.readObject();
                System.out.println("Trudy: Response received: " + ByteBuffer.wrap(bobsAnswer).getLong());

            }
            catch (ClassNotFoundException e)
            {
                System.out.println("Trudy: Failed to receive Response to message 1.");
                LOGGER.log(java.util.logging.Level.SEVERE, null, e);
            }

            // Close streams and second socket
            inStream2.close();
            outStream2.close();
            bobSocket2.close();
            System.out.println(
                    "Trudy: I got Bob's answer to Bob's challenge, from Bob! Hahaha, sucker!");
            System.out.println();
            System.out.println("Session 1:");

            // Send Bob, Bob's response
            System.out.println("Trudy: Transmitting response to challenge now: " + ByteBuffer.wrap(bobsAnswer).getLong());
            outStream.writeObject(bobsAnswer);
            // save hex of second message for ecb/cbc comparison
            this.cbcNonceTwoHex = new BigInteger(1, bobsAnswer).toString(16);

            // Report final response and close streams/socket
            System.out.println("Trudy: Thanks Bob. It was pleasure doin' business with ya.");
            System.out.println("Trudy: Ending transmission with Bob.");
            inStream.close();
            outStream.close();
            bobSocket1.close();
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
        Alice alice = new Alice();
        alice.extendedNHS();
        System.out.println();
        // Call trudy for reflection attack
        alice.ecbTrudy();
        alice.cbcTrudy();
        System.out.println();
        System.out.println("ECB Message One hex value: " + alice.ecbNonceOneHex);
        System.out.println("ECB Message Two hex value: " + alice.ecbNonceTwoHex);
        System.out.println("CBC Message One hex value: " + alice.cbcNonceOneHex);
        System.out.println("CBC Message Two hex value: " + alice.cbcNonceTwoHex);
    }
}