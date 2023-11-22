import java.net.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
/*
 * Key Distributed Center
 */
public class Kdc
{
    // Logger for error handling
    private static final Logger LOGGER = Logger.getLogger(Kdc.class.getName());
    // Unique IDs to verify Alice and Bob
    private final int aliceID = 02;
    private final int bobID = 01;
    // Maintains the public keys for Alice and Bob (sent to KDC)
    private Map<Integer, SecretKey> secretKeys;
    // Cipher object for encryption/decryption
    private Cipher cipher;

    /*
     * Constructor for initializing Kdc member fields
     */
    public Kdc()
    {
        this.secretKeys = new HashMap<Integer, SecretKey>();
        // Cipher object used for 3DES Enc/Dec
        try
        {
            this.cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println("KDC failed to generate cipher obj. System aborted.");
            LOGGER.log(Level.SEVERE, "KDC failed to generate cipher obj. System aborted", e);
        }
        catch (NoSuchPaddingException e)
        {
            System.out.println("KDC failed to generate cipher obj. System aborted.");
            LOGGER.log(Level.SEVERE, "KDC failed to generate cipher obj. System aborted.", e);
        }
    }

    public static byte[] generateNonce()
    {
        // Transmit a nonce challenge to kdc
        SecureRandom random = new SecureRandom();
        // 8 bits in 1 byte, therefore 8 bytes = 64 bit challenge
        byte[] nonce = new byte[8];
        random.nextBytes(nonce);
        return nonce;
    }

    public static IvParameterSpec generateIV()
    {
        // Transmit a nonce challenge to kdc
        SecureRandom random = new SecureRandom();
        // 8 bits in 1 byte, therefore 8 bytes = 64 bit challenge
        byte[] nonce = new byte[8];
        random.nextBytes(nonce);
        return new IvParameterSpec(nonce);
    }

    public void runExtended()
    {
        try
        {
            // Initialize server socket
            int serverPort = 8080;
            ServerSocket serverSocket = new ServerSocket(serverPort);
            // Indicates when a client is still communicating with server
            boolean openSocket = true;

            while (openSocket)
            {
                System.out.println("KDC: Waiting for connection...");
                // Accept in client and report to console
                Socket client = serverSocket.accept();
                System.out.println(
                        "KDC: Connection established. What is the public RSA key and user's encrypted ID?");
                ObjectInputStream inStream = new ObjectInputStream(client.getInputStream());

                // Receive key
                PublicKey key = null;
                try
                {
                    key = (PublicKey) inStream.readObject();
                }
                catch (ClassNotFoundException e)
                {
                    System.out.print("KDC: RSA key could not be processed. System aborted");

                }

                // Stores client's enc id. Requires default initialization
                byte[] encryptedID = null;
                // plain id
                int id = -1;
                // Decrypting RSA cipher
                Cipher decryptCipher = null;

                // Receive id, confirm usr
                try
                {
                    decryptCipher = Cipher.getInstance("RSA");
                    decryptCipher.init(Cipher.DECRYPT_MODE, key);
                    encryptedID = (byte[]) inStream.readObject();
                    // Optimistically assume it's valid, decrypt it with key (non-null)
                    if (key != null)
                    {
                        encryptedID = decryptCipher.doFinal(encryptedID);
                        // Convert id back to int
                        id = ByteBuffer.wrap(encryptedID).getInt();
                    }
                }
                catch (ClassNotFoundException | IllegalBlockSizeException
                        | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException
                        | NoSuchPaddingException e)
                {
                    System.out
                            .println("KDC: ID could not decrypted with given key. System aborted");
                    LOGGER.log(Level.SEVERE, "KDC: ID could not decrypted with given key. System aborted", e);
                }

                // If Bob, receive 3DES key and end communication
                if (id == this.bobID)
                {
                    System.out.println("KDC: Bob's ID was verified with ID = " + id + " and awaiting 3DES key.");
                    byte[] encKey = (byte[]) inStream.readObject();
                    try
                    {
                        byte[] decKey = decryptCipher.doFinal(encKey);
                        // Convert key back to secret key
                        SecretKey bobsKey = new SecretKeySpec(decKey, "DESede");
                        System.out.println("KDC: Bob's 3DES key received as: " + decKey);

                        // store Bobs key in map
                        secretKeys.put(this.bobID, bobsKey);
                    }
                    catch (IllegalBlockSizeException | BadPaddingException e)
                    {
                        System.out.println("KDC: Error obtaining Bob's 3DES key");
                        LOGGER.log(Level.SEVERE,"KDC: Error obtaining Bob's 3DES key", e);
                    }

                    System.out.println("KDC: Bob's 3DES key has been accepted.");
                    System.out.println("KDC: Ending communication with Bob.");
                    client.close();
                }
                // If Alice, continue protocol.
                else if (id == this.aliceID)
                {
                    // Obtain Alice's 3DES key
                    System.out.println("KDC: Alice's ID was verified as ID = " + id + " and awaiting 3DES key.");
                    byte[] encKey = (byte[]) inStream.readObject();
                    try
                    {
                        byte[] decKey = decryptCipher.doFinal(encKey);
                        // Convert key back to secret key
                        SecretKey alicesKey = new SecretKeySpec(decKey, "DESede");
                        System.out.println("KDC: Alice's 3DES key received as: " + decKey);

                        // store Bobs key in map
                        secretKeys.put(this.aliceID, alicesKey);
                    }
                    catch (IllegalBlockSizeException | BadPaddingException e)
                    {
                        System.out.println("KDC: Error obtaining Alice's 3DES key");
                        
                    }
                    System.out.println("KDC: Alice's 3DES key has been accepted.");

                    // Continue with NHS protocol
                    System.out.println(
                            "KDC: Alice may proceed with protocol. Awaiting nonce challenge.");

                    // accept her challenge
                    byte[] nonceAlice = null;
                    try
                    {
                        nonceAlice = (byte[]) inStream.readObject();
                        // decrypt Alice's nonce
                        this.cipher.init(Cipher.DECRYPT_MODE, this.secretKeys.get(this.aliceID));
                        nonceAlice = this.cipher.doFinal(nonceAlice);
                        System.out.println("KDC: Alice challenge received. Nonce: " + ByteBuffer.wrap(nonceAlice).getLong());
                        // encrypt alice's nonce with shared kdc key
                        this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKeys.get(this.aliceID));
                        nonceAlice = this.cipher.doFinal(nonceAlice);
                        System.out.println("KDC: Alice's challenge was received.");
                    }
                    catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                            | BadPaddingException e)
                    {
                        System.out.print("KDC: Alice's Nonce was not found. System aborted.");
                        LOGGER.log(Level.SEVERE,"KDC: Alice's Nonce was not found. System aborted.", e);
                    }

                    SecretKey keyAB = null;
                    byte[] aliceKeyAB = null;
                    // Generate a key shared between Alice and Bob
                    try
                    {
                        KeyGenerator keyGen = KeyGenerator.getInstance("DESede");
                        keyAB = keyGen.generateKey();
                        // Encrypt key with Alice's shared KDC key
                        this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKeys.get(this.aliceID));
                        aliceKeyAB = this.cipher.doFinal(keyAB.getEncoded());
                    }
                    catch (NoSuchAlgorithmException | IllegalBlockSizeException
                            | BadPaddingException | InvalidKeyException e)
                    {
                        System.out.println("KDC: Alice's symmetric key generation failed.");
                        LOGGER.log(Level.SEVERE,"KDC: Alice's symmetric key generation failed.", e);
                    }

                    // Transmit Alice's message
                    // Create object output stream to transmit msg
                    ObjectOutputStream outStream =
                            new ObjectOutputStream(client.getOutputStream());

                    // Trasmit encrypted message to Alice
                    System.out.println("KDC: Transmitting Alice's encrypted ticket.");
                    outStream.writeObject(nonceAlice);
                    outStream.flush();
                    outStream.writeObject(aliceKeyAB);
                    outStream.flush();

                    // Extract Bob's nonce
                    byte[] cipherBob = null;
                    byte[] nonceBob = null;
                    System.out.println(
                            "KDC: Attempting to verify valid communication between Alice and Bob.");
                    try
                    {
                        cipherBob = (byte[]) inStream.readObject();
                        // Attempt to decrypt Bob's nonce
                        this.cipher.init(Cipher.DECRYPT_MODE, secretKeys.get(this.bobID));
                        nonceBob = this.cipher.doFinal(cipherBob);
                        System.out.println(
                                "KDC: Verified initial communication between Alice and Bob. Bob's nonce: " + ByteBuffer.wrap(nonceBob).getLong());
                    }
                    catch (ClassNotFoundException | InvalidKeyException | IllegalBlockSizeException
                            | BadPaddingException e)
                    {
                        System.out.print("KDC: Bob's cipher was not extractable. System aborted.");
                        LOGGER.log(Level.SEVERE,"KDC: Bob's cipher was not extractable. System aborted.", e);
                    }

                    // Set cipher to Bob's keys
                    try
                    {
                        this.cipher.init(Cipher.ENCRYPT_MODE, secretKeys.get(bobID));
                    }
                    catch (InvalidKeyException e)
                    {
                        System.out.println("KDC: Error encrypting Bob's Message");
                        LOGGER.log(Level.SEVERE,"KDC: Error encrypting Bob's Message", e);
                    }

                    // Encrypt Bob's message
                    byte[] encBobNonce = null;
                    byte[] bobKeyAB = null;
                    byte[] bobEncAliceID = null;
                    try
                    {
                        // Encrypt using Bob's key
                        encBobNonce = this.cipher.doFinal(nonceBob);
                        System.out.print("KDC: Encrypting Bob's nonce: " + nonceBob + ".");

                        bobKeyAB = this.cipher.doFinal(keyAB.getEncoded());
                        System.out.print("KDC: Encrypting Bob's key: " + bobKeyAB + ".");

                        bobEncAliceID = this.cipher
                                .doFinal(ByteBuffer.allocate(4).putInt(this.aliceID).array());
                        System.out.print("KDC: Encrypting Alice's ID for Bob: " + bobEncAliceID + ".");

                        // set cipher to Alice's key
                        this.cipher.init(Cipher.ENCRYPT_MODE, this.secretKeys.get(this.aliceID));
                        // Encrypt Bob's message with Alice's key
                        encBobNonce = this.cipher.doFinal(encBobNonce);
                        bobKeyAB = this.cipher.doFinal(bobKeyAB);
                        bobEncAliceID = this.cipher.doFinal(bobEncAliceID);
                    }
                    catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException e)
                    {
                        System.out.println("KDC: Error encrypting Bob's Message");
                        LOGGER.log(Level.SEVERE,"KDC: Error encrypting Bob's Message", e);
                    }


                    // Transmit Bob's message to Alice
                    System.out.println("KDC: Transmitting Bob's encrypted ticket.");
                    outStream.writeObject(encBobNonce);
                    outStream.flush();
                    outStream.writeObject(bobKeyAB);
                    outStream.flush();
                    outStream.writeObject(bobEncAliceID);
                    outStream.flush();

                    // Receive confirmation from Alice and complete protocol
                    try
                    {
                        inStream.readObject();
                        System.out.println(
                                "KDC: Confirmation from Alice received. Ending communication.");
                    }
                    catch (ClassNotFoundException e)
                    {
                        System.out.println("KDC: Error connecting to client");
                        LOGGER.log(Level.SEVERE, "KDC: Error connecting to client", e);
                    }
                    inStream.close();
                    client.close();
                    openSocket = false;
                }
            }
            serverSocket.close();
        }
        catch (UnknownHostException ex)
        {
            System.out.println("KDC: Error connecting to client");
            LOGGER.log(Level.SEVERE, "KDC: Error connecting to client", ex);
        }
        catch (IOException e)
        {
            System.out.println("KDC: Error connecting to client");
            LOGGER.log(Level.SEVERE, "KDC: Error connecting to client", e);
        }
        catch (ClassNotFoundException e1)
        {
            System.out.println("KDC: Error connecting to client");
            LOGGER.log(Level.SEVERE, "KDC: Error connecting to client", e1);
        }
    }

    public static void main(String[] args)
    {
        System.out.println("Extended Needham Schroeder Mediated-Authentication Scheme");
        Kdc kdc = new Kdc();
        kdc.runExtended();
    }
}
