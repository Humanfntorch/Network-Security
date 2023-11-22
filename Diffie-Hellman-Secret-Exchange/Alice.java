/*
 * Client side 'Alice' used to communicate with the server, 'Bob', for the Diffie-Hellman protocol
 */
import java.io.*;
import java.math.BigInteger;
import java.net.*;

public class Alice 
{
    // initialize socket and i/o streams
    private Socket socket = null;
    private DataInputStream input = null;
    private DataOutputStream out = null;
    // Agreed upon values for Primary num P and generator g
    private int primP = 784313;
    private int genG = 1907;
    // Given DH key for Alice
    private int secretKey = 160031;
    private BigInteger pubKey;

    public void run() 
	{
		try
        {
            
			int serverPort = 8080;
            InetAddress host = InetAddress.getByName("localhost"); 
            // File/writer to create encryption output file
            File file = new File("dh.out");
            file.createNewFile();
            FileWriter writer = new FileWriter("dh.out", true);
            
            System.out.println("Alice is connecting to the server.");
            writer.write("Alice is connecting to the server. \n");

			Socket socket = new Socket(host, serverPort);
            System.out.println("Alice has connected with Bob.");
            writer.write("Alice has connected with Bob.\n");
			PrintWriter toBob = new PrintWriter(socket.getOutputStream(), true);
            BufferedReader fromBob =
                    new BufferedReader(new InputStreamReader(socket.getInputStream()));
            // Alice asks Bob about P and g
            System.out.println("Alice: Hello Bob, is our agreed upon values still: p = " + primP + " and g = "
                    + genG + "?");
            writer.write("Alice: Hello Bob, is our agreed upon values still: p = " + primP + " and g = " + genG + "? Line (1) \n");
            toBob.println("Alice: Hello Bob, is our agreed upon values still: p = " + primP + " and g = "
                    + genG + "?");
            // Agreed upon P and g
            String line = fromBob.readLine();
            // Alice calculates her public key:
            BigInteger base = new BigInteger(Integer.toString(this.genG));
            BigInteger exponent = new BigInteger(Integer.toString(this.secretKey));
            this.pubKey = base.pow(exponent.intValue());
            this.pubKey = this.pubKey.mod(new BigInteger(Integer.toString(this.primP)));
            System.out.println("Alice: Great! This is my public key: " + this.pubKey);
            writer.write("Alice: Great! This is my public key: " + this.pubKey + " Line (2) \n");
            toBob.println("Great! This is my public key: " + this.pubKey);
            // Alice gets Bob's pub key
            line = fromBob.readLine();
            // Alice calculates shared secret
            String digitLine = line.replaceAll("\\D+", "");
            int bobsKey = Integer.parseInt(digitLine);
            base = new BigInteger(Integer.toString(bobsKey));
            exponent = new BigInteger(Integer.toString(this.secretKey));
            BigInteger sharedSecret = base.pow(exponent.intValue());
            sharedSecret =  sharedSecret.mod(new BigInteger(Integer.toString(this.primP)));
            System.out.println("Alice: My calculated shared secret value is: " + sharedSecret);
            writer.write("Alice: My calculated shared secret value is: " + sharedSecret + "Line (3) \n");
            System.out.println("Alice: Thanks Bob, see ya later!");
            writer.write("Alice: Thanks Bob, see ya later! Line (4)\n");
            
			toBob.close();
			fromBob.close();
            socket.close();
            writer.close();
		}
		catch (UnknownHostException ex)
		{
			ex.printStackTrace();
		}
		catch (IOException e)
		{
			e.printStackTrace();
		}
	}
	public static void main(String[] args)
	{
		Alice alice = new Alice();
		alice.run();
	}
}