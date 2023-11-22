// Server Side
import java.net.*;
import java.io.*;
import java.math.BigInteger;

public class Bob 
{
    // Agreed upon values for Primary num P and generator g
    private int primP = 784313;
    private int genG = 1907;
    // Given DH key for Bob
    private int secretKey = 12077;
    private BigInteger pubKey;
  public void run() 
  {
	try 
	{
		int serverPort = 8080;
		ServerSocket serverSocket = new ServerSocket(serverPort);
        //serverSocket.setSoTimeout(10000);
        File file = new File("dh.out");
        file.createNewFile();
        FileWriter writer = new FileWriter("dh.out", true);
        boolean openSocket = true;
            
        while (openSocket)
        {
            System.out.println("Waiting for Alice...");
            writer.write("Bob: Waiting for Alice... Line (1) \n");

            Socket server = serverSocket.accept();
            System.out.println("Bob: Just connected to Alice.");
            writer.write(
                    "Bob: Just connected to Alice. Line (2) \n");

            PrintWriter toAlice =
                    new PrintWriter(server.getOutputStream(), true);
            BufferedReader fromAlice =
                    new BufferedReader(
                            new InputStreamReader(server.getInputStream()));
            // Alice asks if P and g are still valid
            String line = fromAlice.readLine();
            System.out.println(
                    "Bob: Yes, p = " + this.primP + " and g = " + this.genG + ". Let's start the exchange!");
            writer.write("Bob: Yes, p = " + this.primP + " and g = " + this.genG
                    + ". Let's start the exchange! Line (3) \n");
            toAlice.println(
                    "Bob: Yes, p = " + this.primP + " and g = " + this.genG + ". Let's start the exchange!");
            // Bob calculates public key
            BigInteger base = new BigInteger(Integer.toString(this.genG));
            BigInteger exponent = new BigInteger(Integer.toString(this.secretKey));
            this.pubKey = base.pow(exponent.intValue());
            this.pubKey = this.pubKey.mod(new BigInteger(Integer.toString(this.primP)));
            // Alice sends key to Bob
            line = fromAlice.readLine();
            System.out.println("Bob: Key was received. This is my public key: " + this.pubKey);
            writer.write(
                    "Bob: Key was received. This is my public key: " + this.pubKey + " Line (4) \n");
            toAlice.println("Key was received. This is my public key: " + this.pubKey);
            // Bob calculates shared secret
            String digitLine = line.replaceAll("\\D+", "");
            int alicesKey = Integer.parseInt(digitLine);
            base = new BigInteger(Integer.toString(alicesKey));
            exponent = new BigInteger(Integer.toString(this.secretKey));
            BigInteger sharedSecret = base.pow(exponent.intValue());
            sharedSecret =  sharedSecret.mod(new BigInteger(Integer.toString(this.primP)));
            System.out.println("Bob: My calculated shared secret value is: " + sharedSecret);
            writer.write(
                    "Bob: My calculated shared secret value is: " + sharedSecret + "Line (5) \n");
            // Receive goodbye from Alice
            line = fromAlice.readLine();
            System.out.println("Bob: Later, Alice.");
            writer.write("Bob: Later, Alice. Line (6)\n");
            openSocket = false;
        }
        serverSocket.close();
        writer.close();
	}
	catch(UnknownHostException ex) 
	{
		ex.printStackTrace();
	}
	catch(IOException e)
	{
		e.printStackTrace();
	}
  }
	
  public static void main(String[] args)
  {
		Bob bob = new Bob();
		bob.run();
  }
}