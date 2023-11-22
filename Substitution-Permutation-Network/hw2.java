/*
 * Created by Jacob Rogers for CS6490 - Network Security. This program encrypts an 8 character
 * string input using an 8 character key by performing 16 rounds of substitution/permutation with a
 * randomly generated set of unique character distributed values in the ASCII range [33, 127]. The
 * output of each round in encryption/decryption is printed into a console and written into
 * a specified output file within each of the encyrption/decryption methods.
 */
import java.util.Random;
import java.util.ArrayList;
import java.util.Arrays;
import java.io.File; 
import java.io.FileWriter;
import java.io.IOException;

class hw2 
{  
    private ArrayList<char []> tables;
    private char[] key;
    private char[] input;
    private char[] encryptedInput;

    // Ctor
    public hw2(String input, String key)
    {
        this.key = key.toCharArray();
        this.input = input.toCharArray();
        if(this.key.length != 8)
        {
            throw new IllegalArgumentException("key must be composed of 8 characters.");
        }
        if(this.input.length != 8)
        {
            throw new IllegalArgumentException("Input must be composed of 8 characters");
        }

        this.encryptedInput = new char[8];
         // Holds 8 arrays composed of 8 characters
         this.tables= new ArrayList<char []>();
         // Fill with init null values
         for(int i = 0; i < 8; i++)
         {
            tables.add(null);
         }
    }

    /*
     * Performs a right circular shift on the input array.
     */
    private void rightCircularShift()
    {  
        char tempChar = this.encryptedInput[this.encryptedInput.length - 1];
        for(int i = this.encryptedInput.length - 1; i > 0 ; i--)
        {
            this.encryptedInput[i] = this.encryptedInput[i - 1];
        }
        this.encryptedInput[0] = tempChar;
    }

    /*
     * Performs a left circular shift on the input array.
     */
    private void leftCircularShift()
    {
        char tempChar = this.encryptedInput[0];
        for(int i = 0; i < this.encryptedInput.length - 1; i++)
        {
            this.encryptedInput[i] = this.encryptedInput[i + 1];   
        }
        this.encryptedInput[this.encryptedInput.length - 1] = tempChar;
    }

    /*
     * Performs a character-by-character exclusive or operation
     */
    private void XOR(boolean enc)
    {   
        if(enc)
        {
            for(int i = 0; i < 8; i++)
            {
                this.encryptedInput[i] = (char) (this.input[i] ^ this.key[i] + 33);
            }
        }
        else
        {
            for(int i = 0; i < 8; i++)
            {
                this.encryptedInput[i] = (char) (this.encryptedInput[i] ^ this.key[i] + 33);
            }   
        }
    }

    /*
     * Generates 8 random substitution tables,
     * one for each character in the encrypted array (assumed 8 characters)
     */
    private void generateRandTables()
    {   
        Random rnd = new Random();
        for(int i = this.input.length - 1; i >= 0; i--)
        {
            char[] table = new char[8];
            if(i == 0)
            {   
                for(int j = 1; j < 8; j++)
                {   
                    table[j] = (char) (this.encryptedInput[j] + this.tables.get(j)[j]);
                }
                table[0] = (char)(this.encryptedInput[0] + this.tables.get(1)[0]);
            }
            else
            {
                for(int j = 0; j < 8; j++)
                {   
                    table[j] = (char)(rnd.nextInt(94) + 33);
                }
            }
            this.tables.set(i, table);
        }
    }

    /*
     * Substitutes each character in the encrypted input
     * using the unique substitution tables created.
     */
    private void substitute(int round)
    {   
        char[] subCharArr = this.tables.get(round % 8);
        for(int i = 0; i < 8; i++)
        {   
            this.encryptedInput[i] = subCharArr[i];
        }
    }

    /*
     * Reverses the substitution proccess using the unique sub
     * table.
     */
    private void desubstitute(int round)
    {   
        char[] subCharArr = this.tables.get(round % 8);  
        for(int i = 0; i < 8; i++)
        {
            this.encryptedInput[i] = subCharArr[i];
        }
    }

    /*
     * Performs 16 rounds of substitution/permutation to encrypt 
     * the given input. Doesn't return a value, encrypted value is found in field 'input'
     */
    public void encrypt(String filename)
    {   
        try 
        {   
            // File/writer to create encryption output file
            File file = new File(filename);
            file.createNewFile();
            FileWriter writer = new FileWriter(filename);

            System.out.println("Input to be encrypted: " + Arrays.toString(this.input));
            writer.write("Input to be encrypted: " + Arrays.toString(this.input) + "\n");
            
            // XOR the input and key + generate encryption tables
            XOR(true);
            generateRandTables();

            writer.write("Input in encryption algorithm: " + Arrays.toString(this.encryptedInput) + "\n");
            System.out.println("Input in encryption algorithm: " + Arrays.toString(this.encryptedInput));
            writer.write("Encryption Steps\n");
            System.out.println("Encryption Steps");

             // Encryption algo
            for(int i = 0; i < 16; i++)
            {
                substitute(i);
                leftCircularShift();
                writer.write("Round " + i + " output: " + Arrays.toString(this.encryptedInput) + "\n");
                System.out.println("Round " + i + " output: " + Arrays.toString(this.encryptedInput));
            }
            writer.write("Encrypted Output: " + Arrays.toString(this.encryptedInput) + "\n");
            System.out.println("Encrypted Output: " + Arrays.toString(this.encryptedInput));
            writer.write("\n");
            System.out.println();
            writer.close();
          } 
          catch (IOException e) 
          {
            System.out.println("An error occurred.");
            e.printStackTrace();
          }
    }

     /*
     * Performs 16 rounds of substitution/permutation to Decrypt 
     * the given input. Doesn't return a value, encrypted value is found in field 'input'
     */
    public void decrypt(String filename)
    {
        try
        {
            // File/writer to create encryption output file
            File file = new File(filename);
            file.createNewFile();
            FileWriter writer = new FileWriter(filename, true);

            writer.write("Input to be decrypted: " + Arrays.toString(this.encryptedInput) + "\n");
            System.out.println("Input to be decrypted: " + Arrays.toString(this.encryptedInput));
            writer.write("Decryption Steps \n");
            System.out.println("Decryption Steps");

            // Decryption algo
            for(int i = 15; i >= 0 ; i--)
            {   
                rightCircularShift();
                desubstitute(i);
                writer.write("Round " + i + " output: " + Arrays.toString(this.encryptedInput) + "\n");        
                System.out.println("Round " + i + " output: " + Arrays.toString(this.encryptedInput));

            }
            for(int i = 1; i < 8; i++)
            {   
                this.encryptedInput[i] -= (char) this.tables.get(i)[i];
            }
            this.encryptedInput[0] -= (char) this.tables.get(1)[0];
            writer.write("Output of decryption algorithm: " + Arrays.toString(this.encryptedInput) + "\n");
            System.out.println("Output of decryption algorithm: " + Arrays.toString(this.encryptedInput));
            XOR(false);
            writer.write("Decrypted Output: " + Arrays.toString(this.encryptedInput) + "\n");
            System.out.println("Decrypted Output: " + Arrays.toString(this.encryptedInput));
            writer.write("\n");
            writer.close();
            System.out.println();
        }
        catch (IOException e) 
        {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
    }

    public static void main(String args[])  //static method  
    {
        // First input
        hw2 enc = new hw2("abcdefgh", "password");
        enc.encrypt("input1.txt");
        enc.decrypt("input1.txt");

        // Second input
        hw2 enc2 = new hw2("abcdefgz", "password");
        enc2.encrypt("input2.txt");
        enc2.decrypt("input2.txt");
    }
}  