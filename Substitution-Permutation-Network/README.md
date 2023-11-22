This program encrypts an 8 character string input using an 8 character key by performing 16 rounds of substitution/permutation with a randomly generated set of unique character distributed values in the ASCII range [33, 127]. The output of each round in encryption/decryption is printed into a console and written into a specified output file within each of the encyrption/decryption methods.

To run the program with the predefined contents from the command line, perform the following:
1. Ensure the hw2.java file exists in the current directory.
2. From command line input: $ javac hw2.java
3. Ensure hw2.class was compiled and is in the current directory.
4. From command line input: $ java hw2.
This will execute the program, printing the results of each stage to the console as well as generating two input files with the same output as from the console:
input1.txt -> Input = "abcdefgh"; key = "password"
input2.txt -> Input = "abcdefgz"; key = "password"

If running from an IDE capable of compiling and executing .java programs, then simply ensure the file is open in the IDE and click run/execute program.

ADDITIONAL INFORMATION ON PROGRAM:

There is a single constructor:
hw2(String input, String key)
The constructor accepts two arguments:

String input -> The input to be encrypted. Must be 8 characters
within the string (string is converted to a char array) or else an illegalargument exception is thrown.

String key -> The key used for encryption. Must be 8 characters
within the string (string is converted to a char array) or else an illegalargument exception is thrown.

Inititalization is as such: 
hw2 enc = new hw2(input: "abcdefgh", key: "password").

The first of the two main methods is:

public void encrypt(String filename)

This performs the encryption algorithm and writes the 
ouput at each stage to given filename in the argument:
String filename -> filename to produce encryption output.
If the file does not exists, creates a new file using filename.

The second method provided is:

public void decrypt(String filename)

This performs the decryption algorithm (it is implicitly implied that one uses encrypt above before this method, otherwise undefined behavior may occur), and writes the output at each stage to the given filename in the argument:

String filename -> filename to produce encryption output.
If the file does not exists, creates a new file using filename, otherwise appends the written stages to the existing filename.

Both encryption and decryption methods are used as follows:
hw2 enc = new hw2(input: "abcdefgh", key:"password");
enc.encrypt("output1.txt");
enc.decrypt("output1.txt");

In order to analyze the encrypted input, there is a private field that one may access using the initialized class object enc above:
enc.encryptedInput -> a char array holding the 8 characters of encyrpted text.
Additionally, one may access the original input and key arrays in a similar manner:
enc.input -> a char array holding the 8 characters of the original defined input given as String input.
enc.key -> a char array holding the 8 characters of the original defined input given as String key.