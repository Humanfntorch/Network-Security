 The set of files mimics a client (Alice.java) and server (Bob.java) shared secret exchange using the Diffie-Hellman protocol and TCP socket communication.
 The primary number, generator g, secret key value (for both Alice/Bob) were predefined as: g = 1907, p = 784313, SA = 160031 (Alice’s secret), and SB = 12077 (Bob’s secret). 
 The files both write to a shared output file: "dh.out" that shows each side's portion of the client/server communication, along with their calculated shared secret value.

 To run the programs from a terminal:
 1. Input on command line: $javac Bob.java Alice.java
 2. Ensure both programs compiled and Bob.class Alice.class are in the current directory.
 3. Open a second terminal window (requires 2 windows, 1 for Bob, the other for Alice).
 4. On the first window, input on the command line: $ java Bob
 5. On the second window, input on the command line: $ java Alice
 6. Both terminals should have the respective exchange from either party printed in the window and after execution, a dh.out file should exist within the directory, showing the same exchange from both parties.

 If running the programs from an IDE, ensure the environment allows for multiple programs to execute at the same time. First, compile and run Bob.java, then in a second tab of the environment compile and run Alice.java.