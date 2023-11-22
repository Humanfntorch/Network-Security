import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

public class CertificateAuthority
{
    public CertificateAuthority() throws IOException, InterruptedException
    {
        // Build the command to run the shell script
        List<String> command = new ArrayList<String>();
        command.add("/bin/bash");
        command.add("generate_certificate.sh");

        // Run the shell script
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(true);
        Process process = pb.start();

        // Read the output of the shell script
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        String line;
        while ((line = reader.readLine()) != null)
        {
            System.out.println(line);
        }

        // Wait for the shell script to finish
        int exitCode = process.waitFor();
        System.out.println("Exit code: " + exitCode);
    }
}
