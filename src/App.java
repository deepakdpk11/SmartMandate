import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataOutputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.NoSuchAlgorithmException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import java.util.Base64;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.util.UUID;
import java.text.SimpleDateFormat;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.InvalidKeyException;
import java.security.Key;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import java.io.FileInputStream;
import java.io.IOException;
import org.json.JSONObject;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateEncodingException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


public class App {

    public static void main(String[] args) {
        try {
            // Generate a session key
            SecretKey sessionKey = generateKey();

            // Generate the IV using the session key
            byte[] iv = generateIV(sessionKey.getEncoded());

            // Generate the AAD using the timestamp
            byte[] aad = generateAAD();

            // Get OAuth token from the given endpoint
            String oauthToken = getOAuthToken();

            // API endpoint URL
            URL url = new URL("http://localhost:8000/register_mandate"); // Change the URL here

            // Open a connection
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Set the request method
            conn.setRequestMethod("POST");

            // Set headers
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", oauthToken);
            conn.setRequestProperty("Channel", "MOB");

            // Load client certificate
            //X509Certificate clientCert = loadClientCertificate("C:\\Users\\DELL\\UAT\\client\\server-signed-cert.pem");
            X509Certificate clientCert = loadClientCertificate("/home/ubuntu/SmartMandate/client/server-signed-cert.pem");
            if (clientCert != null) {
                // Set client certificate as request property
                conn.setRequestProperty("X-Client-Certificate", encodeCertificate(clientCert));
            }
            // Set X-APIInteraction-ID header
            conn.setRequestProperty("X-APIInteraction-ID", generateAPIInteractionID());
            // Set HealthCheck header
            conn.setRequestProperty("HealthCheck", "FALSE");
            // Set HealthType header
            conn.setRequestProperty("HealthType", "GWY");

            // Enable input/output
            conn.setDoOutput(true);
            conn.setDoInput(true);

            // Read JSON data from config file
            String configFilePath = "config.json";
            String jsonInputString = new String(Files.readAllBytes(Paths.get(configFilePath)));
            JSONObject configJsonObject = new JSONObject(jsonInputString);

            // Generate unique reference number
            String referenceNumber = generateReferenceNumber();
            String consreferenceNumber = generateReferenceNumber();

            // Extract JSON data from config
            JSONObject payload = configJsonObject.getJSONObject("RegisterMandate_Req")
                                                .getJSONObject("Body")
                                                .getJSONObject("Payload")
                                                .put("referenceNumber", referenceNumber)
                                                .put("consRefNo", consreferenceNumber);
            
            System.out.println("payload Data:");
            System.out.println(payload);
            // JSON data to send
           // String jsonInputString = "{ \"RegisterMandate_Req\": { \"Body\": { \"Payload\": { \"referenceNumber\": \"167906\", \"utilityCode\": \"IDIB00290000026898\", \"categoryCode\": \"L002\", \"schmNm\": \"TWO-WHEELER-LOAN\", \"consRefNo\": \"LN1507927\", \"seqTp\": \"RCUR\", \"frqcy\": \"MNTH\", \"frstColltnDt\": \"2021-10-25\", \"fnlColltnDt\": \"2030-10-25\", \"amountTp\": \"MAXA\", \"colltnAmt\": 101, \"dbtrNm\": \"Jane Doe\", \"phone\": \"null\", \"mobile\": \"9887612345\", \"email\": \"suma@gmail.com\", \"pan\": \"ABCDE0011A\", \"bnkId\": \"HDFC\", \"dbtrAccTp\": \"SAVINGS\", \"dbtrAccNo\": \"536875gh6\" } } } }";

            // Encrypt the JSON data using the session key, IV, and AAD
            String encryptedJsonInputString = encryptData(payload.toString(), sessionKey, iv, aad);

            // Encrypt the session key using RSA encryption with the public key from the certificate
            String encryptedSessionKey = encryptsessionkey(Base64.getEncoder().encodeToString(sessionKey.getEncoded()));

            // Prepare the request payload
            //String requestData = "{ \"sessionKey\": \"" + encryptedSessionKey + "\", \"encryptedData\": \"" + encryptedJsonInputString + "\" }";
            String requestData = buildRequestData(encryptedJsonInputString, encryptedSessionKey);
            System.out.println("Request Data:");
            System.out.println(requestData);

            // Generate the JWS token using the encrypted payload and HMAC key
            String jwtToken = getJWSKey(requestData,"dL1aa2Ai28XgDssAZGMwaE63I1iJTpXGZMmfwHpW4s8");

            // Set X-JWS-Signature header
            conn.setRequestProperty("X-JWS-Signature", jwtToken);

            // Write encrypted JSON data to the connection
            try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
                wr.writeBytes(requestData);
                wr.flush();
            }

            // Get the response code
            int responseCode = conn.getResponseCode();
            System.out.println("Response Code: " + responseCode);

            // Read the response
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String inputLine;
                StringBuilder response = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }
                System.out.println("Response Body: " + response.toString());
            }

            // Close the connection
            conn.disconnect();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Generate a session key
    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        SecretKey key = keyGenerator.generateKey();
        System.out.println("Generated Session Key: " + Base64.getEncoder().encodeToString(key.getEncoded()));
        return key;
    }

    // Generate the IV using the session key
    public static byte[] generateIV(byte[] key) {
        return Arrays.copyOfRange(key, 0, 12);
    }

    // Generate the AAD using the timestamp
    public static byte[] generateAAD() {
        Date date = new Date();
        SimpleDateFormat ft = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss:SSS");
        String timestamp_same = ft.format(date);
        return Arrays.copyOfRange(timestamp_same.getBytes(), 0, 16);
    }

    // Method to generate unique reference number
    private static String generateReferenceNumber() {
    // Define the characters allowed in the reference number (A-Z, 0-9)
    String allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    // Generate a random reference number of maximum length 15
    StringBuilder referenceNumber = new StringBuilder();
    Random random = new Random();
    for (int i = 0; i < 15; i++) {
        referenceNumber.append(allowedChars.charAt(random.nextInt(allowedChars.length())));
    }
    return referenceNumber.toString();
    }


    // Encrypt data using AES encryption with the session key, IV, and AAD
    public static String encryptData(String data, SecretKey key, byte[] iv, byte[] aad) {
        try {
            GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); // Encryption Algorithm
            cipher.init(Cipher.ENCRYPT_MODE, key, gcmParameterSpec);
            cipher.updateAAD(aad);
            byte[] ciphertextWithTag = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));
            byte[] c = new byte[ciphertextWithTag.length + aad.length]; // Declaring new Array
            System.arraycopy(ciphertextWithTag, 0, c, 0, ciphertextWithTag.length);
            System.arraycopy(aad, 0, c, ciphertextWithTag.length, aad.length); // Concatenating AAD
            return Base64.getEncoder().encodeToString(c);
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }
    public static String buildRequestData(String encryptedJsonInputString, String encryptedSessionKey) {
        JSONObject payload = new JSONObject();
        payload.put("data", encryptedJsonInputString);
        payload.put("sessionKey", encryptedSessionKey);

        JSONObject payloadBody = new JSONObject();
        payloadBody.put("Payload", payload);

        JSONObject requestBody = new JSONObject();
        requestBody.put("Body", payloadBody);

        JSONObject requestInfo = new JSONObject();
        requestInfo.put("request_info", requestBody);

        return requestInfo.toString();
    }

    // Method to get OAuth token from the given endpoint
    private static String getOAuthToken() {
        try {
            // Endpoint URL
            URL url = new URL("http://localhost:8000/oauth2");

            // Open a connection
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            // Set the request method
            conn.setRequestMethod("POST");

            // Set headers
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

            // Enable input/output
            conn.setDoOutput(true);
            conn.setDoInput(true);

            // Construct the request body
            String requestBody = "scope=application&grant_type=client_credentials&client_id=bb0b3f27fc923f6a51a7af07ff2cbc40&client_secret=dL1aa2Ai28XgDssAZGMwaE63I1iJTpXGZMmfwHpW4s8";

            // Write the request body to the connection
            try (DataOutputStream wr = new DataOutputStream(conn.getOutputStream())) {
                wr.write(requestBody.getBytes(StandardCharsets.UTF_8));
                wr.flush();
            }

            // Get the response code
            int responseCode = conn.getResponseCode();
            System.out.println("OAuth Token Request Response Code: " + responseCode);

            // Read the response
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                StringBuilder response = new StringBuilder();
                String inputLine;
                while ((inputLine = in.readLine()) != null) {
                    response.append(inputLine);
                }

                // Parse the response JSON
                JSONObject jsonResponse = new JSONObject(response.toString());
                String accessToken = jsonResponse.getString("access_token");
                System.out.println("OAuth Token: " + accessToken);
                return accessToken;
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // Method to load client certificate
    private static X509Certificate loadClientCertificate(String certificateFilePath) {
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            byte[] certBytes = Files.readAllBytes(Paths.get(certificateFilePath));
            return (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(certBytes));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String getJWSKey(String encryptedPayload, String secretKey) {
        Key hMacKey = new SecretKeySpec(Base64.getDecoder().decode(secretKey),
        SignatureAlgorithm.HS256.getJcaName());
        String jwtToken =
        Jwts.builder().setPayload(encryptedPayload).signWith(SignatureAlgorithm.HS256,
        hMacKey).compact();
        System.out.println("jwtToken : " + jwtToken);
        String[] arr = jwtToken.split("[.]");
        return arr[0] + ".." + arr[2];
    }

    // Method to generate X-APIInteraction-ID header value
    private static String generateAPIInteractionID() {
        // Generate the value as specified (First 4 characters: Channel, REST 22 Characters: Random Unique Numeric Values)
        String channel = "CHAN"; // Replace with actual channel value provided by the BANK team
        String randomNumericValues = generateRandomNumericValues(22);
        return channel + randomNumericValues;
    }

    // Method to generate random unique numeric values
    private static String generateRandomNumericValues(int length) {
        // Generate random numeric values
        StringBuilder stringBuilder = new StringBuilder();
        for (int i = 0; i < length; i++) {
            stringBuilder.append((int) (Math.random() * 10));
        }
        return stringBuilder.toString();
    }

    

    // Method to encode X.509 certificate to Base64 string
    private static String encodeCertificate(X509Certificate certificate) {
        try {
            // Get the encoded form of the certificate
            byte[] certificateBytes = certificate.getEncoded();

            // Convert the byte array to a Base64-encoded string
            return Base64.getEncoder().encodeToString(certificateBytes);
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
            return null; // Or handle the exception in a way appropriate for your application
        }
    }

    // Encrypt session key using RSA encryption with the public key from the certificate
    public static String encryptsessionkey(String sessionkey) throws CertificateException,
        NoSuchAlgorithmException, NoSuchPaddingException,
        InvalidKeyException,IllegalBlockSizeException, BadPaddingException, IOException {
    try {
        byte[] session = Base64.getDecoder().decode(sessionkey);
        // Update the path to the certificate file
        //FileInputStream certStream = new FileInputStream("C:\\Users\\DELL\\UAT\\server\\extracted_certificate.cer");
        FileInputStream certStream = new FileInputStream("/home/ubuntu/SmartMandate/server/extracted_certificate.cer");
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(certStream);
        PublicKey pk = cert.getPublicKey();
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, pk);
        return Base64.getEncoder().encodeToString(cipher.doFinal(session));
    } catch (Exception ex) {
        ex.printStackTrace();
    }
    return null;
    }
}
