package org.example;

import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.MqttClientSslConfig;
import com.hivemq.client.mqtt.mqtt3.Mqtt3AsyncClient;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.json.JSONObject;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.UUID;

import static org.example.AESUtils.decryptAES;
import static org.example.RSAUtil.decryptByPrivateKey;

public class Main {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    private static String base64KeyQrisStatic =
            "MIIEpAIBAAKCAQEAwMFI4esz6QUY/ndYSARcX2KTCf704HpxGD6j4Nh9PaqGCS++" +
                    "PirLqNEM0/SQRREze9mPVazh+OjnYdMUhYVPI7qCNN6cVsBYqtVwtcnx5JNBKhLt" +
                    "0erBWiW+kWX7OhK/1ssLagsStosxIljgIBJVC4lqyqihFJb0GdOvlPomfZD01bxL" +
                    "0s7o3RmFkuN6FMsl2VAmWG6Lpco6KgsYKVIw8qrgMLWtzS6086Jkbk2vlxatFBkN" +
                    "3C6pPZidHACuPWTmYQioW9PrKcXcqZn9YB+cCU/bHTxNKwoxVpOq6DqoU6xTn+JP" +
                    "EwymDARA+/jHKhPVSerlgXIx5enLNXr/YwYILQIDAQABAoIBAGnTdH08kbJ0bwV+" +
                    "ZoSbiE+CIjJRvQXlk2P5OCYBFbmefppakPs2qbvUklNoKTESQY7UomIqWaI71JUbu" +
                    "1+XEh0Oj+AQ/AqQ7d1U892KsviIdDVyUQl39pHUuSzArc5zbsmxjmG5FJwODXrLC" +
                    "rnw9qov1ubO8CkKu5fWZcbIFAvJbn/GaCtKthIL5rlZDKRYC6+BpAOq5jrfm5txT" +
                    "yJxJs8uSiRIUl9+TwYuw4tZ/Fi4ety0T5B1it20HAgqTB+tAM/38gAGwForFyVTM" +
                    "MRlDHqIT7Sw26XAv6NZmF4QRwArmwnO18RjnfJlBgNHPMk+EerMz9/3N63ZUFmkW" +
                    "uBNf4ECgYEA7T6Tv64WQggnS1u06m2+i1eedR4ny2//EbMva0ujuVfkJQe9CqhTp" +
                    "8ZarhIFF0vOuOl/1NgTGVPrbUmgxRGsmqw9FZDsi2H5lnTdkrEN7ibFW1xA0CuHo" +
                    "xRSQMs3rf6tUSONZT4y2nK3jd8At/m6w57Okkyo4aInGhG4LP1ReSECgYEAz/5RR" +
                    "8sGaFCx/Sk+1wwjtI6tKd14fdgid+FMDr1kaCJvS1FAl6XM96wY1Z2CRvr4PeV9m" +
                    "AIdX8drKaiJcgLdjYTZj7vAO4m0D2PengNyELL8mwZtM+jq3v9jayBF1CSyNAfZE" +
                    "zeLothEMcqMcH0EzKXj6Az/2CpPiVNBPgMXMY0CgYEA0aNlPZCgfHLl/hIoWKrnI" +
                    "AwpqkYeVgc+Ni7HLSGmqCXBJPOkmWFKosuE36JuuzoyjnVOjw7sOYpNU8Im/Vzzz" +
                    "615QLBSRYwq10enb3Ni4tmBtYxcfVapwXI4iKbKKccM8dDfpeIDX8LU7dlrsiZLY" +
                    "YbX9LEm3lLCCKg1vhOOReECgYEAkvD8w1evoyq/VDc7afntj7XsqFMKuP1k/IRyk" +
                    "0dCFD+fmPpCQ+CiuacftGqeiz7q+e+TlzyHPA9KqhejYqSbmUtt2Jmv6WATkXvg3" +
                    "olYoGuTAoK7y5yVsg2DUz9tlb6HFzMkLOtk/xsCspqCNUZdiab5KAtnBHR/1Gi5A" +
                    "vJ0BFECgYAL9ZsQ/r4uuzzujQceTHx/ZmZkIYYmqCyWrCLjMJurRikpNKczoY5+D" +
                    "vPtraeEbWvxLyFJsDYwUUDkZUQDEVtteOjYyCojWV08OoMeRxpmwkOiJho/WF71k" +
                    "sCzmCHDTk03VXDWluZinkC8KAlOf+zd3RDYCV8tccI+qJ3gKICNQQ==";

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        InputStream is = Main.class.getClassLoader().getResourceAsStream("m2mqtt_ca_cz_prod.crt");

        if (is == null) {
            System.out.println("File not found");
            return;
        }

        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] data = new byte[1024];
        int nRead;
        while ((nRead = is.read(data, 0, data.length)) != -1) {
            buffer.write(data, 0, nRead);
        }

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        ByteArrayInputStream caInput = new ByteArrayInputStream(buffer.toByteArray());
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(caInput);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("caCert", caCert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        HostnameVerifier allHostsValid = (hostname, session) -> true;

        //MqttClientSslConfig MANUAL
        MqttClientSslConfig sslConfig = MqttClientSslConfig.builder()
                .trustManagerFactory(tmf)
                .hostnameVerifier(allHostsValid)  // override hostname verifier
                .build();

        //Build client used sslConfig
        String clientId = "client-" + UUID.randomUUID();
        Mqtt3AsyncClient client = MqttClient.builder()
                .useMqttVersion3()
                .identifier(clientId)
                .serverHost("messagebroker.cashlez.com")
                .serverPort(18883)
                .sslConfig(sslConfig)
                .buildAsync();

        client.connect().whenComplete((connAck, throwable) -> {
            if (throwable != null) {
                System.out.println("Connection failed: " + throwable.getMessage());
            } else {
                System.out.println("Connected: " + connAck);
            }
        });

        client.subscribeWith()
                .topicFilter("payment/ittest05")  // topic to subscribe payment/{mobileUserId}
                .callback(mqtt3Publish -> {
                    byte[] payload = mqtt3Publish.getPayloadAsBytes();
                    String jsonString = new String(payload);
                    try {
                        JSONObject json = new JSONObject(jsonString);
                        String invoiceNum = json.optString("invoice_num", null);
                        String encKey = json.optString("enc_key", null);
                        String encPayload = json.optString("enc_payload", null);
                        String encIv = json.optString("enc_iv", null);

                        if (invoiceNum != null && !invoiceNum.isEmpty()) { // Used only for dynamic QRIS
                            System.out.println("Received message QRIS Dynamic: ");
                            System.out.println("Topic : " + mqtt3Publish.getTopic());
                            System.out.println("Payload All Received message QRIS Dynamic: " + new String(mqtt3Publish.getPayloadAsBytes()));
                            System.out.println("Invoice Number : " + invoiceNum);
                        } else {  //Used only for static QRIS
                            System.out.println("Received message QRIS Static Encryption: ");
                            System.out.println("Topic : " + mqtt3Publish.getTopic());
                            System.out.println("Payload All Received message QRIS Static Encryption: " + new String(mqtt3Publish.getPayloadAsBytes()));

                            String decKeys = decryptByPrivateKey(hexStringToBytes(encKey), base64KeyQrisStatic);
                            String decIv = decryptByPrivateKey(hexStringToBytes(encIv), base64KeyQrisStatic);
                            byte[] baPayload = decryptAES(hexStringToBytes(decKeys), hexStringToBytes(decIv), hexStringToBytes(encPayload));
                            String resultDecrypted = bytesToHex(baPayload);

                            System.out.println("Result Decrypted Keys: " + decKeys);
                            System.out.println("Result Decrypted IV: " + decIv);
                            System.out.println("Result Payload All Received message QRIS Static: " + hexToString(resultDecrypted));
                        }

                    } catch (InvalidKeySpecException e) {
                        throw new RuntimeException(e);
                    } catch (NoSuchPaddingException e) {
                        throw new RuntimeException(e);
                    } catch (InvalidKeyException e) {
                        throw new RuntimeException(e);
                    } catch (BadPaddingException e) {
                        throw new RuntimeException(e);
                    } catch (IllegalBlockSizeException e) {
                        throw new RuntimeException(e);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                })
                .send()
                .whenComplete((subAck, throwable) -> {
                    if (throwable != null) {
                        System.err.println("Subscribe failed: " + throwable.getMessage());
                    } else {
                        System.out.println("Subscribe success!!!!");
                    }
                });

        Thread.sleep(5000); // wait for connection
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.isEmpty()) {
            return null;
        }

        byte[] buffer = new byte[hexString.length() >> 1];
        int stringLength = hexString.length();
        int byteIndex = 0;

        for (int i = 0; i < stringLength; i++) {
            char ch = hexString.charAt(i);
            if (ch == ' ') {
                continue;
            }

            byte hex = isHexChar(ch);
            if (hex < 0) {
                return null;
            }

            int shift = (byteIndex % 2 == 1) ? 0 : 4;
            buffer[byteIndex >> 1] = (byte) (buffer[byteIndex >> 1] | (hex << shift));
            byteIndex++;
        }

        byteIndex >>= 1; // Divide by 2
        if (byteIndex > 0) {
            if (byteIndex < buffer.length) {
                byte[] newBuffer = new byte[byteIndex];
                System.arraycopy(buffer, 0, newBuffer, 0, byteIndex);
                return newBuffer;
            }
        } else {
            return null;
        }
        return buffer;
    }

    private static byte isHexChar(char ch) {
        if (ch >= '0' && ch <= '9') {
            return (byte) (ch - '0');
        }
        if (ch >= 'A' && ch <= 'F') {
            return (byte) (ch - 'A' + 10);
        }
        if (ch >= 'a' && ch <= 'f') {
            return (byte) (ch - 'a' + 10);
        }
        return -1; // Invalid hex character
    }

    public static String hexToString(String hex) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < hex.length(); i += 2) {
            String str = hex.substring(i, i + 2);
            output.append((char) Integer.parseInt(str, 16));
        }
        return output.toString();
    }
}