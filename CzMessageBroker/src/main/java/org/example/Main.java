package org.example;

import com.hivemq.client.mqtt.MqttClient;
import com.hivemq.client.mqtt.MqttClientSslConfig;
import com.hivemq.client.mqtt.mqtt3.Mqtt3AsyncClient;
import org.json.JSONObject;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.UUID;

public class Main {
    public static void main(String[] args) throws Exception {
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
                .topicFilter("payment/tyo")  // topic yang mau disubscribe
                .callback(mqtt3Publish -> {
                    byte[] payload = mqtt3Publish.getPayloadAsBytes();
                    String jsonString = new String(payload);
                    System.out.println("Received message : ");
                    System.out.println("Topic : " + mqtt3Publish.getTopic());
                    System.out.println("Payload All Received message : " + new String(mqtt3Publish.getPayloadAsBytes()));
                    try {
                        JSONObject json = new JSONObject(jsonString);
                        String invoiceNum = json.getString("invoice_num");
                        System.out.println("Invoice Number : " + invoiceNum);
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
}