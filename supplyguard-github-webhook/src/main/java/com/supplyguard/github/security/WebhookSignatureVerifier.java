package com.supplyguard.github.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
public class WebhookSignatureVerifier {

    private final String secret;

    public WebhookSignatureVerifier(
            @Value("${supplyguard.github.webhook-secret:}") String secret) {
        this.secret = secret == null ? "" : secret;
    }

    public boolean verify(byte[] body, String signatureHeader) {
        if (secret.isBlank() || body == null || signatureHeader == null) {
            return false;
        }
        if (!signatureHeader.startsWith("sha256=")) {
            return false;
        }

        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] actual = mac.doFinal(body);
            byte[] expected = signatureHeader.substring("sha256=".length())
                    .getBytes(StandardCharsets.UTF_8);
            return MessageDigest.isEqual(toHex(actual).getBytes(StandardCharsets.UTF_8), expected);
        } catch (Exception e) {
            return false;
        }
    }

    private String toHex(byte[] bytes) {
        StringBuilder result = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}
