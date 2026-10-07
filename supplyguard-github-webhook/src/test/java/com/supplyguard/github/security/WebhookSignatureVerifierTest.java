package com.supplyguard.github.security;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class WebhookSignatureVerifierTest {

    @Test
    void acceptsValidGithubSignature() throws Exception {
        WebhookSignatureVerifier verifier = new WebhookSignatureVerifier("test-secret");
        byte[] body = "{\"action\":\"opened\"}".getBytes(StandardCharsets.UTF_8);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec("test-secret".getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        StringBuilder hex = new StringBuilder();
        for (byte b : mac.doFinal(body)) {
            hex.append(String.format("%02x", b));
        }

        assertTrue(verifier.verify(body, "sha256=" + hex));
    }

    @Test
    void rejectsInvalidSignature() {
        WebhookSignatureVerifier verifier = new WebhookSignatureVerifier("test-secret");
        assertFalse(verifier.verify("payload".getBytes(StandardCharsets.UTF_8), "sha256=bad"));
    }
}
