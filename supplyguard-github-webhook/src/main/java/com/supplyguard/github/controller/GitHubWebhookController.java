package com.supplyguard.github.controller;

import com.supplyguard.github.security.WebhookSignatureVerifier;
import com.supplyguard.github.service.GitHubWebhookService;
import com.supplyguard.github.service.DeliveryTracker;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.supplyguard.github.model.WebhookResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.List;

@RestController
@RequestMapping("/api/github")
public class GitHubWebhookController {

    private final WebhookSignatureVerifier signatureVerifier;
    private final GitHubWebhookService webhookService;
    private final DeliveryTracker deliveryTracker;
    private final ObjectMapper objectMapper;

    public GitHubWebhookController(
            WebhookSignatureVerifier signatureVerifier,
            GitHubWebhookService webhookService,
            DeliveryTracker deliveryTracker,
            ObjectMapper objectMapper) {
        this.signatureVerifier = signatureVerifier;
        this.webhookService = webhookService;
        this.deliveryTracker = deliveryTracker;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/health")
    public WebhookResponse health() {
        return new WebhookResponse("ok", "health", "", 0, List.of("SupplyGuard GitHub webhook is running."));
    }

    @PostMapping(value = "/webhook", consumes = "application/json", produces = "application/json")
    public ResponseEntity<WebhookResponse> webhook(
            @RequestHeader(value = "X-GitHub-Event", defaultValue = "") String event,
            @RequestHeader(value = "X-GitHub-Delivery", defaultValue = "") String deliveryId,
            @RequestHeader(value = "X-Hub-Signature-256", defaultValue = "") String signature,
            @RequestBody byte[] body) {

        if (!signatureVerifier.verify(body, signature)) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(
                    new WebhookResponse("rejected", event, deliveryId, 0,
                            List.of("Invalid GitHub webhook signature."))
            );
        }

        String payload = new String(body, StandardCharsets.UTF_8);

        if ("ping".equals(event)) {
            return ResponseEntity.ok(new WebhookResponse(
                    "accepted", event, deliveryId, 0, List.of("GitHub ping received."))
            );
        }

        if (!deliveryTracker.firstTime(deliveryId)) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                    new WebhookResponse("ignored", event, deliveryId, 0,
                            List.of("Duplicate webhook delivery ignored."))
            );
        }

        if (!"pull_request".equals(event)) {
            return ResponseEntity.ok(new WebhookResponse(
                    "ignored", event, deliveryId, 0,
                    List.of("SupplyGuard currently listens only to pull_request events."))
            );
        }

        String action = extractAction(payload);
        if (!webhookService.isSupportedAction(action)) {
            return ResponseEntity.ok(new WebhookResponse(
                    "ignored", event, deliveryId, 0,
                    List.of("Pull request action is not an analysis trigger: " + action))
            );
        }

        webhookService.processPullRequest(payload);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(
                new WebhookResponse(
                        "accepted",
                        event,
                        deliveryId,
                        0,
                        List.of("Pull request queued for dependency-update inspection."))
        );
    }

    private String extractAction(String payload) {
        try {
            JsonNode root = objectMapper.readTree(payload);
            return root.path("action").asText("");
        } catch (Exception e) {
            return "";
        }
    }
}
