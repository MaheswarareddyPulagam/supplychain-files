package com.supplyguard.github.model;

import java.util.List;

public record WebhookResponse(
        String status,
        String event,
        String deliveryId,
        int dependencyUpdatesDetected,
        List<String> messages
) {}
