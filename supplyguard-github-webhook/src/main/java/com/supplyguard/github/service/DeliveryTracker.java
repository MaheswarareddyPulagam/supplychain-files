package com.supplyguard.github.service;

import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Component
public class DeliveryTracker {

    private final Set<String> seen = ConcurrentHashMap.newKeySet();

    public boolean firstTime(String deliveryId) {
        if (deliveryId == null || deliveryId.isBlank()) {
            return true;
        }
        return seen.add(deliveryId);
    }
}
