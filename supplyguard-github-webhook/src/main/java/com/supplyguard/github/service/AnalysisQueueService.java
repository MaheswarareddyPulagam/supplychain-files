package com.supplyguard.github.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.supplyguard.github.model.DependencyUpdate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.List;

@Service
public class AnalysisQueueService {

    private final ObjectMapper objectMapper;
    private final Path queueFile;

    public AnalysisQueueService(
            ObjectMapper objectMapper,
            @Value("${supplyguard.analysis.queue-file:data/github_dependency_update_queue.jsonl}") String queueFile) {
        this.objectMapper = objectMapper;
        this.queueFile = Path.of(queueFile);
    }

    public synchronized void enqueue(List<DependencyUpdate> updates) {
        if (updates == null || updates.isEmpty()) {
            return;
        }
        try {
            Path parent = queueFile.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            StringBuilder content = new StringBuilder();
            for (DependencyUpdate update : updates) {
                content.append(objectMapper.writeValueAsString(update)).append(System.lineSeparator());
            }
            Files.writeString(
                    queueFile,
                    content.toString(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND
            );
        } catch (Exception e) {
            throw new IllegalStateException("Unable to queue dependency-analysis requests", e);
        }
    }
}
