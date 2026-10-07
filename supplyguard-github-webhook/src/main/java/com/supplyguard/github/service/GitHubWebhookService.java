package com.supplyguard.github.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.supplyguard.github.model.DependencyUpdate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class GitHubWebhookService {

    private static final List<String> SUPPORTED_ACTIONS = List.of(
            "opened",
            "synchronize",
            "reopened"
    );

    private final ObjectMapper objectMapper;
    private final GitHubApiClient gitHubApiClient;
    private final DependencyChangeDetector dependencyChangeDetector;
    private final AnalysisQueueService analysisQueueService;

    public GitHubWebhookService(
            ObjectMapper objectMapper,
            GitHubApiClient gitHubApiClient,
            DependencyChangeDetector dependencyChangeDetector,
            AnalysisQueueService analysisQueueService) {
        this.objectMapper = objectMapper;
        this.gitHubApiClient = gitHubApiClient;
        this.dependencyChangeDetector = dependencyChangeDetector;
        this.analysisQueueService = analysisQueueService;
    }

    public boolean isSupportedAction(String action) {
        return SUPPORTED_ACTIONS.contains(action);
    }

    @Async("webhookTaskExecutor")
    public void processPullRequest(String body) {
        try {
            JsonNode root = objectMapper.readTree(body);
            JsonNode repoNode = root.path("repository");
            JsonNode prNode = root.path("pull_request");

            String fullName = repoNode.path("full_name").asText("");
            int slash = fullName.indexOf('/');
            if (slash <= 0 || slash == fullName.length() - 1) {
                return;
            }
            String owner = fullName.substring(0, slash);
            String repo = fullName.substring(slash + 1);

            int pullNumber = root.path("number").asInt(0);
            String action = root.path("action").asText("");
            String baseSha = prNode.path("base").path("sha").asText("");
            String headSha = prNode.path("head").path("sha").asText("");
            String pullRequestUrl = prNode.path("html_url").asText("");

            List<JsonNode> changedFiles = gitHubApiClient.listPullRequestFiles(owner, repo, pullNumber);
            List<DependencyUpdate> updates = new ArrayList<>();

            for (JsonNode file : changedFiles) {
                String path = file.path("filename").asText("");
                if (!isDependencyManifest(path)) {
                    continue;
                }

                String oldContent = gitHubApiClient.getRawFile(owner, repo, path, baseSha);
                String newContent = gitHubApiClient.getRawFile(owner, repo, path, headSha);
                if (oldContent.isBlank() || newContent.isBlank()) {
                    continue;
                }

                if ("package.json".equals(fileName(path))) {
                    String lockPath = findBestLockPath(changedFiles, path);
                    String oldLock = lockPath == null ? "" : gitHubApiClient.getRawFile(owner, repo, lockPath, baseSha);
                    String newLock = lockPath == null ? "" : gitHubApiClient.getRawFile(owner, repo, lockPath, headSha);
                    System.out.printf(
        "[SupplyGuard] Manifest: %s | Lockfile: %s | Base lock loaded: %s | Head lock loaded: %s%n",
        path,
        lockPath,
        !oldLock.isBlank(),
        !newLock.isBlank()
);
      System.out.printf(
        "[SupplyGuard] Detector input: manifest=%s | oldContentLength=%d | newContentLength=%d | oldLockLength=%d | newLockLength=%d%n",
        path,
        oldContent.length(),
        newContent.length(),
        oldLock.length(),
        newLock.length()
);
                    updates.addAll(dependencyChangeDetector.detect(
                            fullName, pullNumber, path,
                            oldContent, newContent,
                            oldLock, newLock,
                            baseSha, headSha, action, pullRequestUrl
                    ));
                }
            }

            analysisQueueService.enqueue(updates);
            System.out.printf(
                    "[SupplyGuard] %s PR #%d -> dependency updates detected: %d%n",
                    fullName, pullNumber, updates.size()
            );
            updates.forEach(update -> System.out.printf(
                    "  %s %s -> %s%n",
                    update.packageName(), update.oldVersion(), update.newVersion()
            ));
        } catch (Exception e) {
            System.err.println("[SupplyGuard] GitHub PR processing failed: " + e.getMessage());
        }
    }

    private boolean isDependencyManifest(String path) {
        return path.endsWith("/package.json")
                || "package.json".equals(path)
                || path.endsWith("/package-lock.json")
                || "package-lock.json".equals(path)
                || path.endsWith("/npm-shrinkwrap.json")
                || "npm-shrinkwrap.json".equals(path);
    }

    private String findBestLockPath(List<JsonNode> files, String packageJsonPath) {
    String directory = packageJsonPath.contains("/")
            ? packageJsonPath.substring(0, packageJsonPath.lastIndexOf('/') + 1)
            : "";

    String[] candidates = {
            directory + "package-lock.json",
            directory + "npm-shrinkwrap.json"
    };

    // First prefer a lockfile that was changed in the PR.
    for (String candidate : candidates) {
        for (JsonNode file : files) {
            if (candidate.equals(file.path("filename").asText(""))) {
                return candidate;
            }
        }
    }

    // If the lockfile was not changed, still use the conventional
    // lockfile path so we can compare base and head versions.
    return candidates[0];
}

    private String fileName(String path) {
        int slash = path.lastIndexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : path;
    }
}
