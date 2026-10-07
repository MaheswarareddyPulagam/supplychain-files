package com.supplyguard.github.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

import java.net.URI;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

@Component
public class GitHubApiClient {

    private final RestClient restClient;
    private final ObjectMapper objectMapper;
    private final String token;
    private final String apiVersion;
    private final String apiBaseUrl;

    public GitHubApiClient(
            ObjectMapper objectMapper,
            @Value("${supplyguard.github.token:}") String token,
            @Value("${supplyguard.github.api-version:2026-03-10}") String apiVersion,
            @Value("${supplyguard.github.api-base-url:https://api.github.com}") String apiBaseUrl) {
        this.objectMapper = objectMapper;
        this.token = token == null ? "" : token;
        this.apiVersion = apiVersion;
        this.apiBaseUrl = apiBaseUrl;
        this.restClient = RestClient.builder().build();
    }

    public List<JsonNode> listPullRequestFiles(String owner, String repo, int pullNumber) {
        List<JsonNode> files = new ArrayList<>();
        for (int page = 1; page <= 30; page++) {
            URI uri = UriComponentsBuilder.fromUriString(apiBaseUrl)
                    .path("/repos/{owner}/{repo}/pulls/{number}/files")
                    .queryParam("per_page", 100)
                    .queryParam("page", page)
                    .build(owner, repo, pullNumber);

            JsonNode response = getJson(uri);
            if (response == null || !response.isArray() || response.isEmpty()) {
                break;
            }
            response.forEach(files::add);
            if (response.size() < 100) {
                break;
            }
        }
        return files;
    }

    public String getRawFile(String owner, String repo, String path, String ref) {
        String encodedPath = UriUtils.encodePath(path, java.nio.charset.StandardCharsets.UTF_8);
        URI uri = UriComponentsBuilder.fromUriString(apiBaseUrl)
                .path("/repos/{owner}/{repo}/contents/")
                .path(encodedPath)
                .queryParam("ref", ref)
                .buildAndExpand(owner, repo)
                .toUri();

        try {
            String raw = restClient.get()
                    .uri(uri)
                    .headers(this::setHeaders)
                    .accept(MediaType.valueOf("application/vnd.github.raw+json"))
                    .retrieve()
                    .body(String.class);
            return raw == null ? "" : raw;
        } catch (Exception e) {
            return "";
        }
    }

    private JsonNode getJson(URI uri) {
        try {
            String body = restClient.get()
                    .uri(uri)
                    .headers(this::setHeaders)
                    .accept(MediaType.APPLICATION_JSON)
                    .retrieve()
                    .body(String.class);
            return body == null ? null : objectMapper.readTree(body);
        } catch (Exception e) {
            return null;
        }
    }

    private void setHeaders(HttpHeaders headers) {
        headers.set(HttpHeaders.ACCEPT, "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", apiVersion);
        if (!token.isBlank()) {
            headers.setBearerAuth(token);
        }
        headers.set(HttpHeaders.USER_AGENT, "SupplyGuardAI-GitHub-Webhook/0.1");
    }
}
