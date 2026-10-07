package com.supplyguard.github.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.supplyguard.github.model.DependencyUpdate;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class DependencyChangeDetector {

    private static final Set<String> DEPENDENCY_SECTIONS = Set.of(
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies"
    );

    private final ObjectMapper objectMapper;

    public DependencyChangeDetector(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public List<DependencyUpdate> detect(
            String repository,
            int pullRequestNumber,
            String manifestPath,
            String oldPackageJson,
            String newPackageJson,
            String oldLockFile,
            String newLockFile,
            String baseSha,
            String headSha,
            String action,
            String pullRequestUrl) {

        List<DependencyUpdate> updates = new ArrayList<>();

        JsonNode oldRoot = readJson(oldPackageJson);
        JsonNode newRoot = readJson(newPackageJson);

        if (oldRoot == null || newRoot == null) {
            return updates;
        }

        Map<String, String> oldDeps = collectDependencies(oldRoot);
        Map<String, String> newDeps = collectDependencies(newRoot);

        Map<String, String> oldResolved = resolveVersions(oldLockFile);
        Map<String, String> newResolved = resolveVersions(newLockFile);

        for (String packageName : newDeps.keySet()) {

            // Only consider dependencies that existed before.
            if (!oldDeps.containsKey(packageName)) {
                continue;
            }

            String oldSpec = oldDeps.get(packageName);
            String newSpec = newDeps.get(packageName);

            // No dependency declaration change.
            if (oldSpec.equals(newSpec)) {
                continue;
            }

            /*
             * Prefer exact resolved versions from package-lock.json.
             * If a resolved version is unavailable, fall back to the
             * declared version/range in package.json.
             */
            String oldVersion = oldResolved.get(packageName);
            String newVersion = newResolved.get(packageName);

            if (oldVersion == null) {
                oldVersion = declaredVersion(oldSpec);
            }

            /*
             * If the lockfile still contains the old resolved version,
             * but package.json declares a new version/range, use the
             * newly declared version as the update target.
             */
            if (newVersion == null || newVersion.equals(oldVersion)) {
                newVersion = declaredVersion(newSpec);
            }

            if (oldVersion == null || newVersion == null) {
                continue;
            }

            if (oldVersion.equals(newVersion)) {
                continue;
            }

            updates.add(new DependencyUpdate(
                    repository,
                    pullRequestNumber,
                    manifestPath,
                    packageName,
                    oldVersion,
                    newVersion,
                    baseSha,
                    headSha,
                    action,
                    pullRequestUrl
            ));
        }

        return updates;
    }

    private Map<String, String> collectDependencies(JsonNode root) {
        Map<String, String> result = new LinkedHashMap<>();

        for (String section : DEPENDENCY_SECTIONS) {

            JsonNode deps = root.get(section);

            if (deps == null || !deps.isObject()) {
                continue;
            }

            Iterator<Map.Entry<String, JsonNode>> fields = deps.fields();

            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();

                if (field.getValue().isTextual()) {
                    result.put(
                            field.getKey(),
                            field.getValue().asText()
                    );
                }
            }
        }

        return result;
    }

    private Map<String, String> resolveVersions(String lockFile) {
        Map<String, String> result = new LinkedHashMap<>();

        if (lockFile == null || lockFile.isBlank()) {
            return result;
        }

        JsonNode root = readJson(lockFile);

        if (root == null) {
            return result;
        }

        /*
         * npm lockfile v2/v3 format.
         */
        JsonNode packages = root.get("packages");

        if (packages != null && packages.isObject()) {

            Iterator<Map.Entry<String, JsonNode>> fields =
                    packages.fields();

            while (fields.hasNext()) {

                Map.Entry<String, JsonNode> field = fields.next();

                String path = field.getKey();
                JsonNode node = field.getValue();

                if (!path.startsWith("node_modules/")
                        || node == null
                        || !node.isObject()) {
                    continue;
                }

                String packageName =
                        path.substring("node_modules/".length());

                String version = text(node.get("version"));

                /*
                 * Ignore nested node_modules paths here.
                 * We only want top-level dependency resolutions.
                 */
                if (version != null
                        && !packageName.contains("/node_modules/")) {

                    result.put(packageName, version);
                }
            }
        }

        /*
         * npm lockfile v1 format.
         */
        JsonNode dependencies = root.get("dependencies");

        if (dependencies != null && dependencies.isObject()) {
            collectLegacyLockVersions(
                    dependencies,
                    result,
                    ""
            );
        }

        return result;
    }

    private void collectLegacyLockVersions(
            JsonNode node,
            Map<String, String> result,
            String prefix) {

        Iterator<Map.Entry<String, JsonNode>> fields =
                node.fields();

        while (fields.hasNext()) {

            Map.Entry<String, JsonNode> field =
                    fields.next();

            String packageName = prefix.isBlank()
                    ? field.getKey()
                    : prefix + "/node_modules/" + field.getKey();

            JsonNode entry = field.getValue();

            if (entry == null || !entry.isObject()) {
                continue;
            }

            String version = text(entry.get("version"));

            /*
             * Store top-level dependencies.
             */
            if (version != null && prefix.isBlank()) {
                result.put(field.getKey(), version);
            }

            JsonNode nested = entry.get("dependencies");

            if (nested != null && nested.isObject()) {
                collectLegacyLockVersions(
                        nested,
                        result,
                        packageName
                );
            }
        }
    }

    /*
     * Extract a concrete version when the dependency declaration
     * itself contains an exact semantic version.
     */
    private String declaredVersion(String spec) {

        if (spec == null) {
            return null;
        }

        String candidate = spec.trim();

        /*
         * Handle common npm range prefixes:
         *
         * ^4.8.4
         * ~4.8.4
         * =4.8.4
         * >=4.8.4
         */
        candidate = candidate.replaceFirst(
                "^[\\^~=<>&\\s]+",
                ""
        );

        if (candidate.matches(
                "\\d+\\.\\d+\\.\\d+(?:[-+][0-9A-Za-z.-]+)?"
        )) {
            return candidate;
        }

        return null;
    }

    private JsonNode readJson(String content) {

        if (content == null || content.isBlank()) {
            return null;
        }

        try {
            return objectMapper.readTree(content);
        } catch (Exception e) {
            return null;
        }
    }

    private String text(JsonNode node) {

        return node != null && node.isTextual()
                ? node.asText()
                : null;
    }
}