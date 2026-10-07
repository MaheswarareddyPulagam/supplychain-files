package com.supplyguard.github.model;

public record DependencyUpdate(
        String repository,
        int pullRequestNumber,
        String manifestPath,
        String packageName,
        String oldVersion,
        String newVersion,
        String baseSha,
        String headSha,
        String action,
        String pullRequestUrl
) {}
