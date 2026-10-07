package com.supplyguard.github.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.supplyguard.github.model.DependencyUpdate;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DependencyChangeDetectorTest {

    private final DependencyChangeDetector detector = new DependencyChangeDetector(new ObjectMapper());

    @Test
    void detectsExactPackageJsonDependencyUpdate() {
        String oldJson = """
                {"dependencies":{"express":"4.18.2"}}
                """;
        String newJson = """
                {"dependencies":{"express":"4.21.0"}}
                """;

        List<DependencyUpdate> result = detector.detect(
                "owner/repo", 42, "package.json",
                oldJson, newJson, "", "",
                "base", "head", "synchronize", "https://github.com/owner/repo/pull/42"
        );

        assertEquals(1, result.size());
        assertEquals("express", result.getFirst().packageName());
        assertEquals("4.18.2", result.getFirst().oldVersion());
        assertEquals("4.21.0", result.getFirst().newVersion());
    }

    @Test
    void resolvesRangeChangesFromPackageLock() {
        String oldJson = """
                {"dependencies":{"lodash":"^4.17.20"}}
                """;
        String newJson = """
                {"dependencies":{"lodash":"^4.17.21"}}
                """;
        String oldLock = """
                {"packages":{"":{"dependencies":{"lodash":"^4.17.20"}},"node_modules/lodash":{"version":"4.17.20"}}}
                """;
        String newLock = """
                {"packages":{"":{"dependencies":{"lodash":"^4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}
                """;

        List<DependencyUpdate> result = detector.detect(
                "owner/repo", 42, "package.json",
                oldJson, newJson, oldLock, newLock,
                "base", "head", "synchronize", "https://github.com/owner/repo/pull/42"
        );

        assertEquals(1, result.size());
        assertEquals("4.17.20", result.getFirst().oldVersion());
        assertEquals("4.17.21", result.getFirst().newVersion());
    }
   @Test
void detectsDeclaredRangeChangeWhenLockfileResolvedVersionIsUnchanged() {
    String oldJson = """
            {"dependencies":{"socket.io":"^4.8.3"}}
            """;

    String newJson = """
            {"dependencies":{"socket.io":"^4.8.4"}}
            """;

    String oldLock = """
            {
              "packages": {
                "": {
                  "dependencies": {
                    "socket.io": "^4.8.3"
                  }
                },
                "node_modules/socket.io": {
                  "version": "4.8.3"
                }
              }
            }
            """;

    String newLock = """
            {
              "packages": {
                "": {
                  "dependencies": {
                    "socket.io": "^4.8.4"
                  }
                },
                "node_modules/socket.io": {
                  "version": "4.8.3"
                }
              }
            }
            """;

    List<DependencyUpdate> result = detector.detect(
            "owner/repo", 42, "server/package.json",
            oldJson, newJson, oldLock, newLock,
            "base", "head", "synchronize",
            "https://github.com/owner/repo/pull/42"
    );

    assertEquals(1, result.size());
    assertEquals("socket.io", result.getFirst().packageName());
    assertEquals("4.8.3", result.getFirst().oldVersion());
    assertEquals("4.8.4", result.getFirst().newVersion());
}
    @Test
    void doesNotCreateUpdateForNewDependency() {
        String oldJson = """
   {"dependencies":{}}
        """;
String newJson = """
        {"dependencies":{"axios":"1.8.0"}}
        """;
        List<DependencyUpdate> result = detector.detect(
                "owner/repo", 42, "package.json",
                oldJson, newJson, "", "",
                "base", "head", "opened", "https://github.com/owner/repo/pull/42"
        );

        assertTrue(result.isEmpty());
    }
}
