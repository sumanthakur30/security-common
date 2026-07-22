package com.shopmanagement.security;

import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;

/**
 * Shared CSV ↔ list resolution for auth (JWT SoT) and account (admin UX SoT).
 * Blank CSV falls back to {@link PermissionCatalog#defaultsForRole(String)}.
 */
public final class PermissionCsv {

    private PermissionCsv() {
    }

    /**
     * Resolve stored CSV (or null/blank) into a normalized permission list for the given role.
     */
    public static List<String> resolve(String csv, String role) {
        if (csv == null || csv.isBlank()) {
            return PermissionCatalog.defaultsForRole(role);
        }
        List<String> raw = Arrays.stream(csv.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .map(s -> s.toUpperCase(Locale.ROOT))
                .collect(Collectors.toList());
        return PermissionCatalog.normalize(raw);
    }

    /** Serialize a normalized list to CSV (null if empty). */
    public static String serialize(List<String> permissions) {
        List<String> normalized = PermissionCatalog.normalize(permissions);
        if (normalized.isEmpty()) {
            return null;
        }
        return String.join(",", normalized);
    }

    /** Compare two permission lists ignoring order. */
    public static boolean sameSet(List<String> a, List<String> b) {
        if (a == null && b == null) {
            return true;
        }
        if (a == null || b == null) {
            return false;
        }
        return PermissionCatalog.normalize(a).equals(PermissionCatalog.normalize(b));
    }
}
