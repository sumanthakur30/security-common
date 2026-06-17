package com.shopmanagement.security;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

public final class JwtTokenParser {

    private final SecretKey secretKey;

    public JwtTokenParser(String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalArgumentException("security.jwt.secret must be configured");
        }
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    public ParsedJwt parse(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return new ParsedJwt(
                normalizeClaim(claims.getSubject()),
                normalizeClaim(claims.get("role")),
                normalizeTenantId(claims.get("tenantId")),
                normalizeShopId(claims.get("shopId")),
                normalizePermissions(claims.get("permissions")));
    }

    private static String normalizeClaim(Object claim) {
        if (claim == null) {
            return null;
        }
        String value = String.valueOf(claim).trim();
        return value.isBlank() ? null : value.toUpperCase();
    }

    private static String normalizeShopId(Object shopClaim) {
        if (shopClaim == null) {
            return null;
        }
        String value = String.valueOf(shopClaim).trim();
        return value.isBlank() ? null : value;
    }

    private static String normalizeTenantId(Object tenantClaim) {
        if (tenantClaim == null) {
            return null;
        }
        if (tenantClaim instanceof Number number) {
            return Long.toString(number.longValue());
        }
        String value = String.valueOf(tenantClaim).trim();
        if (value.isEmpty()) {
            return null;
        }
        try {
            return Long.toString(Long.parseLong(value));
        } catch (NumberFormatException ignored) {
            try {
                return Long.toString((long) Double.parseDouble(value));
            } catch (NumberFormatException ignored2) {
                return value;
            }
        }
    }

    private static String normalizePermissions(Object permissionsClaim) {
        if (permissionsClaim == null) {
            return null;
        }
        if (permissionsClaim instanceof Iterable<?> iterable) {
            List<String> values = new ArrayList<>();
            for (Object value : iterable) {
                String normalized = normalizeClaim(value);
                if (normalized != null) {
                    values.add(normalized);
                }
            }
            return values.isEmpty() ? null : String.join(",", values);
        }
        return normalizeClaim(permissionsClaim);
    }

    public record ParsedJwt(
            String username,
            String role,
            String tenantId,
            String shopId,
            String permissions) {
    }
}
