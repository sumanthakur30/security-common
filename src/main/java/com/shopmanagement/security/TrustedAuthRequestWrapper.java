package com.shopmanagement.security;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

/**
 * Replaces untrusted inbound auth/tenant headers with values extracted from a verified JWT.
 */
public class TrustedAuthRequestWrapper extends HttpServletRequestWrapper {

    private final Map<String, String> trustedHeaders = new HashMap<>();

    public TrustedAuthRequestWrapper(HttpServletRequest request, JwtTokenParser.ParsedJwt jwt) {
        super(request);
        applyJwtClaims(request, jwt);
    }

    private void applyJwtClaims(HttpServletRequest request, JwtTokenParser.ParsedJwt jwt) {
        String role = jwt.role();
        String shopId = jwt.shopId();
        String tenantId = jwt.tenantId();

        if ("SUPER_ADMIN".equals(role)) {
            String incomingShop = trimHeader(request.getHeader(SecurityHeaderNames.SHOP_ID));
            if (incomingShop != null) {
                shopId = incomingShop;
            }
            String incomingTenant = trimHeader(request.getHeader(SecurityHeaderNames.TENANT_ID));
            if (incomingTenant != null) {
                tenantId = incomingTenant;
            }
        } else if (shopId == null) {
            shopId = trimHeader(request.getHeader(SecurityHeaderNames.SHOP_ID));
            tenantId = tenantId != null ? tenantId : trimHeader(request.getHeader(SecurityHeaderNames.TENANT_ID));
        }

        if (tenantId == null || tenantId.isBlank()) {
            tenantId = shopId;
        }

        put(SecurityHeaderNames.TENANT_ID, tenantId);
        put(SecurityHeaderNames.SHOP_ID, shopId);
        put(SecurityHeaderNames.AUTH_ROLE, role);
        put(SecurityHeaderNames.AUTH_USER, jwt.username());
        put(SecurityHeaderNames.AUTH_PERMISSIONS, jwt.permissions());
    }

    private void put(String name, String value) {
        if (value != null && !value.isBlank()) {
            trustedHeaders.put(name.toLowerCase(), value);
        }
    }

    private static String trimHeader(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    @Override
    public String getHeader(String name) {
        String trusted = trustedHeaders.get(name.toLowerCase());
        if (trusted != null) {
            return trusted;
        }
        if (isStrippedAuthHeader(name)) {
            return null;
        }
        return super.getHeader(name);
    }

    @Override
    public Enumeration<String> getHeaders(String name) {
        String trusted = trustedHeaders.get(name.toLowerCase());
        if (trusted != null) {
            return Collections.enumeration(List.of(trusted));
        }
        if (isStrippedAuthHeader(name)) {
            return Collections.emptyEnumeration();
        }
        return super.getHeaders(name);
    }

    @Override
    public Enumeration<String> getHeaderNames() {
        List<String> names = Collections.list(super.getHeaderNames());
        names.removeIf(JwtAuthenticationFilter::isStrippedAuthHeader);
        for (String trustedName : trustedHeaders.keySet()) {
            if (!names.contains(trustedName)) {
                names.add(trustedName);
            }
        }
        return Collections.enumeration(names);
    }

    private static boolean isStrippedAuthHeader(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase();
        return SecurityHeaderNames.AUTH_ROLE.toLowerCase().equals(lower)
                || SecurityHeaderNames.AUTH_USER.toLowerCase().equals(lower)
                || SecurityHeaderNames.AUTH_PERMISSIONS.toLowerCase().equals(lower);
    }
}
