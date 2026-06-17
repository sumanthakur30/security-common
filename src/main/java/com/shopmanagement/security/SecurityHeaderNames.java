package com.shopmanagement.security;

public final class SecurityHeaderNames {

    public static final String TENANT_ID = "X-Tenant-Id";
    public static final String SHOP_ID = "X-Shop-Id";
    public static final String AUTH_ROLE = "X-Auth-Role";
    public static final String AUTH_USER = "X-Auth-User";
    public static final String AUTH_PERMISSIONS = "X-Auth-Permissions";
    public static final String INTERNAL_API_KEY = "X-Internal-Api-Key";
    /** Set by gateway-service on every proxied request; microservices may require it in production. */
    public static final String GATEWAY_VERIFIED = "X-Gateway-Verified";

    private SecurityHeaderNames() {
    }
}
