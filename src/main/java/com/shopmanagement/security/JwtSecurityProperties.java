package com.shopmanagement.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.jwt")
public class JwtSecurityProperties {

    /**
     * When true, microservices require a valid Bearer JWT and ignore spoofed auth headers.
     * Disable only for local troubleshooting ({@code security.jwt.enforce=false}).
     */
    private boolean enforce = true;

    private String secret = "";

    /**
     * Optional shared key for trusted service-to-service calls (e.g. internal conversion APIs).
     */
    private String internalApiKey = "";

    /**
     * Path prefixes that skip JWT (actuator/swagger are always skipped).
     */
    private List<String> publicPathPrefixes = new ArrayList<>();

    /**
     * When true, reject requests that did not pass through gateway-service (missing {@link SecurityHeaderNames#GATEWAY_VERIFIED}).
     * Service-to-service calls with {@link SecurityHeaderNames#INTERNAL_API_KEY} are still allowed.
     */
    private boolean gatewayEnforce = false;

    public boolean isEnforce() {
        return enforce;
    }

    public void setEnforce(boolean enforce) {
        this.enforce = enforce;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public String getInternalApiKey() {
        return internalApiKey;
    }

    public void setInternalApiKey(String internalApiKey) {
        this.internalApiKey = internalApiKey;
    }

    public List<String> getPublicPathPrefixes() {
        return publicPathPrefixes;
    }

    public void setPublicPathPrefixes(List<String> publicPathPrefixes) {
        this.publicPathPrefixes = publicPathPrefixes == null ? new ArrayList<>() : publicPathPrefixes;
    }

    public boolean isGatewayEnforce() {
        return gatewayEnforce;
    }

    public void setGatewayEnforce(boolean gatewayEnforce) {
        this.gatewayEnforce = gatewayEnforce;
    }
}
