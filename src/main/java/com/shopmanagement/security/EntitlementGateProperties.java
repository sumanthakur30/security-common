package com.shopmanagement.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "security.entitlement-gate")
public class EntitlementGateProperties {

    /**
     * When false, {@link RemoteEntitlementGateClient} allows all modules/features (local dev).
     */
    private boolean enforce = false;

    private String shopServiceBaseUrl = "";

    private String internalApiKey = "";

    public boolean isEnforce() {
        return enforce;
    }

    public void setEnforce(boolean enforce) {
        this.enforce = enforce;
    }

    public String getShopServiceBaseUrl() {
        return shopServiceBaseUrl;
    }

    public void setShopServiceBaseUrl(String shopServiceBaseUrl) {
        this.shopServiceBaseUrl = shopServiceBaseUrl == null ? "" : shopServiceBaseUrl.trim();
    }

    public String getInternalApiKey() {
        return internalApiKey;
    }

    public void setInternalApiKey(String internalApiKey) {
        this.internalApiKey = internalApiKey == null ? "" : internalApiKey.trim();
    }
}
