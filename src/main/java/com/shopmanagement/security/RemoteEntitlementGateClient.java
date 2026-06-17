package com.shopmanagement.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.shopmanagement.platform.common.FeatureCode;
import com.shopmanagement.platform.common.ModuleCode;

/** HTTP entitlement lookup against shop-service internal API. */
public class RemoteEntitlementGateClient implements EntitlementGate {

    private static final Logger log = LoggerFactory.getLogger(RemoteEntitlementGateClient.class);

    private final RestClient restClient;
    private final EntitlementGateProperties properties;

    public RemoteEntitlementGateClient(RestClient.Builder restClientBuilder, EntitlementGateProperties properties) {
        this.properties = properties;
        this.restClient = restClientBuilder.build();
    }

    @Override
    public boolean isModuleEnabled(String shopId, ModuleCode module) {
        if (!properties.isEnforce()) {
            return true;
        }
        return fetchEnabled("/api/v1/internal/features/shops/{shopId}/modules/enabled?code={code}", shopId, module.name());
    }

    @Override
    public boolean isFeatureEnabled(String shopId, FeatureCode feature) {
        if (!properties.isEnforce()) {
            return true;
        }
        return fetchEnabled("/api/v1/internal/features/shops/{shopId}/enabled?code={code}", shopId, feature.name());
    }

    private boolean fetchEnabled(String pathTemplate, String shopId, String code) {
        if (properties.getShopServiceBaseUrl().isBlank()) {
            log.warn("Entitlement gate enforced but security.entitlement-gate.shop-service-base-url is blank");
            return false;
        }
        try {
            Boolean enabled = restClient.get()
                    .uri(properties.getShopServiceBaseUrl() + pathTemplate, shopId, code)
                    .header(SecurityHeaderNames.INTERNAL_API_KEY, properties.getInternalApiKey())
                    .retrieve()
                    .body(Boolean.class);
            return Boolean.TRUE.equals(enabled);
        } catch (RestClientException ex) {
            log.warn("Entitlement lookup failed shopId={} code={}: {}", shopId, code, ex.getMessage());
            return false;
        }
    }
}
