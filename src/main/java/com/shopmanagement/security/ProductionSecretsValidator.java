package com.shopmanagement.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;

/**
 * Fails fast in production when known-insecure default secrets are still configured.
 */
public class ProductionSecretsValidator {

    private static final Set<String> INSECURE_JWT_SECRETS = Set.of(
            "01234567890123456789012345678901",
            "CHANGE_ME_at_least_32_chars_for_hs256____");

    private static final Set<String> INSECURE_INVITE_KEYS = Set.of(
            "dev-invite-key-change-in-production",
            "CHANGE_ME_invite_internal_key________");

    private static final Set<String> INSECURE_ADMIN_KEYS = Set.of(
            "dev-shop-admin-key",
            "CHANGE_ME_shop_admin_api_key_______________");

    private final Environment environment;

    public ProductionSecretsValidator(Environment environment) {
        this.environment = environment;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void validateOnStartup() {
        if (!isProdProfile()) {
            return;
        }
        List<String> violations = new ArrayList<>();
        check(violations, "SECURITY_JWT_SECRET", "security.jwt.secret", INSECURE_JWT_SECRETS);
        check(violations, "SECURITY_INVITE_INTERNAL_KEY", "security.invite.internal-key", INSECURE_INVITE_KEYS);
        check(violations, "SHOP_ADMIN_API_KEY", "shop.integration.admin-api-key", INSECURE_ADMIN_KEYS);
        if (!violations.isEmpty()) {
            throw new IllegalStateException(
                    "Production startup blocked — rotate insecure secrets: " + String.join("; ", violations));
        }
    }

    private void check(List<String> violations, String envName, String propertyName, Set<String> insecureValues) {
        String value = firstNonBlank(
                environment.getProperty(envName),
                environment.getProperty(propertyName));
        if (value == null || value.isBlank()) {
            violations.add(envName + " is missing");
            return;
        }
        if (insecureValues.contains(value.trim())) {
            violations.add(envName + " uses an insecure default");
        }
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value;
            }
        }
        return null;
    }

    private boolean isProdProfile() {
        for (String profile : environment.getActiveProfiles()) {
            if ("prod".equalsIgnoreCase(profile)) {
                return true;
            }
        }
        return false;
    }
}
