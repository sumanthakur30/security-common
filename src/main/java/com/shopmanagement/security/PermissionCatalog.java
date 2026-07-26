package com.shopmanagement.security;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Single source of truth for staff permission catalog and role defaults.
 * Consumed by auth-service (JWT enforcement SoT) and account-service (admin UX + write-through).
 * UI {@code staff-permissions.ts} must stay in sync with {@link #ALL}.
 */
public final class PermissionCatalog {

    public static final List<String> ALL = List.of(
            "MANAGE_PRODUCTS",
            "MANAGE_ORDERS",
            "MANAGE_STOCKS",
            "MANAGE_CUSTOMERS",
            "MANAGE_STAFF",
            "MANAGE_CONSULTATIONS",
            "VIEW_DOCTOR_DASHBOARD",
            "WRITE_PRESCRIPTION",
            "MANAGE_APPOINTMENTS",
            "MANAGE_QUEUE",
            "MANAGE_DOCTORS",
            "VIEW_PATIENT_HISTORY",
            "MANAGE_LAB_ORDERS",
            "MANAGE_LAB_RESULTS",
            /** Pathologist / senior tech: e-sign and release lab reports. */
            "RELEASE_LAB_REPORTS",
            /** Analyzer registry + channel map + import console. */
            "MANAGE_LAB_INSTRUMENTS",
            /** IQC lots, Westgard runs, lockouts, reagent rules, CC settlement. */
            "MANAGE_LAB_QC",
            /** CC / franchise nodes + home collection GPS routes. */
            "MANAGE_LAB_NETWORK",
            /** Microbiology cultures/AST + histopathology workflow. */
            "MANAGE_LAB_SPECIALTY",
            /** AI draft assist, FHIR export, ABHA patient links. */
            "MANAGE_LAB_ECOSYSTEM",
            "DISPENSE_MEDICINES",
            "IMPORT_PRODUCTS",
            "EXPORT_PRODUCTS",
            "SUBMIT_FEEDBACK",
            "PROCUREMENT_VIEW",
            "PROCUREMENT_RECEIVE",
            "PROCUREMENT_APPROVE",
            "PROCUREMENT_FINANCE",
            "MANAGE_FINANCE",
            "MANAGE_GST");

    private static final Set<String> ALL_SET = Set.copyOf(ALL);

    private static final List<String> EMPLOYEE_DEFAULTS = List.of(
            "MANAGE_ORDERS",
            "MANAGE_CUSTOMERS");

    private static final List<String> TRADE_PHARMACIST_DEFAULTS = List.of(
            "DISPENSE_MEDICINES",
            "MANAGE_ORDERS",
            "MANAGE_CUSTOMERS",
            "MANAGE_STOCKS");

    /** Aligns with UI accountant preset: finance + GST + procurement view/finance + orders/customers. */
    private static final List<String> TRADE_ACCOUNTANT_DEFAULTS = List.of(
            "PROCUREMENT_VIEW",
            "PROCUREMENT_FINANCE",
            "MANAGE_ORDERS",
            "MANAGE_CUSTOMERS",
            "MANAGE_FINANCE",
            "MANAGE_GST");

    private PermissionCatalog() {
    }

    public static boolean isKnown(String permission) {
        if (permission == null || permission.isBlank()) {
            return false;
        }
        return ALL_SET.contains(permission.trim().toUpperCase(Locale.ROOT));
    }

    public static List<String> defaultsForRole(String role) {
        String normalizedRole = role == null ? "" : role.trim().toUpperCase(Locale.ROOT);
        return switch (normalizedRole) {
            case "SUPER_ADMIN", "SHOP_OWNER" -> ALL;
            case "TRADE_PHARMACIST" -> TRADE_PHARMACIST_DEFAULTS;
            case "TRADE_ACCOUNTANT" -> TRADE_ACCOUNTANT_DEFAULTS;
            case "SHOP_EMPLOYEE", "FIELD_FORCE_PROMOTER", "FIELD_FORCE_SALESMAN" -> EMPLOYEE_DEFAULTS;
            default -> List.of();
        };
    }

    /**
     * Dedupes and uppercases; throws {@link IllegalArgumentException} for unknown permissions.
     */
    public static List<String> normalize(List<String> permissions) {
        if (permissions == null) {
            return List.of();
        }
        Set<String> normalized = new LinkedHashSet<>();
        for (String permission : permissions) {
            if (permission == null || permission.isBlank()) {
                continue;
            }
            String upper = permission.trim().toUpperCase(Locale.ROOT);
            if (!ALL_SET.contains(upper)) {
                throw new IllegalArgumentException("Unsupported permission: " + permission);
            }
            normalized.add(upper);
        }
        return List.copyOf(normalized);
    }

    /** Mutable copy for account-service callers that historically used ArrayList. */
    public static List<String> normalizeMutable(List<String> permissions) {
        return new ArrayList<>(normalize(permissions));
    }
}
