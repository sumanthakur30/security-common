package com.shopmanagement.security;

import java.util.Collection;
import java.util.Locale;

/**
 * Central staff authorization checks. Shop owner and super admin are privileged
 * and pass every permission check; other roles use assigned keys.
 */
public final class PermissionAccess {

    public static final String BILL_VIEW = "BILL_VIEW";
    public static final String BILL_CREATE = "BILL_CREATE";
    public static final String BILL_EDIT = "BILL_EDIT";
    public static final String BILL_DELETE = "BILL_DELETE";
    public static final String PRODUCT_VIEW_PURCHASE_RATE = "PRODUCT_VIEW_PURCHASE_RATE";
    public static final String PRODUCT_EDIT_PURCHASE_RATE = "PRODUCT_EDIT_PURCHASE_RATE";
    public static final String MANAGE_ORDERS = "MANAGE_ORDERS";

    private PermissionAccess() {
    }

    public static boolean isPrivileged(String role) {
        if (role == null || role.isBlank()) {
            return false;
        }
        String normalized = role.trim().toUpperCase(Locale.ROOT);
        return "SUPER_ADMIN".equals(normalized) || "SHOP_OWNER".equals(normalized);
    }

    public static boolean hasAny(String role, Collection<String> granted, String... keys) {
        if (isPrivileged(role)) {
            return true;
        }
        if (keys == null || keys.length == 0 || granted == null || granted.isEmpty()) {
            return false;
        }
        for (String key : keys) {
            if (key == null || key.isBlank()) {
                continue;
            }
            String upper = key.trim().toUpperCase(Locale.ROOT);
            for (String held : granted) {
                if (held != null && upper.equals(held.trim().toUpperCase(Locale.ROOT))) {
                    return true;
                }
            }
        }
        return false;
    }

    public static void requireAny(String role, Collection<String> granted, String... keys) {
        if (!hasAny(role, granted, keys)) {
            String label = keys == null || keys.length == 0 ? "required permission" : String.join(" or ", keys);
            throw new SecurityException("Forbidden: missing permission " + label);
        }
    }

    public static boolean canViewBill(String role, Collection<String> granted) {
        return hasAny(role, granted, BILL_VIEW, MANAGE_ORDERS);
    }

    public static boolean canCreateBill(String role, Collection<String> granted) {
        return hasAny(role, granted, BILL_CREATE, MANAGE_ORDERS);
    }

    public static boolean canEditBill(String role, Collection<String> granted) {
        return hasAny(role, granted, BILL_EDIT, MANAGE_ORDERS);
    }

    public static boolean canDeleteBill(String role, Collection<String> granted) {
        return hasAny(role, granted, BILL_DELETE);
    }

    public static boolean canViewPurchaseRate(String role, Collection<String> granted) {
        return hasAny(role, granted, PRODUCT_VIEW_PURCHASE_RATE);
    }

    public static boolean canEditPurchaseRate(String role, Collection<String> granted) {
        return hasAny(role, granted, PRODUCT_EDIT_PURCHASE_RATE);
    }

    public static void requireViewBill(String role, Collection<String> granted) {
        if (!canViewBill(role, granted)) {
            throw new SecurityException("Forbidden: missing permission BILL_VIEW or MANAGE_ORDERS");
        }
    }

    public static void requireCreateBill(String role, Collection<String> granted) {
        if (!canCreateBill(role, granted)) {
            throw new SecurityException("Forbidden: missing permission BILL_CREATE or MANAGE_ORDERS");
        }
    }

    public static void requireEditBill(String role, Collection<String> granted) {
        if (!canEditBill(role, granted)) {
            throw new SecurityException("Forbidden: missing permission BILL_EDIT or MANAGE_ORDERS");
        }
    }

    public static void requireDeleteBill(String role, Collection<String> granted) {
        if (!canDeleteBill(role, granted)) {
            throw new SecurityException("Forbidden: missing permission BILL_DELETE");
        }
    }

    public static void requireViewPurchaseRate(String role, Collection<String> granted) {
        if (!canViewPurchaseRate(role, granted)) {
            throw new SecurityException("Forbidden: missing permission PRODUCT_VIEW_PURCHASE_RATE");
        }
    }

    public static void requireEditPurchaseRate(String role, Collection<String> granted) {
        if (!canEditPurchaseRate(role, granted)) {
            throw new SecurityException("Forbidden: missing permission PRODUCT_EDIT_PURCHASE_RATE");
        }
    }
}
