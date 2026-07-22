package com.shopmanagement.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class PermissionCatalogTest {

    @Test
    void tradeAccountantIncludesFinanceAndGst() {
        List<String> perms = PermissionCatalog.defaultsForRole("TRADE_ACCOUNTANT");
        assertTrue(perms.contains("MANAGE_FINANCE"));
        assertTrue(perms.contains("MANAGE_GST"));
        assertTrue(perms.contains("PROCUREMENT_FINANCE"));
    }

    @Test
    void normalizeRejectsUnknown() {
        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> PermissionCatalog.normalize(List.of("MANAGE_ORDERS", "NOT_A_REAL_PERM")));
        assertTrue(ex.getMessage().contains("Unsupported permission"));
    }

    @Test
    void ownerGetsFullCatalog() {
        assertEquals(PermissionCatalog.ALL.size(), PermissionCatalog.defaultsForRole("SHOP_OWNER").size());
    }
}
