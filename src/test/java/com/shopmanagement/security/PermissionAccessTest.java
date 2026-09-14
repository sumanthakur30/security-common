package com.shopmanagement.security;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;

import org.junit.jupiter.api.Test;

class PermissionAccessTest {

    @Test
    void ownerBypassesAllChecks() {
        assertTrue(PermissionAccess.canDeleteBill("SHOP_OWNER", List.of()));
        assertTrue(PermissionAccess.canViewPurchaseRate("SHOP_OWNER", List.of()));
        assertTrue(PermissionAccess.canEditPurchaseRate("SUPER_ADMIN", List.of()));
    }

    @Test
    void manageOrdersImpliesViewCreateEditButNotDelete() {
        List<String> billing = List.of("MANAGE_ORDERS");
        assertTrue(PermissionAccess.canViewBill("SHOP_EMPLOYEE", billing));
        assertTrue(PermissionAccess.canCreateBill("SHOP_EMPLOYEE", billing));
        assertTrue(PermissionAccess.canEditBill("SHOP_EMPLOYEE", billing));
        assertFalse(PermissionAccess.canDeleteBill("SHOP_EMPLOYEE", billing));
    }

    @Test
    void manageProductsDoesNotImplyPurchaseRate() {
        List<String> catalog = List.of("MANAGE_PRODUCTS");
        assertFalse(PermissionAccess.canViewPurchaseRate("SHOP_EMPLOYEE", catalog));
        assertFalse(PermissionAccess.canEditPurchaseRate("SHOP_EMPLOYEE", catalog));
    }

    @Test
    void managerCanViewPurchaseRateWithoutEditOrDelete() {
        List<String> manager = List.of("MANAGE_ORDERS", "PRODUCT_VIEW_PURCHASE_RATE");
        assertTrue(PermissionAccess.canEditBill("SHOP_EMPLOYEE", manager));
        assertTrue(PermissionAccess.canViewPurchaseRate("SHOP_EMPLOYEE", manager));
        assertFalse(PermissionAccess.canEditPurchaseRate("SHOP_EMPLOYEE", manager));
        assertFalse(PermissionAccess.canDeleteBill("SHOP_EMPLOYEE", manager));
    }

    @Test
    void unauthorizedCannotViewBill() {
        assertFalse(PermissionAccess.canViewBill("SHOP_EMPLOYEE", List.of("MANAGE_CUSTOMERS")));
        assertThrows(SecurityException.class,
                () -> PermissionAccess.requireDeleteBill("SHOP_EMPLOYEE", List.of("MANAGE_ORDERS")));
    }
}
