package com.shopmanagement.security;

import com.shopmanagement.platform.common.FeatureCode;
import com.shopmanagement.platform.common.ModuleCode;

/** Resolves shop module/feature entitlements for {@link ModuleFeatureGateAspect}. */
public interface EntitlementGate {

    boolean isModuleEnabled(String shopId, ModuleCode module);

    boolean isFeatureEnabled(String shopId, FeatureCode feature);
}
