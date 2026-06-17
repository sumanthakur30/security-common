package com.shopmanagement.security;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.server.ResponseStatusException;

import com.shopmanagement.platform.common.FeatureCode;
import com.shopmanagement.platform.common.RequiresFeature;
import com.shopmanagement.platform.common.RequiresModule;

import jakarta.servlet.http.HttpServletRequest;

@Aspect
@Order(100)
public class ModuleFeatureGateAspect {

    private final EntitlementGate entitlementGate;

    public ModuleFeatureGateAspect(EntitlementGate entitlementGate) {
        this.entitlementGate = entitlementGate;
    }

    @Around("@annotation(requiresModule)")
    public Object enforceModule(ProceedingJoinPoint joinPoint, RequiresModule requiresModule) throws Throwable {
        assertModule(requiresModule.value());
        return joinPoint.proceed();
    }

    @Around("@within(requiresModule)")
    public Object enforceClassModule(ProceedingJoinPoint joinPoint, RequiresModule requiresModule) throws Throwable {
        assertModule(requiresModule.value());
        return joinPoint.proceed();
    }

    @Around("@annotation(requiresFeature)")
    public Object enforceFeature(ProceedingJoinPoint joinPoint, RequiresFeature requiresFeature) throws Throwable {
        assertFeature(requiresFeature.value());
        return joinPoint.proceed();
    }

    @Around("@within(requiresFeature)")
    public Object enforceClassFeature(ProceedingJoinPoint joinPoint, RequiresFeature requiresFeature) throws Throwable {
        assertFeature(requiresFeature.value());
        return joinPoint.proceed();
    }

    private void assertModule(com.shopmanagement.platform.common.ModuleCode module) {
        String shopId = requireShopId();
        if (!entitlementGate.isModuleEnabled(shopId, module)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Module not enabled: " + module.name());
        }
    }

    private void assertFeature(FeatureCode feature) {
        String shopId = requireShopId();
        if (!entitlementGate.isFeatureEnabled(shopId, feature)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Feature not enabled: " + feature.name());
        }
    }

    private static String requireShopId() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();
        if (!(attributes instanceof ServletRequestAttributes servletAttributes)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shop context is required");
        }
        HttpServletRequest request = servletAttributes.getRequest();
        String shopId = request.getHeader(SecurityHeaderNames.SHOP_ID);
        if (shopId == null || shopId.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Shop context is required");
        }
        return shopId.trim();
    }
}
