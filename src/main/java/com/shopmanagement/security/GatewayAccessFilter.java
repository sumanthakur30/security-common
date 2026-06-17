package com.shopmanagement.security;

import java.io.IOException;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Blocks direct microservice port access in production when {@code security.gateway.enforce=true}.
 * Requests must carry {@link SecurityHeaderNames#GATEWAY_VERIFIED} from gateway-service,
 * unless they use a trusted internal API key or hit actuator/swagger paths.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 1)
public class GatewayAccessFilter extends OncePerRequestFilter {

    private final JwtSecurityProperties properties;

    public GatewayAccessFilter(JwtSecurityProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!properties.isGatewayEnforce()) {
            filterChain.doFilter(request, response);
            return;
        }
        String path = normalizedPath(request);
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())
                || path.startsWith("/actuator")
                || path.startsWith("/swagger")
                || path.startsWith("/v3/api-docs")) {
            filterChain.doFilter(request, response);
            return;
        }
        if (isTrustedInternalCall(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        String verified = request.getHeader(SecurityHeaderNames.GATEWAY_VERIFIED);
        if (verified == null || verified.isBlank()) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.setContentType("application/json");
            response.getWriter().write("{\"message\":\"Direct service access is blocked; use the API gateway\"}");
            return;
        }
        filterChain.doFilter(request, response);
    }

    private boolean isTrustedInternalCall(HttpServletRequest request) {
        String expected = properties.getInternalApiKey();
        if (expected == null || expected.isBlank()) {
            return false;
        }
        String provided = request.getHeader(SecurityHeaderNames.INTERNAL_API_KEY);
        return expected.equals(provided);
    }

    private static String normalizedPath(HttpServletRequest request) {
        String uri = request.getRequestURI();
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            uri = uri.substring(context.length());
        }
        if (uri.length() > 1 && uri.endsWith("/")) {
            uri = uri.substring(0, uri.length() - 1);
        }
        return uri.isEmpty() ? "/" : uri;
    }
}
