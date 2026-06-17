package com.shopmanagement.security;

import java.io.IOException;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    private final JwtSecurityProperties properties;
    private final JwtTokenParser tokenParser;

    public JwtAuthenticationFilter(JwtSecurityProperties properties) {
        this.properties = properties;
        if (properties.isEnforce() && (properties.getSecret() == null || properties.getSecret().isBlank())) {
            throw new IllegalStateException("security.jwt.secret is required when security.jwt.enforce=true");
        }
        this.tokenParser = properties.isEnforce() && properties.getSecret() != null && !properties.getSecret().isBlank()
                ? new JwtTokenParser(properties.getSecret())
                : null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!properties.isEnforce()) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = normalizedPath(request);
        if ("OPTIONS".equalsIgnoreCase(request.getMethod()) || isPublicPath(path)) {
            filterChain.doFilter(request, response);
            return;
        }

        if (isTrustedInternalCall(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            logAuthDenied(request, path, "missing_bearer");
            unauthorized(response);
            return;
        }

        JwtTokenParser.ParsedJwt jwt;
        try {
            jwt = tokenParser().parse(authHeader.substring(7).trim());
        } catch (Exception ex) {
            logAuthDenied(request, path, "invalid_token");
            unauthorized(response);
            return;
        }

        if (jwt.role() == null) {
            logAuthDenied(request, path, "missing_role");
            unauthorized(response);
            return;
        }
        if (!"SUPER_ADMIN".equals(jwt.role()) && (jwt.shopId() == null || jwt.shopId().isBlank())) {
            logAuthDenied(request, path, "missing_shop");
            unauthorized(response);
            return;
        }

        filterChain.doFilter(new TrustedAuthRequestWrapper(request, jwt), response);
    }

    private JwtTokenParser tokenParser() {
        if (tokenParser == null) {
            throw new IllegalStateException("JWT parser not initialized");
        }
        return tokenParser;
    }

    static boolean isStrippedAuthHeader(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase();
        return SecurityHeaderNames.AUTH_ROLE.toLowerCase().equals(lower)
                || SecurityHeaderNames.AUTH_USER.toLowerCase().equals(lower)
                || SecurityHeaderNames.AUTH_PERMISSIONS.toLowerCase().equals(lower);
    }

    private boolean isPublicPath(String path) {
        if (path.equals("/actuator/health") || path.equals("/actuator/info")) {
            return true;
        }
        if (!properties.isEnforce()) {
            if (path.startsWith("/swagger-ui")
                    || path.startsWith("/v3/api-docs")
                    || path.startsWith("/webjars")
                    || path.startsWith("/swagger-ui.html")) {
                return true;
            }
        }
        for (String prefix : properties.getPublicPathPrefixes()) {
            if (prefix != null && !prefix.isBlank() && path.startsWith(prefix.trim())) {
                return true;
            }
        }
        return false;
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

    private static void logAuthDenied(HttpServletRequest request, String path, String reason) {
        log.warn("JWT auth denied path={} reason={} requestId={} ip={}",
                path,
                reason,
                request.getHeader("X-Request-Id"),
                clientIp(request));
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            int comma = forwarded.indexOf(',');
            return (comma > 0 ? forwarded.substring(0, comma) : forwarded).trim();
        }
        return request.getRemoteAddr();
    }

    private static void unauthorized(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write("{\"message\":\"Unauthorized\"}");
    }
}
