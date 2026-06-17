package com.shopmanagement.security;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;

@AutoConfiguration
@EnableConfigurationProperties({JwtSecurityProperties.class, EntitlementGateProperties.class})
public class JwtSecurityAutoConfiguration {

    @Bean
    JwtAuthenticationFilter jwtAuthenticationFilter(JwtSecurityProperties properties) {
        return new JwtAuthenticationFilter(properties);
    }

    @Bean
    GatewayAccessFilter gatewayAccessFilter(JwtSecurityProperties properties) {
        return new GatewayAccessFilter(properties);
    }

    @Bean
    ProductionSecretsValidator productionSecretsValidator(org.springframework.core.env.Environment environment) {
        return new ProductionSecretsValidator(environment);
    }

    @Bean
    @ConditionalOnMissingBean(EntitlementGate.class)
    EntitlementGate remoteEntitlementGate(RestClient.Builder restClientBuilder, EntitlementGateProperties properties) {
        return new RemoteEntitlementGateClient(restClientBuilder, properties);
    }

    @Bean
    ModuleFeatureGateAspect moduleFeatureGateAspect(EntitlementGate entitlementGate) {
        return new ModuleFeatureGateAspect(entitlementGate);
    }
}
