package org.mazhai.aran.gateway.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * GatewaySecurityConfig — SCG runs on WebFlux (reactive).
 *
 * Authentication is fully handled by Envoy (jwt_authn) before requests
 * reach this layer. Spring Security here is configured to:
 *   - Disable CSRF (stateless API gateway)
 *   - Permit all requests at the Spring Security level (Envoy is the gate)
 *   - Strip any forwarded auth headers that did not come from Envoy
 *     (handled via default-filters in application.yml: RemoveRequestHeader)
 *
 * IMPORTANT: This only works correctly when aran-api-gateway is NOT
 * directly exposed on the host network. In docker-compose, port 8080
 * is internal-only (expose, not ports). All external traffic enters
 * via aran-waf:8443.
 */
@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                    .pathMatchers("/api/v1/gateway/metrics/**").permitAll()
                    .anyExchange().permitAll()
                )
                .build();
    }
}
