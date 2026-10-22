package com.proyectoalmacen.gateway.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(
            ServerHttpSecurity http,
            JwtAuthenticationFilter jwtAuthenticationFilter
    ) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)

                .authorizeExchange(exchanges -> exchanges

                        // PUBLICOS
                        .pathMatchers(
                                "/auth-service/api/auth/login",
                                "/actuator/health",
                                "/actuator/info"
                        )
                        .permitAll()

                        // CATALOGO - ESCRITURA
                        .pathMatchers(
                                HttpMethod.POST,
                                "/catalog-service/api/**"
                        )
                        .hasAnyRole("ADMIN", "SUPERVISOR")

                        .pathMatchers(
                                HttpMethod.PUT,
                                "/catalog-service/api/**"
                        )
                        .hasAnyRole("ADMIN", "SUPERVISOR")

                        .pathMatchers(
                                HttpMethod.PATCH,
                                "/catalog-service/api/**"
                        )
                        .hasAnyRole("ADMIN", "SUPERVISOR")

                        .pathMatchers(
                                HttpMethod.DELETE,
                                "/catalog-service/api/**"
                        )
                        .hasRole("ADMIN")

                        // MOVIMIENTOS
                        .pathMatchers(
                                HttpMethod.POST,
                                "/movement-service/api/movimientos/**"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "SUPERVISOR",
                                "ALMACENERO"
                        )

                        // ALERTAS
                        .pathMatchers(
                                HttpMethod.PUT,
                                "/alert-service/api/alertas/*/atender"
                        )
                        .hasAnyRole(
                                "ADMIN",
                                "SUPERVISOR",
                                "ALMACENERO"
                        )

                        // TODO LO DEMAS
                        .anyExchange()
                        .authenticated()
                )

                .addFilterAt(
                        jwtAuthenticationFilter,
                        SecurityWebFiltersOrder.AUTHENTICATION
                )

                .build();
    }
}