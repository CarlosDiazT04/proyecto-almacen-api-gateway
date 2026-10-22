package com.proyectoalmacen.gateway.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

@Service
public class JwtService {

    private final String secret;

    public JwtService(@Value("${app.jwt.secret}") String secret) {
        if (secret == null || secret.isBlank()) {
            throw new IllegalStateException(
                    "JWT_SECRET no esta configurado en api-gateway"
            );
        }
        this.secret = secret;
    }

    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(key())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String getUsername(Claims claims) {
        return claims.getSubject();
    }

    public List<String> getRoles(Claims claims) {
        Object rolesClaim = claims.get("roles");

        if (rolesClaim == null) {
            rolesClaim = claims.get("authorities");
        }

        if (rolesClaim == null) {
            rolesClaim = claims.get("role");
        }

        List<String> roles = new ArrayList<>();

        if (rolesClaim instanceof Collection<?> collection) {
            for (Object value : collection) {
                if (value != null) {
                    roles.add(normalizeRole(value.toString()));
                }
            }
        } else if (rolesClaim instanceof String value) {
            for (String role : value.split(",")) {
                if (!role.isBlank()) {
                    roles.add(normalizeRole(role.trim()));
                }
            }
        }

        return roles;
    }

    private String normalizeRole(String role) {
        return role.startsWith("ROLE_") ? role : "ROLE_" + role;
    }

    private SecretKey key() {
        try {
            return Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
        } catch (Exception ex) {
            return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        }
    }
}
