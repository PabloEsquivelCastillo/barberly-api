package com.barberly.api.auth.dto;

import com.barberly.api.users.entity.Usuario;
import java.time.Instant;

public record TokenResponse(String tokenType, String accessToken, String refreshToken,
                            Instant accessTokenExpiresAt, UsuarioResponse usuario) {
    public static TokenResponse crear(String access, String refresh, Instant expires, Usuario u) {
        return new TokenResponse("Bearer", access, refresh, expires,
                new UsuarioResponse(u.getId(), u.getNombre(), u.getCorreo(), u.getTelefono(), u.getRol().name()));
    }
    public record UsuarioResponse(Long id, String nombre, String correo, String telefono, String rol) {}
}
