package com.barberly.api.auth.controller;

import com.barberly.api.auth.dto.*;
import com.barberly.api.auth.service.AuthService;
import com.barberly.api.users.repository.UsuarioRepository;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/v1/auth")
@Tag(name = "Autenticación", description = "Registro de clientes, inicio de sesión y gestión de tokens")
public class AuthController {
    private final AuthService auth;
    private final UsuarioRepository usuarios;

    public AuthController(AuthService auth, UsuarioRepository usuarios) {
        this.auth = auth;
        this.usuarios = usuarios;
    }

    @PostMapping("/register")
    @Operation(summary = "Registrar cliente", description = "Crea una cuenta activa con rol CLIENTE y devuelve tokens de acceso y renovación. El rol no se recibe del cliente.")
    @ApiResponses({
            @ApiResponse(responseCode = "201", description = "Cuenta creada y autenticada", content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "Datos inválidos", content = @Content),
            @ApiResponse(responseCode = "409", description = "El correo ya está registrado", content = @Content)
    })
    @ResponseStatus(HttpStatus.CREATED)
    public TokenResponse registrar(@Valid @RequestBody RegistroRequest request) {
        return auth.registrar(request);
    }

    @PostMapping("/login")
    @Operation(summary = "Iniciar sesión", description = "Autentica por correo y contraseña. Las cuentas desactivadas no pueden iniciar sesión.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Autenticación exitosa", content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "Datos inválidos", content = @Content),
            @ApiResponse(responseCode = "401", description = "Credenciales inválidas o cuenta desactivada", content = @Content)
    })
    public TokenResponse login(@Valid @RequestBody LoginRequest request) {
        return auth.login(request);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Renovar tokens", description = "Valida y rota el refresh token; el anterior queda revocado y se devuelve un nuevo par de tokens.")
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Tokens renovados", content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "400", description = "Falta el refresh token", content = @Content),
            @ApiResponse(responseCode = "401", description = "Refresh token inválido, expirado o revocado", content = @Content)
    })
    public TokenResponse refresh(@Valid @RequestBody RefreshRequest request) {
        return auth.renovar(request.refreshToken());
    }

    @PostMapping("/logout")
    @Operation(summary = "Cerrar sesión", description = "Revoca el refresh token enviado. El access token vigente expira según su duración configurada.")
    @ApiResponses({
            @ApiResponse(responseCode = "204", description = "Sesión cerrada"),
            @ApiResponse(responseCode = "400", description = "Falta el refresh token", content = @Content)
    })
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void logout(@Valid @RequestBody RefreshRequest request) {
        auth.logout(request.refreshToken());
    }

    @GetMapping("/me")
    @Operation(summary = "Consultar usuario autenticado", description = "Devuelve el perfil asociado al subject del JWT de acceso.", security = @SecurityRequirement(name = "bearerAuth"))
    @ApiResponses({
            @ApiResponse(responseCode = "200", description = "Perfil del usuario", content = @Content(schema = @Schema(implementation = TokenResponse.UsuarioResponse.class))),
            @ApiResponse(responseCode = "401", description = "JWT faltante o inválido", content = @Content),
            @ApiResponse(responseCode = "404", description = "Usuario del token no encontrado", content = @Content)
    })
    public TokenResponse.UsuarioResponse me(@AuthenticationPrincipal Jwt jwt) {
        var u = usuarios.findById(Long.valueOf(jwt.getSubject())).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
        return new TokenResponse.UsuarioResponse(u.getId(), u.getNombre(), u.getCorreo(), u.getTelefono(), u.getRol().name());
    }
}
