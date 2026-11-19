package com.barberly.api.auth.service;

import com.barberly.api.auth.dto.*;
import com.barberly.api.auth.entity.RefreshToken;
import com.barberly.api.auth.repository.RefreshTokenRepository;
import com.barberly.api.users.entity.Usuario;
import com.barberly.api.users.enums.RolUsuario;
import com.barberly.api.users.repository.UsuarioRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthService {
    private final UsuarioRepository usuarios;
    private final RefreshTokenRepository refreshTokens;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authenticationManager;
    private final JwtEncoder jwtEncoder;
    private final SecureRandom random = new SecureRandom();
    private final long accessMinutes, refreshDays;

    public AuthService(UsuarioRepository usuarios, RefreshTokenRepository refreshTokens, PasswordEncoder encoder,
                       AuthenticationManager authenticationManager, JwtEncoder jwtEncoder,
                       @Value("${barberly.auth.access-token-minutes:15}") long accessMinutes,
                       @Value("${barberly.auth.refresh-token-days:14}") long refreshDays) {
        this.usuarios=usuarios; this.refreshTokens=refreshTokens; this.encoder=encoder;
        this.authenticationManager=authenticationManager; this.jwtEncoder=jwtEncoder;
        this.accessMinutes=accessMinutes; this.refreshDays=refreshDays;
    }

    @Transactional
    public TokenResponse registrar(RegistroRequest req) {
        String correo=req.correo().trim().toLowerCase();
        if (usuarios.existsByCorreoIgnoreCase(correo)) throw new ResponseStatusException(HttpStatus.CONFLICT,"El correo ya está registrado");
        Usuario usuario=usuarios.save(new Usuario(req.nombre().trim(), correo, encoder.encode(req.password()), req.telefono(), RolUsuario.CLIENTE));
        return emitir(usuario);
    }

    @Transactional
    public TokenResponse login(LoginRequest req) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(req.correo().trim().toLowerCase(), req.password()));
        Usuario usuario=usuarios.findByCorreoIgnoreCase(req.correo()).filter(Usuario::isActivo)
                .orElseThrow(() -> new BadCredentialsException("Credenciales inválidas"));
        return emitir(usuario);
    }

    @Transactional
    public TokenResponse renovar(String raw) {
        Instant ahora=Instant.now(); String hash=hash(raw);
        RefreshToken existente=refreshTokens.findByTokenHash(hash).orElseThrow(this::tokenInvalido);
        if (!existente.estaActivo(ahora)) throw tokenInvalido();
        Usuario usuario=existente.getUsuario();
        if (!usuario.isActivo()) { existente.revocar(ahora,null); throw tokenInvalido(); }
        String nuevo=generarRefresh(); String nuevoHash=hash(nuevo);
        existente.revocar(ahora,nuevoHash);
        refreshTokens.save(new RefreshToken(usuario,nuevoHash,ahora.plusSeconds(refreshDays*86400)));
        return crearRespuesta(usuario,nuevo,ahora);
    }

    @Transactional
    public void logout(String raw) {
        refreshTokens.findByTokenHash(hash(raw)).ifPresent(t -> t.revocar(Instant.now(),null));
    }

    private TokenResponse emitir(Usuario usuario) {
        Instant ahora=Instant.now(); String raw=generarRefresh();
        refreshTokens.save(new RefreshToken(usuario,hash(raw),ahora.plusSeconds(refreshDays*86400)));
        return crearRespuesta(usuario,raw,ahora);
    }
    private TokenResponse crearRespuesta(Usuario usuario,String refresh,Instant ahora) {
        Instant exp=ahora.plusSeconds(accessMinutes*60);
        JwtClaimsSet claims=JwtClaimsSet.builder().issuer("barberly-api").issuedAt(ahora).expiresAt(exp)
                .subject(usuario.getId().toString()).claim("email",usuario.getCorreo()).claim("role",usuario.getRol().name()).build();
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return TokenResponse.crear(jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue(),refresh,exp,usuario);
    }
    private String generarRefresh() { byte[] bytes=new byte[64]; random.nextBytes(bytes); return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes); }
    private String hash(String token) {
        try { return java.util.HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8))); }
        catch (Exception e) { throw new IllegalStateException(e); }
    }
    private ResponseStatusException tokenInvalido() { return new ResponseStatusException(HttpStatus.UNAUTHORIZED,"Refresh token inválido o expirado"); }
}
