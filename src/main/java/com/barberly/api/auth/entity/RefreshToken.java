package com.barberly.api.auth.entity;

import com.barberly.api.users.entity.Usuario;
import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "refresh_tokens", indexes = @Index(name = "idx_refresh_tokens_hash", columnList = "token_hash", unique = true))
public class RefreshToken {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @ManyToOne(fetch = FetchType.LAZY, optional = false) @JoinColumn(name = "usuario_id", nullable = false)
    private Usuario usuario;
    @Column(name = "token_hash", nullable = false, unique = true, length = 64)
    private String tokenHash;
    @Column(name = "fecha_expiracion", nullable = false)
    private Instant fechaExpiracion;
    @Column(name = "fecha_revocacion")
    private Instant fechaRevocacion;
    @Column(name = "reemplazado_por_hash", length = 64)
    private String reemplazadoPorHash;
    protected RefreshToken() {}
    public RefreshToken(Usuario usuario, String tokenHash, Instant fechaExpiracion) {
        this.usuario = usuario; this.tokenHash = tokenHash; this.fechaExpiracion = fechaExpiracion;
    }
    public boolean estaActivo(Instant ahora) { return fechaRevocacion == null && fechaExpiracion.isAfter(ahora); }
    public void revocar(Instant ahora, String reemplazo) { fechaRevocacion = ahora; reemplazadoPorHash = reemplazo; }
    public Usuario getUsuario() { return usuario; }
}
