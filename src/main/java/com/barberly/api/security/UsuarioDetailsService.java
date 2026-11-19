package com.barberly.api.security;

import com.barberly.api.users.repository.UsuarioRepository;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

@Service
public class UsuarioDetailsService implements UserDetailsService {
    private final UsuarioRepository usuarios;
    public UsuarioDetailsService(UsuarioRepository usuarios) { this.usuarios=usuarios; }
    @Override public UserDetails loadUserByUsername(String correo) {
        var u=usuarios.findByCorreoIgnoreCase(correo).orElseThrow(() -> new UsernameNotFoundException("Credenciales inválidas"));
        return User.withUsername(u.getCorreo()).password(u.getPasswordHash()).roles(u.getRol().name()).disabled(!u.isActivo()).build();
    }
}
