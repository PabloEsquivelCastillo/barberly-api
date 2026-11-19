package com.barberly.api.auth.dto;

import jakarta.validation.constraints.*;

public record RegistroRequest(@NotBlank @Size(max=100) String nombre,
                              @NotBlank @Email @Size(max=150) String correo,
                              @NotBlank @Size(min=8, max=72) String password,
                              @Size(max=20) String telefono) {}
