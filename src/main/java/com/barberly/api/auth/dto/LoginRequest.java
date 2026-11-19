package com.barberly.api.auth.dto;

import jakarta.validation.constraints.*;

public record LoginRequest(@NotBlank @Email String correo, @NotBlank String password) {}
