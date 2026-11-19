package com.barberly.api.config;


import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "barberly-api",
                version = "1.0.0",
                description = "API REST de Barberly para la administración de citas y operación de una barbería. " +
                        "El registro público crea exclusivamente cuentas CLIENTE."
        )
)
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT",
        description = "JWT de acceso. Enviar como: Authorization: Bearer {token}")
public class OpenApiConfig {
}
