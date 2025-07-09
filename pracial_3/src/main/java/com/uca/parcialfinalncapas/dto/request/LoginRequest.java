package com.uca.parcialfinalncapas.dto.request;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class LoginRequest {
    @NotBlank private String correo;
    @NotBlank private String password;
}
