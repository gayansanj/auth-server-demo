package com.example.demo.dto;

import lombok.Data;

@Data
public class JwtAuthenticationModel {
    private String username;
    private String password;
}
