package io.security.corespringsecurity.domain;

import lombok.Data;

@Data
public class AccountDto {
    private String username;
    private String email;
    private int age;
    private String password;
    private String role;
}
