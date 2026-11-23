package com.example.loginmonitoring.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Data typed into the registration form. There is deliberately no "role" field:
 * every new account gets the USER role, whatever the browser sends.
 */
public class RegistrationRequest {

    /** At least one letter and at least one digit. */
    public static final String PASSWORD_PATTERN = "^(?=.*[A-Za-z])(?=.*\\d).+$";
    public static final int PASSWORD_MIN = 8;
    public static final int PASSWORD_MAX = 64;

    @NotBlank(message = "Please enter your name.")
    @Size(max = 100, message = "Name can be at most 100 characters.")
    private String name;

    @NotBlank(message = "Please enter your email.")
    @Email(message = "Please enter a valid email address.")
    @Size(max = 150, message = "Email can be at most 150 characters.")
    private String email;

    @NotBlank(message = "Please enter a password.")
    @Size(min = PASSWORD_MIN, max = PASSWORD_MAX, message = "Password must be 8 to 64 characters long.")
    @Pattern(regexp = PASSWORD_PATTERN, message = "Password must contain at least one letter and one number.")
    private String password;

    @NotBlank(message = "Please confirm your password.")
    private String confirmPassword;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }
}
