package com.example.loginmonitoring.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/** Data typed into the "Change password" form. */
public class ChangePasswordForm {

    @NotBlank(message = "Please enter your current password.")
    private String currentPassword;

    @NotBlank(message = "Please enter a new password.")
    @Size(min = RegistrationRequest.PASSWORD_MIN, max = RegistrationRequest.PASSWORD_MAX,
            message = "Password must be 8 to 64 characters long.")
    @Pattern(regexp = RegistrationRequest.PASSWORD_PATTERN,
            message = "Password must contain at least one letter and one number.")
    private String newPassword;

    @NotBlank(message = "Please confirm your new password.")
    private String confirmPassword;

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }

    public String getConfirmPassword() {
        return confirmPassword;
    }

    public void setConfirmPassword(String confirmPassword) {
        this.confirmPassword = confirmPassword;
    }

    public void clearPasswords() {
        currentPassword = null;
        newPassword = null;
        confirmPassword = null;
    }
}
