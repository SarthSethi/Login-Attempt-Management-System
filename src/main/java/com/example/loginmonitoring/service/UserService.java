package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Locale;
import java.util.List;
import java.util.Optional;

import org.springframework.data.domain.Sort;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.config.AdminProperties;
import com.example.loginmonitoring.dto.RegistrationRequest;
import com.example.loginmonitoring.entity.Role;
import com.example.loginmonitoring.entity.User;
import com.example.loginmonitoring.repository.UserRepository;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AdminProperties adminProperties;
    private final Clock clock;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder,
                       AdminProperties adminProperties, Clock clock) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.adminProperties = adminProperties;
        this.clock = clock;
    }

    /**
     * Creates a normal USER account. The password is hashed with BCrypt before saving.
     *
     * @throws EmailAlreadyRegisteredException if the email is taken (or reserved for the admin)
     */
    @Transactional
    public User register(RegistrationRequest request) {
        String email = normalizeEmail(request.getEmail());
        if (userRepository.existsByEmail(email) || email.equals(normalizeEmail(adminProperties.email()))) {
            throw new EmailAlreadyRegisteredException();
        }
        User user = new User(request.getName().trim(), email, passwordEncoder.encode(request.getPassword()),
                Role.USER, LocalDateTime.now(clock));
        // saveAndFlush so a duplicate email (unique constraint) fails here, inside this method
        return userRepository.saveAndFlush(user);
    }

    /**
     * Makes sure the configured administrator exists with the configured password and the
     * ADMIN role. Safe to run on every startup: nothing changes if it is already correct.
     *
     * @return what was done, for logging
     */
    @Transactional
    public String createOrUpdateAdmin(String name, String rawEmail, String rawPassword) {
        String email = normalizeEmail(rawEmail);
        Optional<User> existing = userRepository.findByEmail(email);

        if (existing.isEmpty()) {
            userRepository.save(new User(name, email, passwordEncoder.encode(rawPassword), Role.ADMIN,
                    LocalDateTime.now(clock)));
            return "created";
        }

        User admin = existing.get();
        boolean changed = false;
        if (admin.getRole() != Role.ADMIN) {
            admin.setRole(Role.ADMIN);
            changed = true;
        }
        if (!admin.isEnabled()) {
            admin.setEnabled(true);
            changed = true;
        }
        if (!passwordEncoder.matches(rawPassword, admin.getPasswordHash())) {
            admin.setPasswordHash(passwordEncoder.encode(rawPassword));
            changed = true;
        }
        return changed ? "updated" : "unchanged";
    }

    @Transactional(readOnly = true)
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(normalizeEmail(email));
    }

    @Transactional(readOnly = true)
    public Optional<User> findById(long id) {
        return userRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public List<User> allUsers() {
        return userRepository.findAll(Sort.by(Sort.Direction.DESC, "createdAt"));
    }

    @Transactional(readOnly = true)
    public boolean passwordMatches(String email, String rawPassword) {
        return findByEmail(email).map(user -> passwordEncoder.matches(rawPassword, user.getPasswordHash())).orElse(false);
    }

    /** Stores a new BCrypt hash for the user. */
    @Transactional
    public void changePassword(String email, String newRawPassword) {
        User user = userRepository.findByEmail(normalizeEmail(email))
                .orElseThrow(() -> new IllegalStateException("No such user"));
        user.setPasswordHash(passwordEncoder.encode(newRawPassword));
    }

    @Transactional
    public Optional<User> setEnabled(long id, boolean enabled) {
        Optional<User> user = userRepository.findById(id);
        user.ifPresent(u -> u.setEnabled(enabled));
        return user;
    }

    /** Emails are compared in lower case without surrounding spaces. */
    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }
}
