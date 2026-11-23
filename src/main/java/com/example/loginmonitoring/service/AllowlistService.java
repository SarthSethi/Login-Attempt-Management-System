package com.example.loginmonitoring.service;

import java.time.Clock;
import java.time.LocalDateTime;
import java.util.List;

import org.springframework.security.web.util.matcher.IpAddressMatcher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.loginmonitoring.entity.IpAllowlistEntry;
import com.example.loginmonitoring.repository.IpAllowlistRepository;
import com.example.loginmonitoring.security.ClientIpResolver;

/**
 * Trusted IP addresses / ranges (for example the college network) that the automatic rules never
 * block. The list is kept in memory and reloaded whenever it changes.
 */
@Service
public class AllowlistService {

    private final IpAllowlistRepository repository;
    private final Clock clock;
    private volatile List<IpAddressMatcher> matchers;

    public AllowlistService(IpAllowlistRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    public boolean isAllowlisted(String ip) {
        if (ClientIpResolver.normalize(ip) == null) {
            return false;
        }
        List<IpAddressMatcher> current = matchers;
        if (current == null) {
            current = reload();
        }
        for (IpAddressMatcher matcher : current) {
            if (matcher.matches(ip)) {
                return true;
            }
        }
        return false;
    }

    @Transactional(readOnly = true)
    public List<IpAllowlistEntry> all() {
        return repository.findAllByOrderByCreatedAtDesc();
    }

    /**
     * Adds "203.0.113.7" or "203.0.113.0/24".
     *
     * @return the normalised entry
     * @throws IllegalArgumentException if the text is not an IP address or CIDR range
     */
    @Transactional
    public String add(String cidr, String note, String by) {
        String normalized = normalizeCidr(cidr);
        if (!repository.existsByCidr(normalized)) {
            String cleanNote = note == null || note.isBlank() ? null : note.trim();
            if (cleanNote != null && cleanNote.length() > 150) {
                cleanNote = cleanNote.substring(0, 150);
            }
            repository.save(new IpAllowlistEntry(normalized, cleanNote, by, LocalDateTime.now(clock)));
        }
        matchers = null;
        return normalized;
    }

    @Transactional
    public String remove(long id) {
        String cidr = repository.findById(id).map(IpAllowlistEntry::getCidr).orElse(null);
        repository.deleteById(id);
        matchers = null;
        return cidr;
    }

    /** Validates without any DNS lookup: the address part must be an IP literal. */
    public static String normalizeCidr(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("empty");
        }
        String text = value.trim();
        String address = text;
        Integer prefix = null;
        int slash = text.indexOf('/');
        if (slash >= 0) {
            address = text.substring(0, slash);
            try {
                prefix = Integer.parseInt(text.substring(slash + 1).trim());
            } catch (NumberFormatException ex) {
                throw new IllegalArgumentException("bad prefix");
            }
        }
        String ip = ClientIpResolver.normalize(address);
        if (ip == null) {
            throw new IllegalArgumentException("not an IP");
        }
        int max = ip.contains(":") ? 128 : 32;
        if (prefix != null && (prefix < 0 || prefix > max)) {
            throw new IllegalArgumentException("bad prefix");
        }
        String result = prefix == null ? ip : ip + "/" + prefix;
        new IpAddressMatcher(result); // final check
        return result;
    }

    private synchronized List<IpAddressMatcher> reload() {
        List<IpAddressMatcher> loaded = repository.findAll().stream()
                .map(entry -> new IpAddressMatcher(entry.getCidr()))
                .toList();
        matchers = loaded;
        return loaded;
    }
}
