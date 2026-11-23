package com.example.loginmonitoring.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * How the real visitor IP is found (prefix "app.client-ip").
 *
 * @param trustedProxies IPs / CIDR ranges of reverse proxies allowed to set X-Forwarded-For
 * @param headers        headers that carry the visitor IP and are set by a proxy we trust,
 *                       e.g. CF-Connecting-IP (Cloudflare). Read only from trusted senders.
 * @param render         true when running on Render (Render sets RENDER=true automatically). All
 *                       traffic to a Render web service passes through Render's own proxy and
 *                       Cloudflare, so the Cloudflare header is trusted from any sender.
 */
@ConfigurationProperties(prefix = "app.client-ip")
public record ClientIpProperties(
        @DefaultValue List<String> trustedProxies,
        @DefaultValue List<String> headers,
        @DefaultValue("false") boolean render) {
}
