package com.example.loginmonitoring.service.intel;

import java.util.Locale;

/**
 * Small, dependency-free User-Agent parser. It only needs to be good enough to tell
 * "Chrome on Windows" from "Safari on iOS" and to spot attack tools and scripts.
 * The User-Agent is sent by the client, so it can be faked - it is a hint, never proof.
 */
public final class UserAgentParser {

    private UserAgentParser() {
    }

    public static DeviceInfo parse(String userAgent) {
        if (userAgent == null || userAgent.isBlank()) {
            // Every real browser sends a User-Agent; a missing one means a script.
            return new DeviceInfo("No user agent", null, DeviceInfo.AUTOMATED);
        }
        String ua = userAgent.toLowerCase(Locale.ROOT);
        String os = detectOs(ua);

        String tool = detectTool(ua);
        if (tool != null) {
            return new DeviceInfo(tool, os, DeviceInfo.AUTOMATED);
        }
        return new DeviceInfo(detectBrowser(ua), os, detectDeviceType(ua));
    }

    private static String detectTool(String ua) {
        if (ua.contains("hydra")) return "Hydra (attack tool)";
        if (ua.contains("sqlmap")) return "sqlmap (attack tool)";
        if (ua.contains("nikto")) return "Nikto (scanner)";
        if (ua.contains("burp")) return "Burp Suite";
        if (ua.startsWith("curl/")) return "curl";
        if (ua.startsWith("wget/")) return "Wget";
        if (ua.contains("python-requests")) return "Python requests";
        if (ua.contains("python-urllib") || ua.contains("aiohttp") || ua.contains("python-httpx")) return "Python script";
        if (ua.contains("postmanruntime")) return "Postman";
        if (ua.contains("insomnia")) return "Insomnia";
        if (ua.contains("go-http-client")) return "Go HTTP client";
        if (ua.contains("okhttp")) return "OkHttp";
        if (ua.contains("apache-httpclient")) return "Apache HttpClient";
        if (ua.startsWith("java/") || ua.contains("java-http-client")) return "Java HTTP client";
        if (ua.contains("node-fetch") || ua.contains("axios/") || ua.contains("undici")) return "Node.js script";
        if (ua.contains("libwww-perl")) return "Perl script";
        if (ua.contains("headlesschrome")) return "Headless Chrome";
        if (ua.contains("phantomjs")) return "PhantomJS";
        if (ua.contains("bot") || ua.contains("spider") || ua.contains("crawl")) return "Bot / crawler";
        return null;
    }

    private static String detectBrowser(String ua) {
        if (ua.contains("edg/") || ua.contains("edga/") || ua.contains("edgios/")) return "Edge";
        if (ua.contains("opr/") || ua.contains("opera")) return "Opera";
        if (ua.contains("samsungbrowser")) return "Samsung Internet";
        if (ua.contains("ucbrowser")) return "UC Browser";
        if (ua.contains("yabrowser")) return "Yandex Browser";
        if (ua.contains("firefox/") || ua.contains("fxios/")) return "Firefox";
        if (ua.contains("crios/")) return "Chrome";
        if (ua.contains("chromium/")) return "Chromium";
        if (ua.contains("chrome/")) return "Chrome";
        if (ua.contains("safari/") && ua.contains("version/")) return "Safari";
        if (ua.contains("msie") || ua.contains("trident/")) return "Internet Explorer";
        if (ua.contains("mozilla/")) return "Other browser";
        return "Unknown client";
    }

    private static String detectOs(String ua) {
        if (ua.contains("iphone") || ua.contains("ipod")) return "iOS";
        if (ua.contains("ipad")) return "iPadOS";
        if (ua.contains("android")) return "Android";
        if (ua.contains("cros")) return "ChromeOS";
        if (ua.contains("windows nt 10.0")) return "Windows 10/11";
        if (ua.contains("windows nt 6.3")) return "Windows 8.1";
        if (ua.contains("windows nt 6.1")) return "Windows 7";
        if (ua.contains("windows")) return "Windows";
        if (ua.contains("mac os x") || ua.contains("macintosh")) return "macOS";
        if (ua.contains("linux")) return "Linux";
        return null;
    }

    private static String detectDeviceType(String ua) {
        if (ua.contains("ipad") || ua.contains("tablet") || (ua.contains("android") && !ua.contains("mobile"))) {
            return DeviceInfo.TABLET;
        }
        if (ua.contains("mobi") || ua.contains("iphone") || ua.contains("android")) {
            return DeviceInfo.MOBILE;
        }
        return DeviceInfo.DESKTOP;
    }
}
