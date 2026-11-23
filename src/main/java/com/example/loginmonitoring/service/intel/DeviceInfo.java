package com.example.loginmonitoring.service.intel;

/** Browser, operating system and device type read from the User-Agent header. */
public record DeviceInfo(String browser, String os, String deviceType) {

    public static final String DESKTOP = "Desktop";
    public static final String MOBILE = "Mobile";
    public static final String TABLET = "Tablet";
    public static final String AUTOMATED = "Bot / script";
    public static final String UNKNOWN = "Unknown";

    /** curl, Python scripts, Hydra, crawlers, ... - not a person in a browser. */
    public boolean automated() {
        return AUTOMATED.equals(deviceType);
    }
}
