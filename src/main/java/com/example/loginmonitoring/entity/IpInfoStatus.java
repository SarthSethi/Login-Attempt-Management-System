package com.example.loginmonitoring.entity;

public enum IpInfoStatus {
    /** Location found by the lookup service. */
    OK,
    /** Private / local network address (no public location). */
    PRIVATE,
    /** Reserved or documentation address. */
    RESERVED,
    /** The lookup service could not be reached or did not know the address. */
    FAILED,
    /** Made-up location attached to a test address by the attack simulator. */
    SIMULATED
}
