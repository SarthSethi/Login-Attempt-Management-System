package com.example.loginmonitoring.entity;

/** Who created an IP block. */
public enum BlockSource {
    /** Created by one of the detection rules. */
    AUTOMATIC,
    /** Created by an administrator. */
    MANUAL,
    /** The account owner pressed "This wasn't me" on a login from this IP. */
    USER_REPORT
}
