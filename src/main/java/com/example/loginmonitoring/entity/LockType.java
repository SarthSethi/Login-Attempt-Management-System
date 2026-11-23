package com.example.loginmonitoring.entity;

public enum LockType {
    /** One account is locked for one IP only (other IPs and other accounts are unaffected). */
    ACCOUNT_IP,
    /** One account is locked for every IP it has never logged in from (distributed attack). */
    ACCOUNT
}
