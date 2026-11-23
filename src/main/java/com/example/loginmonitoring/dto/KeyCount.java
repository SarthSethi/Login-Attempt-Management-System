package com.example.loginmonitoring.dto;

/** A value (IP address, email, ...) with how many times it occurred. */
public record KeyCount(String key, long count) {
}
