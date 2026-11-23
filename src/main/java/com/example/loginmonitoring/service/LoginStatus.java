package com.example.loginmonitoring.service;

/**
 * What the login page shows about the visitor's recent attempts. It is calculated from the
 * database every time the page is opened, so refreshing the page does not change it.
 */
public record LoginStatus(
        State state,
        String email,
        long secondsLeft,
        int accountFailures,
        int accountLimit,
        int ipFailures,
        int ipFailureLimit,
        int ipAccounts,
        int ipAccountLimit,
        boolean ipWarning) {

    public enum State {
        /** No recent failures. */
        CLEAR,
        /** Some wrong passwords for this account from this network, not locked yet. */
        FAILURES,
        /** Rule 1: this account is paused for this network. */
        ACCOUNT_LOCKED,
        /** Rule 4: the account is under attack and this network was never used by its owner. */
        ACCOUNT_UNDER_ATTACK,
        /** The IP is blocked for a while. */
        IP_BLOCKED,
        /** The IP is banned by the administrator. */
        IP_BANNED
    }

    static LoginStatus of(State state, String email, long secondsLeft, int accountLimit) {
        return new LoginStatus(state, email, secondsLeft, 0, accountLimit, 0, 0, 0, 0, false);
    }

    public int accountAttemptsLeft() {
        return Math.max(0, accountLimit - accountFailures);
    }

    public boolean blocked() {
        return state == State.IP_BLOCKED || state == State.IP_BANNED;
    }

    public boolean locked() {
        return state == State.ACCOUNT_LOCKED || state == State.ACCOUNT_UNDER_ATTACK;
    }

    /** "14:05" style time left, for the countdown. */
    public String timeLeft() {
        long minutes = secondsLeft / 60;
        long seconds = secondsLeft % 60;
        return String.format("%d:%02d", minutes, seconds);
    }
}
