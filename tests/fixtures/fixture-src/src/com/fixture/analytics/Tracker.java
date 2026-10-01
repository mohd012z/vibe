package com.fixture.analytics;

// Simulated analytics (AppLovin-like) — separate from ads to test classification.
public final class Tracker {
    private Tracker() {}
    public static void trackScreen(String name) { /* https://api.applovin.com track */ }
}
