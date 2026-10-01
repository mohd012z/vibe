package com.fixture.sdkads;

public final class InterstitialAd {
    private static final String ENDPOINT = "https://ads.example-sdk.net/load";
    private InterstitialAd() {}
    public static InterstitialAd load(String unitId) { return new InterstitialAd(); }
    public void show() { /* would fetch ENDPOINT */ }
}
