package com.fixture.demo;

import android.app.Application;
import com.fixture.sdkads.MobileAds;
import com.fixture.sdkads.InterstitialAd;

// Simulates a real app's Application class that boots an ad SDK.
public class DemoApp extends Application {
    static InterstitialAd sInterstitial;
    @Override public void onCreate() {
        super.onCreate();
        // E3: application-owned caller invoking SDK init
        MobileAds.initialize(this, "ca-app-pub-3940256099942544~3347511713");
        sInterstitial = InterstitialAd.load("ad-unit-444");
    }
}
