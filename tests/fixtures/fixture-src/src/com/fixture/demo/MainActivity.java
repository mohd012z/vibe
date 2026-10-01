package com.fixture.demo;

import android.app.Activity;
import android.os.Bundle;
import com.fixture.sdkads.InterstitialAd;
import com.fixture.sdkads.BannerAd;
import com.fixture.analytics.Tracker;

public class MainActivity extends Activity {
    @Override protected void onCreate(Bundle b) {
        super.onCreate(b);
        BannerAd.showBanner(this, "banner-unit-1");
    }
    @Override protected void onResume() {
        super.onResume();
        // E3: application-owned caller invoking ad show
        DemoApp.sInterstitial.show();
        Tracker.trackScreen("main");
    }
}
