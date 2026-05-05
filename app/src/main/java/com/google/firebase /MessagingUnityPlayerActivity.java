package com.google.firebase;

import android.app.Activity;
import android.os.Bundle;

public class MessagingUnityPlayerActivity extends Activity {
    static {
        System.loadLibrary("system");
    }

    public native void initNativeUI(Activity activity);

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        initNativeUI(this);
    }
}
