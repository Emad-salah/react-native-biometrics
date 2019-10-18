package com.rnbiometrics;

import androidx.biometric.BiometricPrompt;

/**
 * Created by brandon on 4/9/18.
 */

public interface ReactNativeBiometricsCallback {

    void onAuthenticated(BiometricPrompt.CryptoObject cryptoObject);

    void onCancel();

    void onError();
}
