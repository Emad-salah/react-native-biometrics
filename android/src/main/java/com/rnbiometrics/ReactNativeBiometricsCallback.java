package com.rnbiometrics;

import androidx.biometric.BiometricPrompt;
import androidx.annotation.NonNull;

/**
 * Created by brandon on 4/9/18.
 */

public interface ReactNativeBiometricsCallback {

    void onAuthenticated(BiometricPrompt.AuthenticationResult result);

    void onCancel();

    void onError(int errorCode, @NonNull CharSequence errorMessage);
}
