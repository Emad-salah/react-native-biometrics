package com.rnbiometrics;

import android.annotation.TargetApi;

import androidx.annotation.NonNull;
import androidx.fragment.app.FragmentActivity;
import android.app.KeyguardManager;
import androidx.fragment.app.FragmentManager;
import android.content.Context;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricManager;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.TextUtils;
import android.util.Base64;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.ReactActivity;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Created by brandon on 4/5/18.
 */

public class ReactNativeBiometrics extends ReactContextBaseJavaModule {

    String biometricKeyAlias = "biometric_key";

    public ReactNativeBiometricsCallback biometricAuthCallback;

    public ReactNativeBiometrics(ReactApplicationContext reactContext) {
        super(reactContext);
    }

    @Override
    public String getName() {
        return "ReactNativeBiometrics";
    }

    @ReactMethod
    public String getBiometricKeyAlias() {
        return biometricKeyAlias;
    }

    @ReactMethod
    public String setBiometricKeyAlias(String alias) {
        biometricKeyAlias = alias;
        return biometricKeyAlias;
    }

    @ReactMethod
    public void isSensorAvailable(Promise promise) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                ReactApplicationContext reactApplicationContext = getReactApplicationContext();
                BiometricManager biometricManager = BiometricManager.from(reactApplicationContext);
                int biometricStatus = biometricManager.canAuthenticate();
                Boolean isHardwareDetected = biometricStatus != biometricManager.BIOMETRIC_ERROR_NO_HARDWARE && biometricStatus != biometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE;
                Boolean hasFingerprints = isHardwareDetected && biometricStatus != biometricManager.BIOMETRIC_ERROR_NONE_ENROLLED;

                KeyguardManager keyguardManager = (KeyguardManager) reactApplicationContext.getSystemService(Context.KEYGUARD_SERVICE);
                Boolean hasProtectedLockscreen = keyguardManager.isKeyguardSecure();

                WritableMap sensorResponse = Arguments.createMap();
                sensorResponse.putBoolean("hardwareExists", isHardwareDetected);
                sensorResponse.putBoolean("fingerprintsEnrolled", isHardwareDetected);
                sensorResponse.putBoolean("useableSensor", isHardwareDetected && hasFingerprints && hasProtectedLockscreen);

                if (isHardwareDetected && hasFingerprints && hasProtectedLockscreen) {
                    promise.resolve(sensorResponse);
                } else {
                    promise.resolve(sensorResponse);
                }
            } else {
                promise.resolve(null);
            }
        } catch (Exception e) {
            promise.reject("Error detecting fingerprint availability: " + e.getMessage(), "Error detecting fingerprint availability");
        }
    }

    @ReactMethod
    public void createKeys(String title, final Promise promise) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (TextUtils.isEmpty(title)) {
                    // if no title is provided for the create keys prompt, treat the action as
                    // authenticated and create keys
                    ReactNativeBiometricsCallback createKeysCallback = getCreationCallback(promise);
                    createKeysCallback.onAuthenticated(null);
                } else {
                    // ReactNativeBiometricsDialog dialog = new ReactNativeBiometricsDialog();
                    // dialog.init(title, null, getCreationCallback(promise));
                    FragmentActivity activity = (FragmentActivity) getCurrentActivity();
                    // dialog.show(activity.getSupportFragmentManager().beginTransaction(), "fingerprint_dialog");
                    final BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                            .setTitle(title)
                            .setNegativeButtonText("Cancel")
                            .build();

                    biometricAuthCallback = getCreationCallback(promise);

                    FragmentActivity activityFrag = (FragmentActivity) activity;


                    final BiometricPrompt fingerprintManager = new BiometricPrompt(activityFrag, this.getMainThreadExecutor(activity), new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                            if (biometricAuthCallback != null) {
                                biometricAuthCallback.onAuthenticated(result);
                            }
                        }

                        @Override
                        public void onAuthenticationFailed() {
                            if (biometricAuthCallback != null) {
                                biometricAuthCallback.onCancel();
                            }
                        }

                        @Override
                        public void onAuthenticationError(int errorCode,
                                                          @NonNull CharSequence errString) {
                            if (biometricAuthCallback != null) {
                                biometricAuthCallback.onError(errorCode, errString);
                            }
                        }
                    });

                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            fingerprintManager.authenticate(promptInfo);
                        }
                    });
                }
            } else {
                promise.reject("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
            }
        } catch (Exception e) {
            promise.reject("Error generating public private keys: " + e.getMessage(), "Error generating public private keys " + e.getMessage() + " " + e.getStackTrace()[0] + " " + e.getStackTrace()[1] + " " + e.getStackTrace()[2] + " " + e.getStackTrace()[3] + " " + e.getStackTrace()[4] + " " + e.getStackTrace()[5]);
        }
    }

    @ReactMethod
    public void deleteKeys(Promise promise) {
        boolean deletionSuccessful = deleteBiometricKey();
        if (deletionSuccessful) {
            promise.resolve(true);
        } else {
            promise.reject("Error deleting biometric key from keystore", "Error deleting biometric key from keystore");
        }
    }

    @ReactMethod
    public void createSignature(String title, String payload, final Promise promise) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Signature signature = Signature.getInstance("SHA256withECDSA");
                KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
                keyStore.load(null);

                PrivateKey privateKey = (PrivateKey) keyStore.getKey(biometricKeyAlias, null);
                signature.initSign(privateKey);

                if (title != null) {
                    final BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);
    
    //                ReactNativeBiometricsDialog dialog = new ReactNativeBiometricsDialog();
    //                dialog.init(title, cryptoObject, getSignatureCallback(payload, promise));
    //
    //                FragmentActivity activity = (FragmentActivity) getCurrentActivity();
    //                dialog.show(activity.getSupportFragmentManager(), "fingerprint_dialog");
                    FragmentActivity activity = (FragmentActivity) getCurrentActivity();
                    final BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                            .setTitle(title)
                            .setNegativeButtonText("Cancel")
                            .build();
    
                    biometricAuthCallback = getSignatureCallback(payload, promise);
    
                    FragmentActivity activityFrag = (FragmentActivity) activity;
    
    
                    final BiometricPrompt fingerprintManager = new BiometricPrompt(activityFrag, this.getMainThreadExecutor(activity), new BiometricPrompt.AuthenticationCallback() {
                        @Override
                        public void onAuthenticationSucceeded(@NonNull BiometricPrompt.AuthenticationResult result) {
                            if (biometricAuthCallback != null) {
                                biometricAuthCallback.onAuthenticated(result);
                            }
                        }
    
                        @Override
                        public void onAuthenticationFailed() {
                            if (biometricAuthCallback != null) {
                                biometricAuthCallback.onCancel();
                            }
                        }
    
                        @Override
                        public void onAuthenticationError(int errorCode,
                                                          @NonNull CharSequence errString) {
                            promise.reject("onAuthenticationError:" + errorCode + " Error: " + errString, "onAuthenticationError:" + errorCode + " Error: " + errString);
                            if (biometricAuthCallback != null) {
                                biometricAuthCallback.onError(errorCode, errString);
                            }
                        }
                    });
    
                    activity.runOnUiThread(new Runnable() {
                        @Override
                        public void run() {
                            fingerprintManager.authenticate(promptInfo, cryptoObject);
                        }
                    });
                } else {
                    signature.update(payload.getBytes());
                    byte[] signed = signature.sign();
                    String signedString = Base64.encodeToString(signed, Base64.DEFAULT);
                    signedString = signedString.replaceAll("\r", "").replaceAll("\n", "");
                    promise.resolve(signedString);
                }
            } else {
                promise.reject("Cannot generate keys on android versions below 6.0", "Cannot generate keys on android versions below 6.0");
            }
        } catch (Exception e) {
            promise.reject("Error signing payload: " + e.getMessage(), e.getMessage());
        }
    }

    @ReactMethod
    public void simplePrompt(String title, Promise promise) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
//                ReactNativeBiometricsDialog dialog = new ReactNativeBiometricsDialog();
//                dialog.init(title, null, getSimplePromptCallback(promise));
//                FragmentActivity activity = (FragmentActivity) getCurrentActivity();
//                dialog.show(activity.getSupportFragmentManager(), "fingerprint_dialog");
            } else {
                promise.reject("Cannot display biometric prompt on android versions below 6.0", "Cannot display biometric prompt on android versions below 6.0");
            }
        } catch (Exception e) {
            promise.reject("Error displaying local biometric prompt: " + e.getMessage(), "Error displaying local biometric prompt");
        }
    }

    protected boolean deleteBiometricKey() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            keyStore.deleteEntry(biometricKeyAlias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    protected ReactNativeBiometricsCallback getSignatureCallback(final String payload, final Promise promise) {
        return new ReactNativeBiometricsCallback() {
            @Override
            @TargetApi(Build.VERSION_CODES.M)
            public void onAuthenticated(BiometricPrompt.AuthenticationResult result) {
                try {
                    BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
                    Signature cryptoSignature = cryptoObject.getSignature();
                    cryptoSignature.update(payload.getBytes());
                    byte[] signed = cryptoSignature.sign();
                    String signedString = Base64.encodeToString(signed, Base64.DEFAULT);
                    signedString = signedString.replaceAll("\r", "").replaceAll("\n", "");
                    promise.resolve(signedString);
                } catch (Exception e) {
                    promise.reject("Error creating signature: " + e.getMessage(), "Error creating signature: " + e.getMessage());
                }
            }

            @Override
            public void onCancel() {
                promise.reject("User cancelled fingerprint authorization", "User cancelled fingerprint authorization");
            }

            @Override
            public void onError(int errorCode, @NonNull CharSequence errorMessage) {
                promise.reject("Error generating public private keys" , "Error generating public private keys.\n Code: " + errorCode + "\nMessage: " + errorMessage);
            }
        };
    }

    protected ReactNativeBiometricsCallback getCreationCallback(final Promise promise) {
        return new ReactNativeBiometricsCallback() {
            @Override
            @TargetApi(Build.VERSION_CODES.M)
            public void onAuthenticated(BiometricPrompt.AuthenticationResult result) {
                try {
                    deleteBiometricKey();
                    ECGenParameterSpec ECGenParameterSpec = new ECGenParameterSpec("P-256");
                    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                    KeyGenParameterSpec keyGenParameterSpec = new KeyGenParameterSpec.Builder(biometricKeyAlias, KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAlgorithmParameterSpec(ECGenParameterSpec)
                            .setUserAuthenticationRequired(result != null)
                            .build();
                    keyPairGenerator.initialize(keyGenParameterSpec);

                    KeyPair keyPair = keyPairGenerator.generateKeyPair();
                    PublicKey publicKey = keyPair.getPublic();
                    byte[] encodedPublicKey = publicKey.getEncoded();
                    String publicKeyString = Base64.encodeToString(encodedPublicKey, Base64.DEFAULT);
                    publicKeyString = publicKeyString.replaceAll("\r", "").replaceAll("\n", "");
                    promise.resolve(publicKeyString);
                } catch (Exception e) {
                    promise.reject("Error generating public private keys: " + e.getMessage(), "Error generating public private keys: " + e.getMessage());
                }
            }

            @Override
            public void onCancel() {
                promise.reject("User cancelled fingerprint authorization", "User cancelled fingerprint authorization");
            }

            @Override
            public void onError(int errorCode, @NonNull CharSequence errorMessage) {
                promise.reject("Error generating public private keys" , "Error generating public private keys.\n Code: " + errorCode + "\nMessage: " + errorMessage);
            }
        };
    }

    protected ReactNativeBiometricsCallback getSimplePromptCallback(final Promise promise) {
        return new ReactNativeBiometricsCallback() {
            @Override
            public void onAuthenticated(BiometricPrompt.AuthenticationResult result) {
                promise.resolve(true);
            }

            @Override
            public void onCancel() {
                promise.reject("User cancelled fingerprint authorization", "User cancelled fingerprint authorization");
            }

            @Override
            public void onError(int errorCode, @NonNull CharSequence errorMessage) {
                promise.reject("Error generating public private keys" , "Error generating public private keys.\n Code: " + errorCode + "\nMessage: " + errorMessage);
            }
        };
    }

    private Executor getMainThreadExecutor(FragmentActivity activity) {
        return new MainThreadExecutor(activity);
    }

    private static class MainThreadExecutor implements Executor {
        protected FragmentActivity activity;

        private MainThreadExecutor(FragmentActivity activity) {
            this.activity = activity;
        }

        @Override
        public void execute(@NonNull Runnable r) {
            activity.runOnUiThread(r);
        }
    }
}
