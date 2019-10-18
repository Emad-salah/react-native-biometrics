package com.rnbiometrics;

import android.annotation.TargetApi;
import android.app.Activity;
import androidx.fragment.app.DialogFragment;
import androidx.fragment.app.FragmentActivity;
import android.content.Context;
import android.content.DialogInterface;
import androidx.biometric.BiometricPrompt;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.Nullable;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.TextView;
import com.rnbiometrics.R;

import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

/**
 * Created by brandon on 4/6/18.
 */

@TargetApi(Build.VERSION_CODES.M)
public class ReactNativeBiometricsDialog extends DialogFragment implements ReactNativeBiometricsCallback {

    protected String title;
    protected BiometricPrompt.CryptoObject cryptoObject;
    protected ReactNativeBiometricsCallback biometricAuthCallback;

    protected ReactNativeBiometricsHelper biometricAuthenticationHelper;
    protected Activity activity;
    protected Button cancelButton;

    public void init(String title, BiometricPrompt.CryptoObject cryptoObject, ReactNativeBiometricsCallback callback) {
        this.title = title;
        this.cryptoObject = cryptoObject;
        this.biometricAuthCallback = callback;
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setStyle(DialogFragment.STYLE_NORMAL, R.style.BiometricsDialog);
    }

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, @Nullable ViewGroup container, Bundle savedInstanceState) {
        getDialog().setTitle(title);
        View view = inflater.inflate(R.layout.fingerprint_dialog_container, container, false);
        Executor executor = Executors.newSingleThreadExecutor();
        cancelButton = (Button) view.findViewById(R.id.cancel_button);
        cancelButton.setText(R.string.fingerprint_cancel);
        cancelButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                dismissAllowingStateLoss();
                onCancel();
            }
        });

        BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(this.title)
                .setNegativeButtonText("Cancel")
                .build();

        FragmentActivity activityFrag = (FragmentActivity) activity;

        biometricAuthenticationHelper = new ReactNativeBiometricsHelper(
                new BiometricPrompt(activityFrag.getSupportFragmentManager().findFragmentByTag("fingerprint_dialog"), executor, new BiometricPrompt.AuthenticationCallback() {
                    public void onAuthenticated(BiometricPrompt.CryptoObject cryptoObject) {
                        dismissAllowingStateLoss();
                        if (biometricAuthCallback != null) {
                            biometricAuthCallback.onAuthenticated(cryptoObject);
                        }
                    }

                    public void onCancel() {
                        if (biometricAuthCallback != null) {
                            biometricAuthCallback.onCancel();
                        }
                    }

                    public void onError() {
                        dismissAllowingStateLoss();
                        if (biometricAuthCallback != null) {
                            biometricAuthCallback.onError();
                        }
                    }
                }),
                (ImageView) view.findViewById(R.id.fingerprint_icon),
                (TextView) view.findViewById(R.id.fingerprint_status),
                promptInfo,
                this
        );

        return view;
    }

    // DialogFragment lifecycle methods
    @Override
    public void onAttach(Context context) {
        super.onAttach(context);
        activity = getActivity();
    }

    @Override
    public void onPause() {
        super.onPause();
        biometricAuthenticationHelper.stopListening();
    }

    @Override
    public void onResume() {
        super.onResume();
        biometricAuthenticationHelper.startListening(cryptoObject);
    }

    @Override
    public void onCancel(DialogInterface dialog) {
        super.onCancel(dialog);
        onCancel();
    }

    // ReactNativeBiometricsCallback methods
    @Override
    public void onAuthenticated(BiometricPrompt.CryptoObject cryptoObject) {
        dismissAllowingStateLoss();
        if (biometricAuthCallback != null) {
            biometricAuthCallback.onAuthenticated(cryptoObject);
        }
    }

    @Override
    public void onCancel() {
        if (biometricAuthCallback != null) {
            biometricAuthCallback.onCancel();
        }
    }

    @Override
    public void onError() {
        dismissAllowingStateLoss();
        if (biometricAuthCallback != null) {
            biometricAuthCallback.onError();
        }
    }
}
