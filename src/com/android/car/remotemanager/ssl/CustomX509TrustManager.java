package com.android.car.remotemanager.ssl;

import android.util.Log;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;

public class CustomX509TrustManager implements X509TrustManager {
    private static final String TAG = "CustomX509TrustManager";
    
    private final X509Certificate mRootCertificate;
    
    public CustomX509TrustManager(X509Certificate rootCertificate) {
        this.mRootCertificate = rootCertificate;
    }
    
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        Log.d(TAG, "Checking client trust with authType: " + authType);
        
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Client certificate chain is empty");
        }
        
        try {
            if (mRootCertificate != null) {
                chain[0].verify(mRootCertificate.getPublicKey());
            }
            
            Log.d(TAG, "Client certificate verified successfully");
        } catch (Exception e) {
            Log.e(TAG, "Client certificate verification failed", e);
            throw new CertificateException("Client certificate verification failed", e);
        }
    }
    
    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        Log.d(TAG, "Checking server trust with authType: " + authType);
        
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Server certificate chain is empty");
        }
        
        try {
            if (mRootCertificate != null) {
                chain[0].verify(mRootCertificate.getPublicKey());
            }
            
            Log.d(TAG, "Server certificate verified successfully");
        } catch (Exception e) {
            Log.e(TAG, "Server certificate verification failed", e);
            throw new CertificateException("Server certificate verification failed", e);
        }
    }
    
    @Override
    public X509Certificate[] getAcceptedIssuers() {
        if (mRootCertificate != null) {
            return new X509Certificate[]{mRootCertificate};
        }
        return new X509Certificate[0];
    }
}
