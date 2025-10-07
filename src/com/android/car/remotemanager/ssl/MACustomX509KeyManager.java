package com.android.car.remotemanager.ssl;

import android.security.KeyStore2;
import android.system.keystore2.KeyDescriptor;
import android.util.Log;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

public class MACustomX509KeyManager extends X509ExtendedKeyManager {
    private static final String TAG = "MACustomX509KeyManager";
    
    private final String mAlias;
    private final KeyStore2 mKeyStore;
    private final char[] mPassword;
    private final KeyDescriptor mKeyDescriptor;
    
    public MACustomX509KeyManager(String alias, KeyStore2 keyStore, char[] password, KeyDescriptor keyDescriptor) {
        this.mAlias = alias;
        this.mKeyStore = keyStore;
        this.mPassword = password;
        this.mKeyDescriptor = keyDescriptor;
    }
    
    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
        Log.d(TAG, "chooseClientAlias called");
        return mAlias;
    }
    
    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
        Log.d(TAG, "chooseServerAlias called");
        return mAlias;
    }
    
    @Override
    public X509Certificate[] getCertificateChain(String alias) {
        try {
            if (mAlias.equals(alias)) {
                android.system.keystore2.KeyEntryResponse response = mKeyStore.getKeyEntry(mKeyDescriptor);
                if (response != null && response.metadata.certificate != null) {
                    java.security.cert.CertificateFactory certFactory = 
                        java.security.cert.CertificateFactory.getInstance("X.509");
                    X509Certificate cert = (X509Certificate) certFactory.generateCertificate(
                            new java.io.ByteArrayInputStream(response.metadata.certificate)
                    );
                    return new X509Certificate[]{cert};
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get certificate chain", e);
        }
        return null;
    }
    
    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
        return new String[]{mAlias};
    }
    
    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
        return new String[]{mAlias};
    }
    
    @Override
    public PrivateKey getPrivateKey(String alias) {
        try {
            if (mAlias.equals(alias)) {
                android.system.keystore2.KeyEntryResponse response = mKeyStore.getKeyEntry(mKeyDescriptor);
                if (response != null && response.iSecurityLevel != null) {
                    return new TEEPrivateKey(response);
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get private key", e);
        }
        return null;
    }
    
    private static class TEEPrivateKey implements PrivateKey {
        private final android.system.keystore2.KeyEntryResponse mResponse;
        
        TEEPrivateKey(android.system.keystore2.KeyEntryResponse response) {
            this.mResponse = response;
        }
        
        @Override
        public String getAlgorithm() {
            return "RSA";
        }
        
        @Override
        public String getFormat() {
            return "PKCS#8";
        }
        
        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }
}
