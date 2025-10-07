package com.android.car.remotemanager.ssl;

import android.security.KeyStore2;
import android.system.keystore2.Domain;
import android.system.keystore2.KeyDescriptor;
import android.system.keystore2.KeyEntryResponse;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;

public class MAX509Manager {
    private static final String TAG = "MAX509Manager";
    
    public static final int TYPE_TLS = 0;

    public SSLContext getSSLContext(int type) {
        switch (type) {
            case TYPE_TLS:
                return getTLSSSLContext();
            default:
                return null;
        }
    }

    public MACustomX509KeyManager getTLSMACustomX509KeyManager() {
        return new MACustomX509KeyManager("security_signature_1", KeyStore2.getInstance(), null, getSecuritySignatureKDS());
    }

    public CustomX509TrustManager getTLSCustomX509TrustManager() {
        return new CustomX509TrustManager(readRootCert());
    }

    private KeyDescriptor getSecuritySignatureKDS() {
        KeyDescriptor kds = new KeyDescriptor();
        kds.domain = Domain.SELINUX;
        kds.alias = "security_signature_1";
        kds.nspace = 30101;
        kds.blob = null;
        return kds;
    }

    private KeyDescriptor getRootKDS() {
        KeyDescriptor kds = new KeyDescriptor();
        kds.domain = Domain.SELINUX;
        kds.alias = "root_cc";
        kds.nspace = 30100;
        kds.blob = null;
        return kds;
    }

    private SSLContext getTLSSSLContext() {
        KeyStore2 keyStore2 = KeyStore2.getInstance();
        return createTLSSSLContext("security_signature_1", keyStore2, null, getSecuritySignatureKDS());
    }

    private SSLContext createTLSSSLContext(String keyAlias, KeyStore2 keyStore, char[] keyPassword, KeyDescriptor kd) {
        try {
            MACustomX509KeyManager keyManager = new MACustomX509KeyManager(
                    keyAlias,
                    keyStore,
                    keyPassword,
                    kd
            );
            CustomX509TrustManager trustManager = new CustomX509TrustManager(readRootCert());
            
            SSLContext sslContext = SSLContext.getInstance("TLSv1.3");
            sslContext.init(new KeyManager[]{keyManager}, new TrustManager[]{trustManager}, null);
            
            Log.d(TAG, "TLS SSLContext initialized successfully");
            return sslContext;
            
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            Log.e(TAG, "Failed to create SSLContext", e);
            return null;
        }
    }

    private X509Certificate readRootCert() {
        try {
            KeyStore2 keyStore = KeyStore2.getInstance();
            KeyEntryResponse resp = keyStore.getKeyEntry(getRootKDS());
            byte[] x509PublicCert = resp.metadata.certificate;
            
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certFactory.generateCertificate(
                    new ByteArrayInputStream(x509PublicCert)
            );
        } catch (Exception e) {
            Log.e(TAG, "Failed to read root certificate", e);
            return null;
        }
    }
}
