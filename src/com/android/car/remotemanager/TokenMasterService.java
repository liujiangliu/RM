package com.android.car.remotemanager;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyDescriptor;
import android.util.Log;

import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class TokenMasterService extends Service {
    private static final String TAG = "TokenMasterService";
    private static final long TOKEN_EXPIRY_TIME = 3600; // 1小时
    private static final long CLEANUP_INTERVAL = 300; // 5分钟清理一次过期token
    private static final String KEY_ALIAS = "jwt_hmac_key_ks2";
    
    private final Map<String, JwtTokenInfo> mValidTokens = new ConcurrentHashMap<>();
    private final ScheduledExecutorService mScheduler = Executors.newScheduledThreadPool(1);
    private final SecureRandom mRandom = new SecureRandom();
    
    private SecretKey mHmacKey;
    private RapaServer mRapaServer;
    private boolean mUseKeystore2 = true; // 标记是否使用Keystore2
    
    private final ITokenMasterService.Stub mBinder = new ITokenMasterService.Stub() {
        @Override
        public boolean verifyToken(String token) throws RemoteException {
            return verifyTokenInternal(token, null);
        }
        
        @Override
        public boolean verifyTokenWithScope(String token, String scope) throws RemoteException {
            return verifyTokenInternal(token, scope);
        }
        
        @Override
        public String getTokenInfo(String token) throws RemoteException {
            JwtTokenInfo tokenInfo = mValidTokens.get(token);
            if (tokenInfo != null && !tokenInfo.isExpired()) {
                return tokenInfo.toString();
            }
            return "Token not found or expired";
        }
    };
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "TokenMasterService starting...");
        
        // 尝试使用Keystore2初始化HMAC密钥
        if (!initializeHmacKeyWithKeystore2()) {
            // 降级到旧版Keystore
            Log.w(TAG, "Keystore2 initialization failed, falling back to legacy Keystore");
            initializeHmacKeyWithLegacyKeystore();
        }
        
        startTokenCleanupTask();
        
        // 获取RapaServer实例
        try {
            mRapaServer = new RapaServer();
            mRapaServer.onCreate();
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize RapaServer", e);
        }
        
        Log.i(TAG, "TokenMasterService initialized with " + 
              (mUseKeystore2 ? "Keystore2" : "legacy Keystore"));
    }
    
    @Override
    public void onDestroy() {
        super.onDestroy();
        mScheduler.shutdown();
        Log.d(TAG, "TokenMasterService stopped");
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }
    
    /**
     * 使用Keystore2初始化HMAC密钥
     */
    private boolean initializeHmacKeyWithKeystore2() {
        try {
            // Android 12+ 推荐使用Keystore2
            // 注意：实际使用时需要检查API级别和可用性
            
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
            
            KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(256)
                .setIsStrongBoxBacked(false)
                .setUserAuthenticationRequired(false)
                .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
                .setInvalidatedByBiometricEnrollment(false)
                // Keystore2 特有属性
                .setNamespace(KeyProperties.NAMESPACE_APPLICATION)
                .build();
            
            keyGenerator.init(keySpec);
            mHmacKey = keyGenerator.generateKey();
            
            Log.i(TAG, "HMAC key initialized with Keystore2 successfully");
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "Keystore2 initialization failed: " + e.getMessage(), e);
            mUseKeystore2 = false;
            return false;
        }
    }
    
    /**
     * 使用旧版Keystore初始化HMAC密钥（降级方案）
     */
    private void initializeHmacKeyWithLegacyKeystore() {
        try {
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            
            if (keyStore.containsAlias(KEY_ALIAS)) {
                KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) 
                    keyStore.getEntry(KEY_ALIAS, null);
                mHmacKey = secretKeyEntry.getSecretKey();
                Log.i(TAG, "HMAC key loaded from legacy Keystore");
            } else {
                KeyGenerator keyGenerator = KeyGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_HMAC_SHA256, "AndroidKeyStore");
                
                KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
                    KEY_ALIAS,
                    KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setKeySize(256)
                    .setUserAuthenticationRequired(false)
                    .build();
                
                keyGenerator.init(keySpec);
                mHmacKey = keyGenerator.generateKey();
                Log.i(TAG, "New HMAC key generated with legacy Keystore");
            }
            
        } catch (Exception e) {
            Log.e(TAG, "Legacy Keystore initialization also failed", e);
            // 最终降级：生成软件密钥（仅用于测试）
            initializeSoftwareKey();
        }
    }
    
    /**
     * 软件密钥（最不安全，仅用于测试）
     */
    private void initializeSoftwareKey() {
        try {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacSHA256");
            keyGenerator.init(256);
            mHmacKey = keyGenerator.generateKey();
            Log.w(TAG, "Using software-based HMAC key (INSECURE - for testing only)");
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate software HMAC key", e);
            throw new RuntimeException("HMAC key initialization completely failed", e);
        }
    }
    
    private boolean verifyTokenInternal(String token, String requiredScope) {
        if (token == null) {
            Log.w(TAG, "Token verification failed: token is null");
            return false;
        }
        
        JwtTokenInfo tokenInfo = mValidTokens.get(token);
        if (tokenInfo == null) {
            Log.w(TAG, "Token verification failed: token not found - " + token);
            return false;
        }
        
        if (tokenInfo.isExpired()) {
            Log.w(TAG, "Token verification failed: token expired - " + tokenInfo);
            mValidTokens.remove(token);
            return false;
        }
        
        if (!tokenInfo.verifySignature(mHmacKey)) {
            Log.w(TAG, "Token verification failed: invalid signature");
            mValidTokens.remove(token);
            return false;
        }
        
        if (requiredScope != null && !requiredScope.isEmpty() && 
            !tokenInfo.validateScope(requiredScope)) {
            Log.w(TAG, "Token verification failed: scope mismatch - required: " + 
                  requiredScope + ", token: " + tokenInfo.getScope());
            return false;
        }
        
        Log.d(TAG, "Token verification successful: " + tokenInfo);
        return true;
    }
    
    private void startTokenCleanupTask() {
        mScheduler.scheduleAtFixedRate(() -> {
            try {
                cleanupExpiredTokens();
            } catch (Exception e) {
                Log.e(TAG, "Error in token cleanup task", e);
            }
        }, CLEANUP_INTERVAL, CLEANUP_INTERVAL, TimeUnit.SECONDS);
    }
    
    private void cleanupExpiredTokens() {
        int initialSize = mValidTokens.size();
        Iterator<Map.Entry<String, JwtTokenInfo>> iterator = mValidTokens.entrySet().iterator();
        
        while (iterator.hasNext()) {
            Map.Entry<String, JwtTokenInfo> entry = iterator.next();
            if (entry.getValue().isExpired()) {
                iterator.remove();
                Log.d(TAG, "Cleaned up expired token for client: " + entry.getValue().getClientId());
            }
        }
        
        if (mValidTokens.size() < initialSize) {
            Log.d(TAG, "Token cleanup completed: removed " + (initialSize - mValidTokens.size()) + " expired tokens");
        }
    }
    
    public JwtTokenInfo generateNewToken(String clientId, String scopes) {
        String token = generateJwtToken(clientId, scopes);
        JwtTokenInfo tokenInfo = new JwtTokenInfo(token, clientId, scopes, TOKEN_EXPIRY_TIME, mHmacKey);
        mValidTokens.put(token, tokenInfo);
        
        Log.d(TAG, "Generated new JWT token: " + tokenInfo);
        return tokenInfo;
    }

    public JwtTokenInfo validateTokenForGrpc(String token, String requiredScope) {
        JwtTokenInfo tokenInfo = mValidTokens.get(token);
        if (tokenInfo == null || tokenInfo.isExpired()) {
            return null;
        }
        
        if (!tokenInfo.verifySignature(mHmacKey)) {
            return null;
        }
        
        if (requiredScope != null && !requiredScope.isEmpty() && 
            !tokenInfo.validateScope(requiredScope)) {
            return null;
        }
        
        return tokenInfo;
    }
    
    private String generateJwtToken(String clientId, String scopes) {
        long issuedAt = System.currentTimeMillis() / 1000;
        long expiresAt = issuedAt + TOKEN_EXPIRY_TIME;
        
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String encodedHeader = base64UrlEncode(header.getBytes());
        
        String payload = String.format(
            "{\"iss\":\"remote-manager\",\"sub\":\"%s\",\"aud\":\"car-resources\"," +
            "\"exp\":%d,\"iat\":%d,\"scope\":\"%s\",\"client_id\":\"%s\"}",
            clientId, expiresAt, issuedAt, scopes, clientId
        );
        String encodedPayload = base64UrlEncode(payload.getBytes());
        
        String signingInput = encodedHeader + "." + encodedPayload;
        String signature = generateHmacSignature(signingInput, mHmacKey);
        
        return encodedHeader + "." + encodedPayload + "." + signature;
    }
    
    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
    
    private String generateHmacSignature(String data, SecretKey key) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            byte[] signature = mac.doFinal(data.getBytes());
            return base64UrlEncode(signature);
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate HMAC signature", e);
            throw new RuntimeException("HMAC signature generation failed", e);
        }
    }
    
    /**
     * 获取Keystore版本信息
     */
    public String getKeystoreVersion() {
        if (mUseKeystore2) {
            return "KEYSTORE2_ACTIVE";
        } else {
            return "LEGACY_KEYSTORE_ACTIVE";
        }
    }
    
    /**
     * 密钥轮换
     */
    public boolean rotateHmacKey() {
        try {
            // 删除现有密钥
            KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
            if (keyStore.containsAlias(KEY_ALIAS)) {
                keyStore.deleteEntry(KEY_ALIAS);
            }
            
            // 重新初始化（优先使用Keystore2）
            if (!initializeHmacKeyWithKeystore2()) {
                initializeHmacKeyWithLegacyKeystore();
            }
            
            // 清除所有token
            int clearedTokens = mValidTokens.size();
            mValidTokens.clear();
            
            Log.i(TAG, "HMAC key rotated successfully, cleared " + clearedTokens + " tokens");
            return true;
            
        } catch (Exception e) {
            Log.e(TAG, "HMAC key rotation failed", e);
            return false;
        }
    }
    
    // 供gRPC服务调用的方法
    public RapaServer getRapaServer() {
        return mRapaServer;
    }
    
    public int getActiveTokenCount() {
        return mValidTokens.size();
    }
}