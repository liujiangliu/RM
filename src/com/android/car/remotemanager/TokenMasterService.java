package com.android.car.remotemanager;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class TokenMasterService extends Service {
    private static final String TAG = "TokenMasterService";
    private static final long TOKEN_EXPIRY_TIME = 3600; // 1小时
    private static final long CLEANUP_INTERVAL = 300; // 5分钟清理一次过期token
    
    private final Map<String, JwtTokenInfo> mValidTokens = new ConcurrentHashMap<>();
    private final ScheduledExecutorService mScheduler = Executors.newScheduledThreadPool(1);
    private final SecureRandom mRandom = new SecureRandom();
    private final String mJwtSecret;
    
    private RapaServer mRapaServer;
    
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
    
    public TokenMasterService() {
        // 生成JWT签名密钥
        this.mJwtSecret = generateJwtSecret();
    }
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "TokenMasterService starting...");
        startTokenCleanupTask();
        
        // 获取RapaServer实例
        try {
            mRapaServer = new RapaServer();
            mRapaServer.onCreate();
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize RapaServer", e);
        }
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
        
        // 检查token是否过期
        if (tokenInfo.isExpired()) {
            Log.w(TAG, "Token verification failed: token expired - " + tokenInfo);
            mValidTokens.remove(token); // 移除过期token
            return false;
        }
        
        // 验证JWT签名
        if (!tokenInfo.verifySignature(mJwtSecret)) {
            Log.w(TAG, "Token verification failed: invalid signature");
            mValidTokens.remove(token);
            return false;
        }
        
        // 检查scope（如果指定了requiredScope）
        if (requiredScope != null && !requiredScope.isEmpty()) {
            if (!tokenInfo.validateScope(requiredScope)) {
                Log.w(TAG, "Token verification failed: scope mismatch - required: " + 
                      requiredScope + ", token: " + tokenInfo.getScope());
                return false;
            }
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
        JwtTokenInfo tokenInfo = new JwtTokenInfo(token, clientId, scopes, TOKEN_EXPIRY_TIME, mJwtSecret);
        mValidTokens.put(token, tokenInfo);
        
        Log.d(TAG, "Generated new JWT token: " + tokenInfo);
        return tokenInfo;
    }
    
    public JwtTokenInfo validateTokenForGrpc(String token, String requiredScope) {
        JwtTokenInfo tokenInfo = mValidTokens.get(token);
        if (tokenInfo == null || tokenInfo.isExpired()) {
            return null;
        }
        
        if (!tokenInfo.verifySignature(mJwtSecret)) {
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
        
        // 构建JWT Header
        String header = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
        String encodedHeader = base64UrlEncode(header.getBytes());
        
        // 构建JWT Payload
        String payload = String.format(
            "{\"iss\":\"remote-manager\",\"sub\":\"%s\",\"aud\":\"car-resources\"," +
            "\"exp\":%d,\"iat\":%d,\"scope\":\"%s\",\"client_id\":\"%s\"}",
            clientId, expiresAt, issuedAt, scopes, clientId
        );
        String encodedPayload = base64UrlEncode(payload.getBytes());
        
        // 构建签名
        String signingInput = encodedHeader + "." + encodedPayload;
        String signature = generateHmacSignature(signingInput, mJwtSecret);
        String encodedSignature = base64UrlEncode(signature.getBytes());
        
        // 组合JWT
        return encodedHeader + "." + encodedPayload + "." + encodedSignature;
    }
    
    private String generateJwtSecret() {
        byte[] secretBytes = new byte[32];
        mRandom.nextBytes(secretBytes);
        return base64UrlEncode(secretBytes);
    }
    
    private String base64UrlEncode(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
    
    private String generateHmacSignature(String data, String secret) {
        try {
            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKeySpec = 
                new javax.crypto.spec.SecretKeySpec(secret.getBytes(), "HmacSHA256");
            mac.init(secretKeySpec);
            byte[] signature = mac.doFinal(data.getBytes());
            return new String(signature);
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate HMAC signature", e);
            throw new RuntimeException("HMAC signature generation failed", e);
        }
    }
    
    // 供gRPC服务调用的方法
    public RapaServer getRapaServer() {
        return mRapaServer;
    }
    
    // 用于调试和监控的方法
    public int getActiveTokenCount() {
        return mValidTokens.size();
    }
}
