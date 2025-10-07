lspackage com.android.car.remotemanager;

import android.util.Log;

import java.util.Base64;

/**
 * JWT Token信息类，包含完整的JWT token元数据
 */
public class JwtTokenInfo {
    private static final String TAG = "JwtTokenInfo";
    
    private final String token;
    private final String clientId;
    private final String scope;
    private final long issuedAt;
    private final long expiresAt;
    private final String tokenType;
    private final String jwtSecret;
    
    public JwtTokenInfo(String token, String clientId, String scope, long expiresIn, String jwtSecret) {
        this.token = token;
        this.clientId = clientId;
        this.scope = scope;
        this.issuedAt = System.currentTimeMillis();
        this.expiresAt = this.issuedAt + (expiresIn * 1000); // 转换为毫秒
        this.tokenType = "JWT";
        this.jwtSecret = jwtSecret;
    }
    
    // Getters
    public String getToken() { return token; }
    public String getClientId() { return clientId; }
    public String getScope() { return scope; }
    public long getIssuedAt() { return issuedAt; }
    public long getExpiresAt() { return expiresAt; }
    public String getTokenType() { return tokenType; }
    
    /**
     * 验证token是否有效
     */
    public boolean isValid() {
        return !isExpired();
    }
    
    /**
     * 验证token是否过期
     */
    public boolean isExpired() {
        return System.currentTimeMillis() > expiresAt;
    }
    
    /**
     * 验证JWT签名
     */
    public boolean verifySignature(String secret) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return false;
            }
            
            String signingInput = parts[0] + "." + parts[1];
            String expectedSignature = generateHmacSignature(signingInput, secret);
            String actualSignature = new String(Base64.getUrlDecoder().decode(parts[2]));
            
            return expectedSignature.equals(actualSignature);
        } catch (Exception e) {
            Log.e(TAG, "JWT signature verification failed", e);
            return false;
        }
    }
    
    /**
     * 验证scope是否匹配
     */
    public boolean validateScope(String requiredScope) {
        if (requiredScope == null || requiredScope.isEmpty()) {
            return true; // 没有要求scope，默认通过
        }
        
        // 简单的scope验证：要求scope必须是token scope的子集
        String[] tokenScopes = scope.split(" ");
        String[] requiredScopes = requiredScope.split(" ");
        
        for (String reqScope : requiredScopes) {
            boolean found = false;
            for (String tokenScope : tokenScopes) {
                if (tokenScope.equals(reqScope)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                Log.d(TAG, "Scope validation failed: required " + reqScope + " not found in " + scope);
                return false;
            }
        }
        
        return true;
    }
    
    /**
     * 获取剩余有效时间（秒）
     */
    public long getRemainingTime() {
        long remaining = (expiresAt - System.currentTimeMillis()) / 1000;
        return Math.max(0, remaining);
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
    
    @Override
    public String toString() {
        return String.format(
            "JwtTokenInfo{clientId=%s, scope=%s, issuedAt=%d, expiresAt=%d, remaining=%ds}",
            clientId, scope, issuedAt, expiresAt, getRemainingTime()
        );
    }
}
