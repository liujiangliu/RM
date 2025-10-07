package com.android.car.remotemanager.tee;

import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

public class EncryptedTeeSecretManager {
    private static final String TAG = "EncryptedTeeSecretManager";
    private static final String PREFS_NAME = "encrypted_client_secrets";
    private static final String MASTER_KEY_ALIAS = "__remote_manager_master_key__";
    
    private SharedPreferences encryptedPrefs;
    
    public EncryptedTeeSecretManager(Context context) {
        try {
            MasterKey masterKey = new MasterKey.Builder(context, MASTER_KEY_ALIAS)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build();
            
            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );
            
            Log.i(TAG, "EncryptedTeeSecretManager initialized");
        } catch (Exception e) {
            Log.e(TAG, "Encrypted storage init failed", e);
            throw new RuntimeException("Encrypted storage init failed", e);
        }
    }
    
    /**
     * 使用Android官方加密存储
     */
    public boolean storeClientSecret(String clientId, String clientSecret) {
        Log.i(TAG, "Storing client_secret in encrypted storage: " + clientId);
        
        try {
            SharedPreferences.Editor editor = encryptedPrefs.edit();
            editor.putString(clientId, clientSecret);
            boolean success = editor.commit();
            
            if (success) {
                Log.i(TAG, "Client_secret stored in encrypted storage: " + clientId);
            }
            return success;
            
        } catch (Exception e) {
            Log.e(TAG, "Encrypted storage failed", e);
            return false;
        }
    }
    
    public String retrieveClientSecret(String clientId) {
        Log.i(TAG, "Retrieving client_secret from encrypted storage: " + clientId);
        
        try {
            String secret = encryptedPrefs.getString(clientId, null);
            if (secret != null) {
                Log.i(TAG, "Client_secret retrieved from encrypted storage: " + clientId);
            }
            return secret;
        } catch (Exception e) {
            Log.e(TAG, "Encrypted retrieval failed", e);
            return null;
        }
    }
    
    public boolean verifyClientSecret(String clientId, String clientSecret) {
        String stored = retrieveClientSecret(clientId);
        return stored != null && stored.equals(clientSecret);
    }
}