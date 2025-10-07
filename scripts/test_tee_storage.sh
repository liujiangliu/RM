#!/bin/bash

echo "Testing TEE storage functionality..."

# 创建简单的TEE测试应用
mkdir -p ../TeeTestApp/src/com/example/teetest
cat > ../TeeTestApp/src/com/example/teetest/TeeTestApp.java << 'TESTEOF'
package com.example.teetest;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;

import com.android.car.remotemanager.tee.TeeSecretManager;

public class TeeTestApp extends Activity {
    private static final String TAG = "TeeTestApp";
    private TeeSecretManager mTeeManager;
    
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        
        Log.d(TAG, "Testing TEE storage...");
        
        try {
            mTeeManager = new TeeSecretManager();
            
            // 测试存储client_secret
            String clientId = "test_client_123";
            String clientSecret = "test_secret_456";
            
            boolean storeSuccess = mTeeManager.storeClientSecret(clientId, clientSecret);
            Log.d(TAG, "Store client_secret: " + (storeSuccess ? "SUCCESS" : "FAILED"));
            
            // 测试读取client_secret
            String retrievedSecret = mTeeManager.retrieveClientSecret(clientId);
            Log.d(TAG, "Retrieve client_secret: " + (retrievedSecret != null ? "SUCCESS" : "FAILED"));
            
            // 测试验证client_secret
            boolean verifySuccess = mTeeManager.verifyClientSecret(clientId, clientSecret);
            Log.d(TAG, "Verify client_secret: " + (verifySuccess ? "VALID" : "INVALID"));
            
            // 测试错误client_secret
            boolean verifyFail = mTeeManager.verifyClientSecret(clientId, "wrong_secret");
            Log.d(TAG, "Verify wrong secret: " + (verifyFail ? "UNEXPECTED_VALID" : "EXPECTED_INVALID"));
            
            Log.d(TAG, "TEE Storage Status: " + mTeeManager.getStorageStatus());
            
        } catch (Exception e) {
            Log.e(TAG, "TEE test failed", e);
        }
    }
}
TESTEOF

echo "TEE test application created in parent directory"
echo "To test TEE functionality:"
echo "1. Deploy RemoteManagerApp to device"
echo "2. Run the TeeTestApp to verify TEE storage"
echo "3. Check logcat for TEE operation results"
