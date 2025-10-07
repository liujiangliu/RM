package com.android.car.remotemanager;

import android.app.Application;
import android.util.Log;

import com.android.car.remotemanager.tee.TeeSecretManager;

public class RemoteManagerApplication extends Application {
    private static final String TAG = "RemoteManagerApp";
    private TeeSecretManager mTeeSecretManager;
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "RemoteManagerApplication starting...");
        
        // 初始化TEE存储管理器
        initializeTeeStorage();
        
        // 启动gRPC服务器
        startGrpcServer();
    }
    
    private void initializeTeeStorage() {
        try {
            mTeeSecretManager = new TeeSecretManager();
            Log.d(TAG, "TEE storage initialized: " + mTeeSecretManager.getStorageStatus());
        } catch (Exception e) {
            Log.e(TAG, "Failed to initialize TEE storage", e);
            // 可以在这里实现降级方案
        }
    }
    
    private void startGrpcServer() {
        try {
            GrpcServerService grpcService = new GrpcServerService(this, mTeeSecretManager);
            grpcService.start();
            Log.d(TAG, "gRPC server started successfully");
        } catch (Exception e) {
            Log.e(TAG, "Failed to start gRPC server", e);
        }
    }
    
    public TeeSecretManager getTeeSecretManager() {
        return mTeeSecretManager;
    }
    
    @Override
    public void onTerminate() {
        super.onTerminate();
        Log.d(TAG, "RemoteManagerApplication terminating...");
    }
}
