package com.android.car.remotemanager;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import android.os.RemoteException;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RapaServer extends Service {
    private static final String TAG = "RapaServer";
    private static final String PIN_FILE = "rapa_pin.dat";
    
    private final Map<String, PairedDevice> mPairedDevices = new ConcurrentHashMap<>();
    private final SecureRandom mRandom = new SecureRandom();
    
    private String mCurrentPin;
    private EncryptedTeeSecretManager mEncryptedSecretManager;
    
    private final IRapaServer.Stub mBinder = new IRapaServer.Stub() {
        @Override
        public String generatePin() throws RemoteException {
            return generatePinInternal();
        }
        
        @Override
        public String getStoredPin() throws RemoteException {
            return mCurrentPin;
        }
        
        @Override
        public boolean verifyPairing(String clientId, String clientSecret) throws RemoteException {
            return verifyPairingInternal(clientId, clientSecret);
        }
    };
    
    @Override
    public void onCreate() {
        super.onCreate();
        Log.d(TAG, "RapaServer starting...");
        
        // 初始化加密存储管理器
        mEncryptedSecretManager = new EncryptedTeeSecretManager(this);
        loadStoredData();
    }
    
    @Override
    public IBinder onBind(Intent intent) {
        return mBinder;
    }
    
    private String generatePinInternal() {
        int pin = 100000 + mRandom.nextInt(900000);
        mCurrentPin = String.valueOf(pin);
        savePinToStorage(mCurrentPin);
        Log.d(TAG, "Generated new PIN: " + mCurrentPin);
        return mCurrentPin;
    }
    
    private boolean verifyPairingInternal(String clientId, String clientSecret) {
        if (clientId == null || clientSecret == null) {
            return false;
        }
        return mEncryptedSecretManager.verifyClientSecret(clientId, clientSecret);
    }
    
    private void savePinToStorage(String pin) {
        try {
            File file = new File(getFilesDir(), PIN_FILE);
            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(pin.getBytes());
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to save PIN", e);
        }
    }
    
    private void loadStoredData() {
        try {
            File file = new File(getFilesDir(), PIN_FILE);
            if (file.exists()) {
                try (FileInputStream fis = new FileInputStream(file)) {
                    byte[] data = new byte[(int) file.length()];
                    fis.read(data);
                    mCurrentPin = new String(data);
                    Log.d(TAG, "Loaded stored PIN: " + mCurrentPin);
                }
            }
        } catch (IOException e) {
            Log.e(TAG, "Failed to load PIN", e);
        }
    }
    
    // 配对设备管理
    public static class PairedDevice {
        public String deviceName;
        public String appType;
        public String source;
        public String macAddr;
        public String clientId;
        public String clientName;
        public String scopes;
        public long pairedTime;
        
        public PairedDevice(String deviceName, String appType, String source, 
                           String macAddr, String clientId, String clientName, String scopes) {
            this.deviceName = deviceName;
            this.appType = appType;
            this.source = source;
            this.macAddr = macAddr;
            this.clientId = clientId;
            this.clientName = clientName;
            this.scopes = scopes;
            this.pairedTime = System.currentTimeMillis();
        }
    }
    
    public boolean verifyPinHash(String pinHash) {
        if (mCurrentPin == null) return false;
        
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            byte[] hash = digest.digest(mCurrentPin.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                hexString.append(String.format("%02x", b));
            }
            String calculatedHash = hexString.toString();
            return calculatedHash.equals(pinHash);
        } catch (Exception e) {
            Log.e(TAG, "Error verifying PIN hash", e);
            return false;
        }
    }
    
    public String addPairedDevice(PairedDevice device, String clientSecret) {
        mPairedDevices.put(device.clientId, device);
        
        // 使用加密存储
        boolean storageSuccess = mEncryptedSecretManager.storeClientSecret(device.clientId, clientSecret);
        if (!storageSuccess) {
            Log.e(TAG, "Failed to store client_secret in encrypted storage for client: " + device.clientId);
        } else {
            Log.i(TAG, "Client secret stored in encrypted storage for client: " + device.clientId);
        }
        
        Log.d(TAG, "Paired new device: " + device.deviceName + " with clientId: " + device.clientId);
        return clientSecret;
    }
    
    public boolean verifyClientSecret(String clientId, String clientSecret) {
        return mEncryptedSecretManager.verifyClientSecret(clientId, clientSecret);
    }
    
    public boolean verifyScopes(String clientId, String scopes) {
        PairedDevice device = mPairedDevices.get(clientId);
        return device != null && device.scopes.equals(scopes);
    }
    
    public String generateClientSecret() {
        byte[] secretBytes = new byte[32];
        mRandom.nextBytes(secretBytes);
        
        StringBuilder sb = new StringBuilder();
        for (byte b : secretBytes) {
            sb.append(String.format("%02x", b));
        }
        return "cs_" + sb.toString();
    }
    
    public int getPairedDeviceCount() {
        return mPairedDevices.size();
    }
}