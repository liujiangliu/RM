package com.android.car.remotemanager;

interface IRapaServer {
    String generatePin();
    String getStoredPin();
    boolean verifyPairing(String clientId, String clientSecret);
}
