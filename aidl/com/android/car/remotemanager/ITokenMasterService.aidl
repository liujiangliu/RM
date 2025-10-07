package com.android.car.remotemanager;

interface ITokenMasterService {
    boolean verifyToken(String token);
    boolean verifyTokenWithScope(String token, String scope);
    String getTokenInfo(String token);
}
