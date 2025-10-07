package com.android.car.remotemanager;

import android.content.Context;
import android.util.Log;

import com.android.car.remotemanager.ssl.MAX509Manager;
import com.android.car.remotemanager.tee.TeeSecretManager;

import io.grpc.Server;
import io.grpc.stub.StreamObserver;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyServerBuilder;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.SslProvider;

import java.io.IOException;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;

public class GrpcServerService {
    private static final String TAG = "GrpcServerService";
    private static final int GRPC_PORT = 8443;
    
    private Server mGrpcServer;
    private Context mContext;
    private TeeSecretManager mTeeSecretManager;
    
    private RapaServer mRapaServer;
    private TokenMasterService mTokenMasterService;
    
    public GrpcServerService(Context context, TeeSecretManager teeSecretManager) {
        this.mContext = context;
        this.mTeeSecretManager = teeSecretManager;
        this.mRapaServer = new RapaServer(teeSecretManager);
        this.mTokenMasterService = new TokenMasterService();
    }
    
    public void start() throws IOException {
        SSLContext sslContext = createSSLContext();
        
        // 启动合并的gRPC服务
        startMergedGrpcServer(sslContext);
        
        Log.d(TAG, "gRPC server started successfully on port: " + GRPC_PORT);
        Log.d(TAG, "TEE Storage Status: " + mRapaServer.getStorageStatus());
    }
    
    private SSLContext createSSLContext() {
        try {
            MAX509Manager maX509Manager = new MAX509Manager();
            SSLContext sslContext = maX509Manager.getSSLContext(MAX509Manager.TYPE_TLS);
            
            if (sslContext == null) {
                throw new RuntimeException("Failed to create SSLContext");
            }
            
            Log.d(TAG, "SSLContext created successfully with protocol: " + sslContext.getProtocol());
            return sslContext;
        } catch (Exception e) {
            Log.e(TAG, "Failed to create SSLContext", e);
            throw new RuntimeException("SSLContext creation failed", e);
        }
    }
    
    private void startMergedGrpcServer(SSLContext sslContext) throws IOException {
        mGrpcServer = NettyServerBuilder.forPort(GRPC_PORT)
                .sslContext(GrpcSslContexts.configure(
                        SslContextBuilder.forServer(sslContext)
                                .clientAuth(ClientAuth.REQUIRE)
                                .sslProvider(SslProvider.OPENSSL))
                        .build())
                .addService(new RemoteManagerServiceImpl(mRapaServer, mTokenMasterService))
                .executor(Executors.newFixedThreadPool(4))
                .build()
                .start();
        
        Log.d(TAG, "Merged gRPC service started on port: " + GRPC_PORT);
        
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            Log.d(TAG, "Shutting down gRPC server");
            if (mGrpcServer != null) {
                mGrpcServer.shutdown();
            }
        }));
        
        // 保持服务器运行
        keepServerRunning();
    }
    
    private void keepServerRunning() {
        Thread serverThread = new Thread(() -> {
            try {
                mGrpcServer.awaitTermination();
            } catch (InterruptedException e) {
                Log.e(TAG, "gRPC server interrupted", e);
                Thread.currentThread().interrupt();
            }
        });
        serverThread.setDaemon(false);
        serverThread.start();
    }
    
    // 合并的gRPC服务实现
    private static class RemoteManagerServiceImpl extends RemoteManagerProto.RemoteManagerServiceImplBase {
        private final RapaServer mRapaServer;
        private final TokenMasterService mTokenMasterService;
        
        public RemoteManagerServiceImpl(RapaServer rapaServer, TokenMasterService tokenMasterService) {
            this.mRapaServer = rapaServer;
            this.mTokenMasterService = tokenMasterService;
            
            // 初始化服务
            this.mRapaServer.onCreate();
            this.mTokenMasterService.onCreate();
        }
        
        @Override
        public void requestPairing(RemoteManagerProto.PairingRequest request, 
                                 StreamObserver<RemoteManagerProto.PairingResponse> responseObserver) {
            Log.d(TAG, "Received pairing request from: " + request.getDeviceName());
            
            RemoteManagerProto.PairingResponse.Builder response = RemoteManagerProto.PairingResponse.newBuilder();
            
            try {
                // 步骤a: 验证PIN哈希
                boolean pinValid = mRapaServer.verifyPinHash(request.getPinHash());
                
                if (!pinValid) {
                    response.setStatus("FAILED")
                           .setMessage("PIN verification failed");
                    responseObserver.onNext(response.build());
                    responseObserver.onCompleted();
                    return;
                }
                
                // 步骤b: PIN验证成功，创建设备记录
                RapaServer.PairedDevice device = 
                    new RapaServer.PairedDevice(
                        request.getDeviceName(),
                        request.getAppType(),
                        request.getSource(),
                        request.getMacAddr(),
                        request.getClientId(),
                        request.getClientName(),
                        request.getScopes()
                    );
                
                String clientSecret = mRapaServer.generateClientSecret();
                mRapaServer.addPairedDevice(device, clientSecret);
                
                // 生成初始JWT token
                JwtTokenInfo initialToken = mTokenMasterService.generateNewToken(
                    request.getClientId(), request.getScopes());
                
                response.setStatus("SUCCESS")
                       .setClientSecret(clientSecret)
                       .setToken(initialToken.getToken())
                       .setExpiresAt(initialToken.getExpiresAt())
                       .setMessage("Pairing successful");
                
                Log.d(TAG, "Pairing successful for device: " + request.getDeviceName());
                Log.d(TAG, "Client_secret stored in TEE for client: " + request.getClientId());
                
            } catch (Exception e) {
                Log.e(TAG, "Error processing pairing request", e);
                response.setStatus("ERROR")
                       .setMessage("Internal server error: " + e.getMessage());
            }
            
            responseObserver.onNext(response.build());
            responseObserver.onCompleted();
        }
        
        @Override
        public void requestToken(RemoteManagerProto.TokenRequest request, 
                               StreamObserver<RemoteManagerProto.TokenResponse> responseObserver) {
            Log.d(TAG, "Received token request from client: " + request.getClientId());
            
            RemoteManagerProto.TokenResponse.Builder response = RemoteManagerProto.TokenResponse.newBuilder();
            
            try {
                // 步骤a: 验证client_secret（从TEE中验证）
                boolean secretValid = mRapaServer.verifyClientSecret(
                    request.getClientId(), request.getClientSecret());
                
                if (!secretValid) {
                    response.setStatus("FAILED")
                           .setMessage("Client secret verification failed");
                    responseObserver.onNext(response.build());
                    responseObserver.onCompleted();
                    return;
                }
                
                // 步骤b: 验证scopes
                boolean scopesValid = mRapaServer.verifyScopes(
                    request.getClientId(), request.getScopes());
                
                if (!scopesValid) {
                    response.setStatus("FAILED")
                           .setMessage("Scopes verification failed");
                    responseObserver.onNext(response.build());
                    responseObserver.onCompleted();
                    return;
                }
                
                JwtTokenInfo newToken = mTokenMasterService.generateNewToken(
                    request.getClientId(), request.getScopes());
                
                response.setStatus("SUCCESS")
                       .setToken(newToken.getToken())
                       .setExpiresAt(newToken.getExpiresAt())
                       .setTokenType(newToken.getTokenType())
                       .setScope(newToken.getScope())
                       .setMessage("Token issued successfully");
                
                Log.d(TAG, "JWT Token issued for client: " + request.getClientId());
                
            } catch (Exception e) {
                Log.e(TAG, "Error processing token request", e);
                response.setStatus("ERROR")
                       .setMessage("Internal server error: " + e.getMessage());
            }
            
            responseObserver.onNext(response.build());
            responseObserver.onCompleted();
        }
        
        @Override
        public void validateToken(RemoteManagerProto.ValidateTokenRequest request,
                                StreamObserver<RemoteManagerProto.ValidateTokenResponse> responseObserver) {
            Log.d(TAG, "Received token validation request");
            
            RemoteManagerProto.ValidateTokenResponse.Builder response = RemoteManagerProto.ValidateTokenResponse.newBuilder();
            
            try {
                JwtTokenInfo tokenInfo = mTokenMasterService.validateTokenForGrpc(
                    request.getToken(), request.getRequiredScope());
                
                if (tokenInfo != null) {
                    response.setValid(true)
                           .setClientId(tokenInfo.getClientId())
                           .setScope(tokenInfo.getScope())
                           .setExpiresAt(tokenInfo.getExpiresAt())
                           .setMessage("JWT Token is valid");
                } else {
                    response.setValid(false)
                           .setMessage("JWT Token is invalid or expired");
                }
                
            } catch (Exception e) {
                Log.e(TAG, "Error processing token validation", e);
                response.setValid(false)
                       .setMessage("Internal server error: " + e.getMessage());
            }
            
            responseObserver.onNext(response.build());
            responseObserver.onCompleted();
        }
    }
    
    public void stop() {
        if (mGrpcServer != null && !mGrpcServer.isShutdown()) {
            mGrpcServer.shutdownNow();
            Log.d(TAG, "gRPC server stopped");
        }
    }
}
