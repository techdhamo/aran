package org.mazhai.aran.omninet

import android.content.Context
import android.util.Log
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.mazhai.aran.security.AranSigilEngine

/**
 * AranOmniNet Flutter Platform Channel Adapter
 * 
 * Provides native Android → Flutter Dart bridge for hardware-backed attestation.
 * 
 * Flutter uses Dart's HttpClient which cannot be intercepted at the native layer.
 * This adapter exposes a MethodChannel that Flutter code calls to sign requests.
 * 
 * Architecture:
 * 1. Flutter Dart code overrides HttpClient via HttpOverrides.global
 * 2. Before each HTTP request, Dart calls native method: generateSigil(payloadHash)
 * 3. Native Android generates hardware-signed JWT
 * 4. Dart receives JWT and attaches to HttpClient headers
 * 
 * Integration (Flutter side - 5 lines):
 * ```dart
 * import 'package:flutter/services.dart';
 * 
 * class AranSigilClient extends HttpOverrides {
 *   static const platform = MethodChannel('org.mazhai.aran/sigil');
 *   
 *   @override
 *   HttpClient createHttpClient(SecurityContext? context) {
 *     final client = super.createHttpClient(context);
 *     client.badCertificateCallback = (cert, host, port) => false;
 *     return client;
 *   }
 * }
 * 
 * // In main.dart:
 * void main() {
 *   HttpOverrides.global = AranSigilClient();
 *   runApp(MyApp());
 * }
 * 
 * // Before HTTP request:
 * final payloadHash = sha256.convert(utf8.encode(requestBody)).toString();
 * final sigil = await AranSigilClient.platform.invokeMethod('generateSigil', {
 *   'payloadHash': payloadHash,
 *   'trafficSource': 'FLUTTER_HTTP'
 * });
 * request.headers.set('X-Aran-Sigil', sigil['token']);
 * request.headers.set('X-Aran-Public-Key', sigil['publicKey']);
 * ```
 */
class AranFlutterAdapter(
    private val context: Context,
    private val getRaspBitmask: () -> Int,
    private val getDeviceFingerprint: () -> String
) : MethodChannel.MethodCallHandler {

    companion object {
        private const val TAG = "AranFlutterAdapter"
        private const val CHANNEL_NAME = "org.mazhai.aran/sigil"
    }

    private val sigilEngine = AranSigilEngine(context)
    private var methodChannel: MethodChannel? = null

    /**
     * Register Flutter MethodChannel
     * 
     * Call this in your FlutterActivity.configureFlutterEngine()
     */
    fun registerWith(flutterEngine: FlutterEngine) {
        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL_NAME)
        methodChannel?.setMethodCallHandler(this)
        Log.i(TAG, "AranFlutterAdapter registered on channel: $CHANNEL_NAME")
    }

    /**
     * Handle method calls from Flutter Dart code
     */
    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "generateSigil" -> {
                try {
                    val payloadHash = call.argument<String>("payloadHash") ?: ""
                    val trafficSource = call.argument<String>("trafficSource") ?: "FLUTTER_HTTP"
                    
                    val raspBitmask = getRaspBitmask()
                    val deviceFingerprint = getDeviceFingerprint()
                    
                    // Generate hardware-signed Sigil
                    val token = sigilEngine.generateSigilToken(
                        deviceFingerprint = deviceFingerprint,
                        raspBitmask = raspBitmask,
                        payloadHash = payloadHash,
                        trafficSource = trafficSource
                    )
                    
                    val publicKey = sigilEngine.getPublicKeyBase64()
                    
                    // Return token and public key to Flutter
                    val response = mapOf(
                        "token" to token,
                        "publicKey" to publicKey,
                        "securityLevel" to sigilEngine.getSecurityLevel(),
                        "isHardwareBacked" to sigilEngine.isHardwareBacked()
                    )
                    
                    Log.d(TAG, "Sigil generated for Flutter: $trafficSource")
                    result.success(response)
                    
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to generate Sigil for Flutter", e)
                    result.error("SIGIL_ERROR", e.message, null)
                }
            }
            
            "computePayloadHash" -> {
                try {
                    val body = call.argument<String>("body") ?: ""
                    val hash = sigilEngine.computePayloadHash(body)
                    result.success(hash)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to compute payload hash", e)
                    result.error("HASH_ERROR", e.message, null)
                }
            }
            
            "getPublicKey" -> {
                try {
                    val publicKey = sigilEngine.getPublicKeyBase64()
                    result.success(publicKey)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to get public key", e)
                    result.error("KEY_ERROR", e.message, null)
                }
            }
            
            "getSecurityInfo" -> {
                try {
                    val info = mapOf(
                        "securityLevel" to sigilEngine.getSecurityLevel(),
                        "isHardwareBacked" to sigilEngine.isHardwareBacked()
                    )
                    result.success(info)
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to get security info", e)
                    result.error("INFO_ERROR", e.message, null)
                }
            }
            
            else -> {
                result.notImplemented()
            }
        }
    }
}

/**
 * Extension function for easy FlutterActivity integration
 */
fun FlutterEngine.registerAranSigil(
    context: Context,
    getRaspBitmask: () -> Int,
    getDeviceFingerprint: () -> String
) {
    val adapter = AranFlutterAdapter(context, getRaspBitmask, getDeviceFingerprint)
    adapter.registerWith(this)
}
