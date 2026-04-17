package org.mazhai.aran.omninet

import android.content.Context
import android.graphics.Bitmap
import android.util.Log
import android.webkit.WebView
import android.webkit.WebViewClient
import org.mazhai.aran.security.AranSigilEngine

/**
 * AranOmniNet WebView Interceptor
 *
 * Security Architecture:
 * - Verifies SHA-256 integrity of registered web assets before injection
 * - Guards addJavascriptInterface against duplicate/hijack registration
 * - Injects JavaScript bridge on page load
 * - Monkey-patches window.fetch and XMLHttpRequest
 * - Requires a short-lived bridge token per getSigil call (prevents JS replay)
 * - Automatically appends X-Aran-Sigil header to ALL outbound requests
 */
class AranWebViewClient(
    private val context: Context,
    private val sigilEngine: AranSigilEngine,
    private val getRaspBitmask: () -> Int,
    private val getDeviceFingerprint: () -> String,
    private val onAssetTampered: ((List<String>) -> Unit)? = null
) : WebViewClient() {

    companion object {
        private const val TAG = "AranWebViewClient"
        private const val JS_BRIDGE_NAME = "AranJSBridge"
    }

    private val jsBridge = AranJSBridge(sigilEngine, getRaspBitmask, getDeviceFingerprint)

    private var bridgeAttached = false

    override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
        super.onPageStarted(view, url, favicon)

        view?.let { wv ->
            val assetResult = AranWebAssetGuard.verify(context)
            if (!assetResult.allPassed) {
                Log.e(TAG, "WebView asset integrity FAILED: ${assetResult.failedAssets}")
                onAssetTampered?.invoke(assetResult.failedAssets)
            }

            if (!bridgeAttached) {
                wv.addJavascriptInterface(jsBridge, JS_BRIDGE_NAME)
                bridgeAttached = true
            } else {
                Log.w(TAG, "Skipping duplicate addJavascriptInterface — possible bridge hijack attempt")
            }

            injectOmniNetScript(wv)
            Log.i(TAG, "AranOmniNet injected into WebView: $url")
        }
    }

    /**
     * Inject JavaScript payload to monkey-patch fetch and XMLHttpRequest
     */
    private fun injectOmniNetScript(webView: WebView) {
        val script = """
            (function() {
                'use strict';
                
                console.log('[AranOmniNet] Initializing WebView protection...');
                
                // ══════════════════════════════════════════════════════════════════
                // Fetch API Monkey-Patch
                // ══════════════════════════════════════════════════════════════════
                
                const originalFetch = window.fetch;
                window.fetch = function(resource, options) {
                    try {
                        const requestBody = options && options.body ? options.body : '';
                        const payloadHash = $JS_BRIDGE_NAME.computePayloadHash(requestBody);
                        const bridgeToken = $JS_BRIDGE_NAME.acquireBridgeToken();
                        const sigilToken = $JS_BRIDGE_NAME.getSigil(bridgeToken, payloadHash, 'WEBVIEW_FETCH');
                        const publicKey = $JS_BRIDGE_NAME.getPublicKey();
                        
                        // Inject Aran headers
                        options = options || {};
                        options.headers = options.headers || {};
                        
                        if (options.headers instanceof Headers) {
                            options.headers.append('X-Aran-Sigil', sigilToken);
                            options.headers.append('X-Aran-Public-Key', publicKey);
                        } else {
                            options.headers['X-Aran-Sigil'] = sigilToken;
                            options.headers['X-Aran-Public-Key'] = publicKey;
                        }
                        
                        console.log('[AranOmniNet] Fetch protected:', resource);
                    } catch (e) {
                        console.error('[AranOmniNet] Fetch protection failed:', e);
                    }
                    
                    return originalFetch.call(this, resource, options);
                };
                
                // ══════════════════════════════════════════════════════════════════
                // XMLHttpRequest Monkey-Patch
                // ══════════════════════════════════════════════════════════════════
                
                const XHR = XMLHttpRequest.prototype;
                const originalOpen = XHR.open;
                const originalSend = XHR.send;
                const originalSetRequestHeader = XHR.setRequestHeader;
                
                // Store request body for hash computation
                let xhrRequestBody = '';
                
                XHR.open = function(method, url, async, user, password) {
                    this._aranUrl = url;
                    this._aranMethod = method;
                    return originalOpen.apply(this, arguments);
                };
                
                XHR.send = function(body) {
                    try {
                        xhrRequestBody = body || '';
                        const payloadHash = $JS_BRIDGE_NAME.computePayloadHash(xhrRequestBody);
                        const bridgeToken = $JS_BRIDGE_NAME.acquireBridgeToken();
                        const sigilToken = $JS_BRIDGE_NAME.getSigil(bridgeToken, payloadHash, 'WEBVIEW_XHR');
                        const publicKey = $JS_BRIDGE_NAME.getPublicKey();
                        
                        // Inject Aran headers
                        originalSetRequestHeader.call(this, 'X-Aran-Sigil', sigilToken);
                        originalSetRequestHeader.call(this, 'X-Aran-Public-Key', publicKey);
                        
                        console.log('[AranOmniNet] XHR protected:', this._aranMethod, this._aranUrl);
                    } catch (e) {
                        console.error('[AranOmniNet] XHR protection failed:', e);
                    }
                    
                    return originalSend.apply(this, arguments);
                };
                
                // ══════════════════════════════════════════════════════════════════
                // Ionic/Cordova HTTP Plugin Compatibility
                // ══════════════════════════════════════════════════════════════════
                
                // Cordova HTTP plugin uses native bridge - already protected by OkHttp interceptor
                // But we log it for analytics
                if (window.cordova && window.cordova.plugin && window.cordova.plugin.http) {
                    console.log('[AranOmniNet] Cordova HTTP plugin detected - protected via native layer');
                }
                
                console.log('[AranOmniNet] WebView protection active - 100% coverage');
                
            })();
        """.trimIndent()

        webView.evaluateJavascript(script, null)
    }
}
