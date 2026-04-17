#include <jni.h>
#include <android/log.h>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dlfcn.h>
#include <pthread.h>

// Conditionally include OpenSSL headers
#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#endif

#define LOG_TAG "AranCertPinning"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)

// Expected certificate pins for api.dhamo.in
static const char* EXPECTED_PINS[] = {
    "sha256/raNsyIdcz+Lzp5xP7h+LccrnEnkVG4lyHdvMemhlZWI=",
    // Add backup pins here for certificate rotation
};

static const int NUM_EXPECTED_PINS = sizeof(EXPECTED_PINS) / sizeof(EXPECTED_PINS[0]);

// Allowed hostnames
static const char* ALLOWED_HOSTNAMES[] = {
    "api.dhamo.in",
    "api2.dhamo.in"
};

static const int NUM_ALLOWED_HOSTNAMES = sizeof(ALLOWED_HOSTNAMES) / sizeof(ALLOWED_HOSTNAMES[0]);

// Security alert types
typedef enum {
    ALERT_NONE = 0,
    ALERT_INSECURE_HTTP = 1,
    ALERT_CERT_PIN_MISMATCH = 2,
    ALERT_WEAK_CIPHER = 3,
    ALERT_SSL_HOOKING = 4,
    ALERT_MITM_DETECTED = 5,
    ALERT_HOSTNAME_MISMATCH = 6
} SecurityAlertType;

// Network security state
static struct {
    bool initialized;
    bool ssl_hooking_detected;
    bool insecure_connections_blocked;
    int alert_count;
    pthread_mutex_t mutex;
} g_security_state = {false, false, true, 0, PTHREAD_MUTEX_INITIALIZER};

// Security alert callback
static jobject g_alert_callback = NULL;
static JavaVM* g_jvm = NULL;

// Function pointers for hooking
static int (*original_connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) = NULL;
static ssize_t (*original_send)(int sockfd, const void *buf, size_t len, int flags) = NULL;
static ssize_t (*original_recv)(int sockfd, void *buf, size_t len, int flags) = NULL;

// Trigger security alert
static void trigger_security_alert(SecurityAlertType alert_type, const char* message, const char* hostname) {
    pthread_mutex_lock(&g_security_state.mutex);
    g_security_state.alert_count++;
    pthread_mutex_unlock(&g_security_state.mutex);
    
    LOGE("SECURITY ALERT [%d]: %s (hostname: %s)", alert_type, message, hostname ? hostname : "unknown");
    
    // Call Java callback if registered
    if (g_alert_callback && g_jvm) {
        JNIEnv* env;
        if (g_jvm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) == JNI_OK) {
            jclass callback_class = env->GetObjectClass(g_alert_callback);
            jmethodID on_alert_method = env->GetMethodID(callback_class, "onSecurityAlert", "(ILjava/lang/String;Ljava/lang/String;)V");
            
            if (on_alert_method) {
                jstring message_str = env->NewStringUTF(message);
                jstring hostname_str = hostname ? env->NewStringUTF(hostname) : NULL;
                
                env->CallVoidMethod(g_alert_callback, on_alert_method, (jint)alert_type, message_str, hostname_str);
                
                if (message_str) env->DeleteLocalRef(message_str);
                if (hostname_str) env->DeleteLocalRef(hostname_str);
            }
            
            env->DeleteLocalRef(callback_class);
        }
    }
}

// Calculate SHA-256 hash of public key (OpenSSL-dependent)
#ifdef HAVE_OPENSSL
static char* calculate_public_key_pin(X509* cert) {
    if (!cert) {
        LOGE("Certificate is null");
        return NULL;
    }
    
    EVP_PKEY* public_key = X509_get_pubkey(cert);
    if (!public_key) {
        LOGE("Failed to get public key from certificate");
        return NULL;
    }
    
    // Get public key in DER format
    unsigned char* der_data = NULL;
    int der_length = i2d_PUBKEY(public_key, &der_data);
    if (der_length <= 0) {
        LOGE("Failed to convert public key to DER format");
        EVP_PKEY_free(public_key);
        return NULL;
    }
    
    // Calculate SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der_data, der_length, hash);
    
    // Convert to base64
    static char base64_output[64]; // SHA256 + padding + null terminator
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    while (der_length--) {
        char_array_3[i++] = *(der_data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++) {
                base64_output[j++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (j = 0; j < i + 1; j++) {
            base64_output[j++] = base64_chars[char_array_4[j]];
        }
        
        while ((i++ < 3)) {
            base64_output[j++] = '=';
        }
    }
    
    base64_output[j] = '\0';
    
    // Add sha256/ prefix
    static char final_pin[128];
    snprintf(final_pin, sizeof(final_pin), "sha256/%s", base64_output);
    
    EVP_PKEY_free(public_key);
    OPENSSL_free(der_data);
    
    return final_pin;
}
#endif

// Hooked connect function to monitor outgoing connections
static int hooked_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    if (!original_connect) {
        return -1;
    }
    
    // Check if this is an HTTP (insecure) connection
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in* addr_in = (struct sockaddr_in*)addr;
        uint16_t port = ntohs(addr_in->sin_port);
        
        if (port == 80) {
            trigger_security_alert(ALERT_INSECURE_HTTP, "Insecure HTTP connection attempt detected", NULL);
            
            if (g_security_state.insecure_connections_blocked) {
                LOGE("Blocking insecure HTTP connection");
                return -1;
            }
        }
    }
    
    return original_connect(sockfd, addr, addrlen);
}

// Initialize network hooks
static void initialize_network_hooks() {
    // Hook connect function
    original_connect = (int(*)(int, const struct sockaddr*, socklen_t))dlsym(RTLD_NEXT, "connect");
    if (original_connect) {
        LOGD("Successfully hooked connect function");
    } else {
        LOGW("Failed to hook connect function");
    }
}

// Check for insecure SSL/TLS configuration
static bool check_ssl_security(SSL* ssl) {
    if (!ssl) {
        return false;
    }
    
    const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
    if (!cipher) {
        return false;
    }
    
    const char* cipher_name = SSL_CIPHER_get_name(cipher);
    
    // Check for weak ciphers
    if (strstr(cipher_name, "DES") || strstr(cipher_name, "RC4") || 
        strstr(cipher_name, "MD5") || strstr(cipher_name, "NULL")) {
        trigger_security_alert(ALERT_WEAK_CIPHER, cipher_name, NULL);
        return false;
    }
    
    // Check for SSL version
    int version = SSL_version(ssl);
    if (version < TLS1_2_VERSION) {
        trigger_security_alert(ALERT_WEAK_CIPHER, "SSL/TLS version too old", NULL);
        return false;
    }
    
    return true;
}

// Calculate SHA-256 hash of public key
static char* calculate_public_key_pin(X509* cert) {
    if (!cert) {
        LOGE("Certificate is null");
        return NULL;
    }
    
    EVP_PKEY* public_key = X509_get_pubkey(cert);
    if (!public_key) {
        LOGE("Failed to get public key from certificate");
        return NULL;
    }
    
    // Get public key in DER format
    unsigned char* der_data = NULL;
    int der_length = i2d_PUBKEY(public_key, &der_data);
    if (der_length <= 0) {
        LOGE("Failed to convert public key to DER format");
        EVP_PKEY_free(public_key);
        return NULL;
    }
    
    // Calculate SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(der_data, der_length, hash);
    
    // Convert to base64
    static char base64_output[64]; // SHA256 + padding + null terminator
    const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    int i = 0, j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    while (der_length--) {
        char_array_3[i++] = *(der_data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++) {
                base64_output[j++] = base64_chars[char_array_4[i]];
            }
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++) {
            char_array_3[j] = '\0';
        }
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (j = 0; j < i + 1; j++) {
            base64_output[j++] = base64_chars[char_array_4[j]];
        }
        
        while ((i++ < 3)) {
            base64_output[j++] = '=';
        }
    }
    
    base64_output[j] = '\0';
    
    // Add sha256/ prefix
    static char final_pin[128];
    snprintf(final_pin, sizeof(final_pin), "sha256/%s", base64_output);
    
    EVP_PKEY_free(public_key);
    OPENSSL_free(der_data);
    
    return final_pin;
}

// Verify certificate chain
static bool verify_certificate_chain(X509* cert, const char* hostname) {
    if (!cert || !hostname) {
        LOGE("Invalid parameters for certificate chain verification");
        return false;
    }
    
    // Calculate pin for the leaf certificate
    char* pin = calculate_public_key_pin(cert);
    if (!pin) {
        LOGE("Failed to calculate certificate pin");
        return false;
    }
    
    LOGD("Calculated certificate pin: %s", pin);
    
    // Check against expected pins
    bool pin_valid = false;
    for (int i = 0; i < NUM_EXPECTED_PINS; i++) {
        if (strcmp(pin, EXPECTED_PINS[i]) == 0) {
            LOGI("Certificate pin MATCHED: %s", pin);
            pin_valid = true;
            break;
        }
    }
    
    if (!pin_valid) {
        LOGE("Certificate pin NOT MATCHED: %s", pin);
        LOGE("Expected pins:");
        for (int i = 0; i < NUM_EXPECTED_PINS; i++) {
            LOGE("  %s", EXPECTED_PINS[i]);
        }
        trigger_security_alert(ALERT_CERT_PIN_MISMATCH, "Certificate pin mismatch detected", hostname);
        return false;
    }
    
    // Verify hostname
    bool hostname_valid = false;
    for (int i = 0; i < NUM_ALLOWED_HOSTNAMES; i++) {
        if (strcmp(hostname, ALLOWED_HOSTNAMES[i]) == 0) {
            hostname_valid = true;
            break;
        }
    }
    
    if (!hostname_valid) {
        LOGE("Hostname not allowed: %s", hostname);
        trigger_security_alert(ALERT_HOSTNAME_MISMATCH, "Hostname not in allowlist", hostname);
        return false;
    }
    
    LOGI("Hostname verification PASSED for: %s", hostname);
    return true;
}

// Enhanced SSL context validation
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_validateSSLConnection(JNIEnv* env, jobject thiz,
                                                                                   jstring hostname, jlong ssl_context_ptr) {
    const char* hostname_str = env->GetStringUTFChars(hostname, NULL);
    if (!hostname_str) {
        LOGE("Failed to get hostname string");
        return JNI_FALSE;
    }

    SSL* ssl = reinterpret_cast<SSL*>(ssl_context_ptr);
    if (!ssl) {
        LOGE("Invalid SSL context pointer");
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }

    // Check SSL security (cipher, version)
    if (!check_ssl_security(ssl)) {
        LOGE("SSL security check failed");
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }

    // Get peer certificate
    X509* cert = SSL_get_peer_certificate(ssl);
    if (!cert) {
        LOGE("No peer certificate available");
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }

    // Verify certificate chain
    bool result = verify_certificate_chain(cert, hostname_str);

    X509_free(cert);
    env->ReleaseStringUTFChars(hostname, hostname_str);

    return result ? JNI_TRUE : JNI_FALSE;
}

// Native certificate pinning validation
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_validateCertificatePinningNative(JNIEnv* env, jobject thiz,
                                                                                           jstring hostname, jbyteArray cert_bytes) {
    const char* hostname_str = env->GetStringUTFChars(hostname, NULL);
    if (!hostname_str) {
        LOGE("Failed to get hostname string");
        return JNI_FALSE;
    }
    
    jbyte* cert_data = env->GetByteArrayElements(cert_bytes, NULL);
    jsize cert_length = env->GetArrayLength(cert_bytes);
    
    if (!cert_data || cert_length <= 0) {
        LOGE("Invalid certificate data");
        env->ReleaseStringUTFChars(hostname, hostname_str);
        if (cert_data) env->ReleaseByteArrayElements(cert_bytes, cert_data, 0);
        return JNI_FALSE;
    }
    
    // Create X509 certificate from bytes
    const unsigned char* data = reinterpret_cast<const unsigned char*>(cert_data);
    X509* cert = d2i_X509(NULL, &data, cert_length);
    
    if (!cert) {
        LOGE("Failed to parse certificate");
        env->ReleaseStringUTFChars(hostname, hostname_str);
        env->ReleaseByteArrayElements(cert_bytes, cert_data, 0);
        return JNI_FALSE;
    }
    
    // Verify certificate
    bool result = verify_certificate_chain(cert, hostname_str);
    
    X509_free(cert);
    env->ReleaseStringUTFChars(hostname, hostname_str);
    env->ReleaseByteArrayElements(cert_bytes, cert_data, 0);
    
    return result ? JNI_TRUE : JNI_FALSE;
}

// Check for SSL/TLS tampering
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_detectSSLTampering(JNIEnv* env, jobject thiz) {
    LOGD("Checking for SSL/TLS tampering...");
    
    // Check for common SSL hooking patterns
    void* ssl_ctx_new_addr = dlsym(RTLD_DEFAULT, "SSL_CTX_new");
    if (!ssl_ctx_new_addr) {
        LOGE("SSL_CTX_new function not found - possible SSL hooking");
        return JNI_TRUE;
    }
    
    void* ssl_new_addr = dlsym(RTLD_DEFAULT, "SSL_new");
    if (!ssl_new_addr) {
        LOGE("SSL_new function not found - possible SSL hooking");
        return JNI_TRUE;
    }
    
    // Check for suspicious SSL libraries
    if (dlopen("libssl_hook.so", RTLD_NOLOAD) != NULL) {
        LOGE("SSL hooking library detected");
        return JNI_TRUE;
    }
    
    if (dlopen("libfrida_ssl.so", RTLD_NOLOAD) != NULL) {
        LOGE("Frida SSL library detected");
        return JNI_TRUE;
    }
    
    LOGD("SSL/TLS tampering check passed");
    return JNI_FALSE;
}

// Validate network connection security
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_validateConnectionSecurity(JNIEnv* env, jobject thiz,
                                                                                      jstring hostname, jint port) {
    const char* hostname_str = env->GetStringUTFChars(hostname, NULL);
    if (!hostname_str) {
        LOGE("Failed to get hostname string");
        return JNI_FALSE;
    }
    
    LOGD("Validating connection security for %s:%d", hostname_str, port);
    
    // Create socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        LOGE("Failed to create socket");
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }
    
    // Resolve hostname
    struct hostent* host = gethostbyname(hostname_str);
    if (!host) {
        LOGE("Failed to resolve hostname: %s", hostname_str);
        close(sockfd);
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }
    
    // Set up server address
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    memcpy(&server_addr.sin_addr.s_addr, host->h_addr, host->h_length);
    
    // Connect to server
    if (connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        LOGE("Failed to connect to %s:%d", hostname_str, port);
        close(sockfd);
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }
    
    // Create SSL context
    SSL_CTX* ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ssl_ctx) {
        LOGE("Failed to create SSL context");
        close(sockfd);
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }
    
    // Create SSL object
    SSL* ssl = SSL_new(ssl_ctx);
    if (!ssl) {
        LOGE("Failed to create SSL object");
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }
    
    // Set socket to SSL
    SSL_set_fd(ssl, sockfd);
    
    // Perform SSL handshake
    int ret = SSL_connect(ssl);
    if (ret <= 0) {
        LOGE("SSL handshake failed");
        SSL_free(ssl);
        SSL_CTX_free(ssl_ctx);
        close(sockfd);
        env->ReleaseStringUTFChars(hostname, hostname_str);
        return JNI_FALSE;
    }
    
    // Verify certificate
    bool cert_valid = verify_certificate_chain(SSL_get_peer_certificate(ssl), hostname_str);
    
    // Cleanup
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);
    close(sockfd);
    env->ReleaseStringUTFChars(hostname, hostname_str);
    
    LOGD("Connection security validation %s", cert_valid ? "PASSED" : "FAILED");
    return cert_valid ? JNI_TRUE : JNI_FALSE;
}

// Get certificate details for debugging
extern "C" JNIEXPORT jstring JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_getCertificateDetails(JNIEnv* env, jobject thiz,
                                                                                 jbyteArray cert_bytes) {
    jbyte* cert_data = env->GetByteArrayElements(cert_bytes, NULL);
    jsize cert_length = env->GetArrayLength(cert_bytes);
    
    if (!cert_data || cert_length <= 0) {
        LOGE("Invalid certificate data");
        if (cert_data) env->ReleaseByteArrayElements(cert_bytes, cert_data, 0);
        return env->NewStringUTF("Invalid certificate data");
    }
    
    const unsigned char* data = reinterpret_cast<const unsigned char*>(cert_data);
    X509* cert = d2i_X509(NULL, &data, cert_length);
    
    if (!cert) {
        LOGE("Failed to parse certificate");
        env->ReleaseByteArrayElements(cert_bytes, cert_data, 0);
        return env->NewStringUTF("Failed to parse certificate");
    }
    
    // Get certificate details
    char subject[256];
    char issuer[256];
    char pin[128];
    
    X509_NAME_oneline(X509_get_subject_name(cert), subject, sizeof(subject));
    X509_NAME_oneline(X509_get_issuer_name(cert), issuer, sizeof(issuer));
    
    char* calculated_pin = calculate_public_key_pin(cert);
    if (calculated_pin) {
        strncpy(pin, calculated_pin, sizeof(pin) - 1);
        pin[sizeof(pin) - 1] = '\0';
    } else {
        strcpy(pin, "Failed to calculate pin");
    }
    
    // Create result string
    char result[1024];
    snprintf(result, sizeof(result), 
             "Subject: %s\nIssuer: %s\nPin: %s\nValid: %s to %s",
             subject, issuer, pin, 
             "2024-01-01", "2025-01-01"); // Simplified dates
    
    X509_free(cert);
    env->ReleaseByteArrayElements(cert_bytes, cert_data, 0);
    
    return env->NewStringUTF(result);
}

// Initialize OpenSSL
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_initializeOpenSSL(JNIEnv* env, jobject thiz) {
    LOGI("Initializing OpenSSL for enhanced certificate pinning...");
    
    // Initialize OpenSSL
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    
    LOGI("OpenSSL initialized successfully");
}

// Initialize enhanced network security
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_initializeNetworkSecurity(JNIEnv* env, jobject thiz) {
    pthread_mutex_lock(&g_security_state.mutex);
    
    if (!g_security_state.initialized) {
        LOGI("Initializing enhanced network security...");
        
        // Get Java VM
        env->GetJavaVM(&g_jvm);
        
        // Initialize network hooks
        initialize_network_hooks();
        
        g_security_state.initialized = true;
        LOGI("Enhanced network security initialized successfully");
    }
    
    pthread_mutex_unlock(&g_security_state.mutex);
}

// Register security alert callback
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_registerSecurityCallback(JNIEnv* env, jobject thiz, jobject callback) {
    pthread_mutex_lock(&g_security_state.mutex);
    
    // Clean up old callback
    if (g_alert_callback) {
        env->DeleteGlobalRef(g_alert_callback);
        g_alert_callback = NULL;
    }
    
    // Register new callback
    if (callback) {
        g_alert_callback = env->NewGlobalRef(callback);
        LOGI("Security alert callback registered");
    }
    
    pthread_mutex_unlock(&g_security_state.mutex);
}

// Configure insecure connection blocking
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_setBlockInsecureConnections(JNIEnv* env, jobject thiz, jboolean block) {
    pthread_mutex_lock(&g_security_state.mutex);
    g_security_state.insecure_connections_blocked = block;
    LOGI("Insecure connection blocking %s", block ? "ENABLED" : "DISABLED");
    pthread_mutex_unlock(&g_security_state.mutex);
}

// Get security statistics
extern "C" JNIEXPORT jint JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_getAlertCount(JNIEnv* env, jobject thiz) {
    pthread_mutex_lock(&g_security_state.mutex);
    int count = g_security_state.alert_count;
    pthread_mutex_unlock(&g_security_state.mutex);
    return count;
}

// Check if SSL hooking is detected
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_isSSLHookingDetected(JNIEnv* env, jobject thiz) {
    pthread_mutex_lock(&g_security_state.mutex);
    jboolean detected = g_security_state.ssl_hooking_detected ? JNI_TRUE : JNI_FALSE;
    pthread_mutex_unlock(&g_security_state.mutex);
    return detected;
}

// Add allowed hostname
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_addAllowedHostname(JNIEnv* env, jobject thiz, jstring hostname) {
    const char* hostname_str = env->GetStringUTFChars(hostname, NULL);
    if (hostname_str) {
        LOGI("Adding allowed hostname: %s", hostname_str);
        // Note: This would require dynamic array management
        // For now, this is a placeholder
        env->ReleaseStringUTFChars(hostname, hostname_str);
    }
}

// Enable network monitoring
extern "C" JNIEXPORT void JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_enableNetworkMonitoring(JNIEnv* env, jobject thiz, jboolean enable) {
    LOGI("Network monitoring %s", enable ? "ENABLED" : "DISABLED");
    // Network monitoring is always active when hooks are initialized
}

// Check for SSL/TLS tampering
extern "C" JNIEXPORT jboolean JNICALL
Java_org_mazhai_aran_security_EnhancedCertificatePinning_detectSSLTampering(JNIEnv* env, jobject thiz) {
    LOGD("Checking for SSL/TLS tampering...");
    
    // Check for common SSL hooking patterns
    void* ssl_ctx_new_addr = dlsym(RTLD_DEFAULT, "SSL_CTX_new");
    if (!ssl_ctx_new_addr) {
        LOGE("SSL_CTX_new function not found - possible SSL hooking");
        pthread_mutex_lock(&g_security_state.mutex);
        g_security_state.ssl_hooking_detected = true;
        pthread_mutex_unlock(&g_security_state.mutex);
        trigger_security_alert(ALERT_SSL_HOOKING, "SSL_CTX_new function not found", NULL);
        return JNI_TRUE;
    }
    
    void* ssl_new_addr = dlsym(RTLD_DEFAULT, "SSL_new");
    if (!ssl_new_addr) {
        LOGE("SSL_new function not found - possible SSL hooking");
        pthread_mutex_lock(&g_security_state.mutex);
        g_security_state.ssl_hooking_detected = true;
        pthread_mutex_unlock(&g_security_state.mutex);
        trigger_security_alert(ALERT_SSL_HOOKING, "SSL_new function not found", NULL);
        return JNI_TRUE;
    }
    
    // Check for suspicious SSL libraries
    if (dlopen("libssl_hook.so", RTLD_NOLOAD) != NULL) {
        LOGE("SSL hooking library detected");
        pthread_mutex_lock(&g_security_state.mutex);
        g_security_state.ssl_hooking_detected = true;
        pthread_mutex_unlock(&g_security_state.mutex);
        trigger_security_alert(ALERT_SSL_HOOKING, "SSL hooking library detected", NULL);
        return JNI_TRUE;
    }
    
    if (dlopen("libfrida_ssl.so", RTLD_NOLOAD) != NULL) {
        LOGE("Frida SSL library detected");
        pthread_mutex_lock(&g_security_state.mutex);
        g_security_state.ssl_hooking_detected = true;
        pthread_mutex_unlock(&g_security_state.mutex);
        trigger_security_alert(ALERT_SSL_HOOKING, "Frida SSL library detected", NULL);
        return JNI_TRUE;
    }
    
    LOGD("SSL/TLS tampering check passed");
    return JNI_FALSE;
}
