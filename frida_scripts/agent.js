/*
  frida_agent.js
  Injected into the malware process at runtime.
  Intercepts: network connections, HTTP requests, SMS, crypto, location,
  clipboard, anti-analysis evasion checks, and SSL certificate validation.

  NOTE: Frida 17+ requires explicit import of frida-java-bridge.
  This script MUST be compiled via frida.Compiler before injection.
*/

import Java from 'frida-java-bridge';

Java.perform(function () {

    // ═══════════════════════════════════════════════════════
    // HOOK 1: TCP Socket — catch ALL outbound connections
    // ═══════════════════════════════════════════════════════
    try {
        const Socket = Java.use('java.net.Socket');
        Socket.$init.overload('java.lang.String', 'int').implementation = function (host, port) {
            send({
                type: 'tcp_connect',
                host: host,
                port: port,
                timestamp: new Date().toISOString(),
                thread: Java.use('java.lang.Thread').currentThread().getName()
            });
            return this.$init(host, port);
        };
    } catch (e) { /* Socket not available */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 2: OkHttp (most common Android HTTP client)
    // ═══════════════════════════════════════════════════════
    try {
        Java.use('okhttp3.internal.connection.RealCall').execute.implementation = function () {
            const req = this.request();
            let bodyStr = null;
            if (req.body()) {
                const buffer = Java.use('okio.Buffer').$new();
                req.body().writeTo(buffer);
                bodyStr = buffer.readUtf8();
            }
            send({
                type: 'http_request',
                url: req.url().toString(),
                method: req.method(),
                body: bodyStr,
                timestamp: new Date().toISOString(),
                severity: 'HIGH'
            });
            const resp = this.execute();
            send({ type: 'http_response', code: resp.code() });
            return resp;
        };
    } catch (e) { /* OkHttp not present */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 3: SSL Certificate Pinning Bypass
    // ═══════════════════════════════════════════════════════
    try {
        const TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        const SSLContext = Java.use('javax.net.ssl.SSLContext');

        const TrustAllCerts = Java.registerClass({
            name: 'com.analysis.TrustAllCerts',
            implements: [TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });

        SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;',
            '[Ljavax.net.ssl.TrustManager;',
            'java.security.SecureRandom'
        ).implementation = function (km, tm, sr) {
            this.init(km, [TrustAllCerts.$new()], sr);
        };
    } catch (e) { /* SSL bypass failed */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 4: SMS Operations (banker trojan detection)
    // ═══════════════════════════════════════════════════════
    try {
        const SmsManager = Java.use('android.telephony.SmsManager');
        SmsManager.sendTextMessage.implementation = function (dest, sc, text, sent, del) {
            send({
                type: 'sms_send',
                destination: dest,
                body: text,
                timestamp: new Date().toISOString(),
                severity: 'CRITICAL'
            });
            // Block the SMS silently
        };
    } catch (e) { /* SMS hook failed */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 5: Location Access
    // ═══════════════════════════════════════════════════════
    try {
        Java.use('android.location.LocationManager')
            .getLastKnownLocation.implementation = function (provider) {
            const loc = this.getLastKnownLocation(provider);
            if (loc) {
                send({
                    type: 'location_read',
                    lat: loc.getLatitude(),
                    lon: loc.getLongitude(),
                    provider: provider,
                    timestamp: new Date().toISOString(),
                    severity: 'HIGH'
                });
            }
            return loc;
        };
    } catch (e) { /* Location hook failed */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 6: Emulator Detection — Anti-Anti-Analysis
    // ═══════════════════════════════════════════════════════
    try {
        const Build = Java.use('android.os.Build');
        Build.FINGERPRINT.value = 'samsung/SM-G998B/SM-G998B:12/SP1A.210812.016/G998BXXS3DWB1:user/release-keys';
        Build.MANUFACTURER.value = 'Samsung';
        Build.MODEL.value = 'SM-G998B';
        Build.BRAND.value = 'samsung';
    } catch (e) { /* Build prop override failed */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 7: Dynamic Code Loading (Dropper / Packer detection)
    // ═══════════════════════════════════════════════════════
    try {
        const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
        DexClassLoader.$init.implementation = function (dexPath, optimizedDirectory, librarySearchPath, parent) {
            send({
                type: 'dynamic_code_load',
                dexPath: dexPath,
                optimizedDirectory: optimizedDirectory,
                timestamp: new Date().toISOString(),
                severity: 'CRITICAL'
            });
            return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
        };
    } catch (e) { /* DexClassLoader hook failed */ }

    // ═══════════════════════════════════════════════════════
    // HOOK 8: Native Library Loading (JNI)
    // ═══════════════════════════════════════════════════════
    try {
        const System = Java.use('java.lang.System');
        const Runtime = Java.use('java.lang.Runtime');

        System.loadLibrary.implementation = function (libname) {
            send({
                type: 'native_lib_load',
                libname: libname,
                timestamp: new Date().toISOString(),
                severity: 'HIGH'
            });
            return this.loadLibrary(libname);
        };

        Runtime.loadLibrary0.implementation = function (classLoader, libname) {
            send({
                type: 'native_lib_load0',
                libname: libname,
                timestamp: new Date().toISOString(),
                severity: 'HIGH'
            });
            return this.loadLibrary0(classLoader, libname);
        };
    } catch (e) { /* System.loadLibrary hook failed */ }

    send({ type: 'agent_ready', timestamp: new Date().toISOString() });
});
