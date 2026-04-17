package org.mazhai.aran.gateway.sigil;

/**
 * Bitmask constants matching the C++ aran-core.cpp threat flags.
 * Must be kept in sync with the SDK bitmask definition.
 */
public final class RaspThreatBit {
    private RaspThreatBit() {}

    public static final int ROOT                  = 0x0001;
    public static final int FRIDA                 = 0x0002;
    public static final int DEBUGGER              = 0x0004;
    public static final int EMULATOR              = 0x0008;
    public static final int HOOKED                = 0x0010;
    public static final int TAMPERED              = 0x0020;
    public static final int UNTRUSTED_INSTALLER   = 0x0040;
    public static final int DEVELOPER_MODE        = 0x0080;
    public static final int ADB_ENABLED           = 0x0100;
    public static final int ENV_TAMPERING         = 0x0200;
    public static final int RUNTIME_INTEGRITY     = 0x0400;
    public static final int PROXY                 = 0x0800;
    public static final int ZYGISK               = 0x1000;
    public static final int ANON_ELF             = 0x2000;
    public static final int ZYGISK_FD            = 0x4000;

    /** Category aggregates used by policy routing. */
    public static final int PRIVILEGE_ESCALATION_MASK =
            ROOT | ZYGISK | ANON_ELF | ZYGISK_FD;

    public static final int DYNAMIC_INSTRUMENTATION_MASK =
            FRIDA | DEBUGGER | HOOKED;

    public static final int TAMPER_MASK =
            TAMPERED | UNTRUSTED_INSTALLER | RUNTIME_INTEGRITY | ENV_TAMPERING;

    public static final int NETWORK_MASK =
            PROXY;
}
