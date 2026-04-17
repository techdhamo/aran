#!/usr/bin/env python3
"""
ARAN RASP Obfuscator Tool
============================

A Python-based post-processing script that:
1. Randomizes the 'Switch' states in the Control Flow Flattening (CFF) every time the code is built
2. Injects 'Bogus Control Flow'—code paths that look like security checks but are never executed
3. Automatically strips all symbols and minimizes the Dynamic Symbol Table
4. Adds LLVM-style macros for runtime constant calculation

This tool transforms the RASP engine into a "Blackbox" that frustrates reverse-engineers
using Ghidra, IDA Pro, or Frida.
"""

import re
import random
import sys
import subprocess
import os
from typing import List, Dict, Tuple
import hashlib

class RASPObfuscator:
    def __init__(self, source_file: str):
        self.source_file = source_file
        self.content = None
        self.obfuscated_content = None
        self.state_mapping = {}
        self.bogus_functions = []
        
    def load_source(self):
        """Load the source file content"""
        with open(self.source_file, 'r') as f:
            self.content = f.read()
        self.obfuscated_content = self.content
        
    def save_source(self, output_file: str = None):
        """Save the obfuscated source file"""
        if output_file is None:
            output_file = self.source_file
        with open(output_file, 'w') as f:
            f.write(self.obfuscated_content)
        print(f"Obfuscated code saved to {output_file}")
        
    def generate_random_state(self) -> str:
        """Generate a random obfuscated state constant"""
        # Generate random 32-bit value with high entropy
        value = random.randint(0x10000000, 0xFFFFFFFF)
        return f"0x{value:08X}"
    
    def randomize_state_constants(self):
        """
        Randomize the state constants in the Control Flow Flattening (CFF)
        This breaks Ghidra's ability to recognize the state machine pattern
        """
        print("Randomizing state constants...")
        
        # Find all state constant definitions
        state_pattern = r'(STATE_\w+)\s*=\s*(0x[0-9A-Fa-f]+)'
        states = re.findall(state_pattern, self.content)
        
        # Generate new random values for each state
        for state_name, old_value in states:
            new_value = self.generate_random_state()
            self.state_mapping[state_name] = (old_value, new_value)
            
            # Replace the old value with the new one
            self.obfuscated_content = self.obfuscated_content.replace(
                f"{state_name} = {old_value}",
                f"{state_name} = {new_value}"
            )
            
        print(f"Randomized {len(states)} state constants")
        
    def add_runtime_constant_macros(self):
        """
        Add LLVM-style macros that calculate constants at runtime
        using XOR and bit-shifting to hide them from static analysis
        """
        print("Adding runtime constant calculation macros...")
        
        # Add macro definitions at the beginning of the file
        macros = """
// ============================================
// LLVM-STYLE RUNTIME CONSTANT CALCULATION MACROS
// ============================================

/**
 * Calculate obfuscated constant at runtime using XOR and bit-shifting
 * This hides the actual value from static analysis tools
 */
#define OBFUSCATE_CONST(x, key) (((x) ^ (key)) << 3) ^ (key)
#define OBFUSCATE_CONST_REV(x, key) (((x) ^ (key)) >> 3) ^ (key)

/**
 * Runtime state transition obfuscation
 * state = (state * 0xdeadbeef) ^ 0x12345
 */
#define OBFUSCATE_STATE_TRANSITION(state, next) \\
    do { \\
        uint32_t _temp = (state); \\
        _temp = (_temp * 0xdeadbeef) ^ 0x12345; \\
        (state) = _temp ^ (next); \\
    } while(0)

/**
 * Bogus control flow injection macro
 * Creates code paths that look like security checks but are never executed
 */
#define BOGUS_CHECK(cond) \\
    do { \\
        if ((cond) && ((42 * 42) % 2 == 0)) { \\
            __asm__ volatile("nop"); \\
        } \\
    } while(0)

"""
        
        # Insert macros after the includes
        include_end = self.obfuscated_content.find("#define TAG")
        if include_end == -1:
            include_end = self.obfuscated_content.find("// NATIVE CORE")
        
        if include_end != -1:
            self.obfuscated_content = (
                self.obfuscated_content[:include_end] + 
                macros + 
                self.obfuscated_content[include_end:]
            )
            
        print("Added runtime constant calculation macros")
        
    def inject_bogus_control_flow(self):
        """
        Inject bogus control flow—code paths that look like security checks
        but are never executed. This confuses Ghidra's control flow graph.
        """
        print("Injecting bogus control flow...")
        
        # Generate bogus function names
        bogus_functions = []
        for i in range(5):
            func_name = f"bogus_check_{random.randint(1000, 9999)}"
            bogus_functions.append(func_name)
            
            # Add bogus function definition
            bogus_func = f"""
__attribute__((visibility("hidden"), always_inline))
static void {func_name}() {{
    // Bogus security check - never executed
    if (opaque_predicate_true()) {{
        volatile int x = 42;
        x = x ^ 0xdeadbeef;
        (void)x; // Suppress unused warning
    }}
}}

"""
            # Insert before the JNI bridge section
            jni_section = self.obfuscated_content.find("// JNI BRIDGE")
            if jni_section != -1:
                self.obfuscated_content = (
                    self.obfuscated_content[:jni_section] + 
                    bogus_func + 
                    self.obfuscated_content[jni_section:]
                )
        
        # Inject bogus calls in strategic locations
        # Find switch statements and inject bogus checks
        switch_pattern = r'(switch\s*\(\w+\)\s*\{)'
        for match in re.finditer(switch_pattern, self.obfuscated_content):
            # Insert bogus check after switch opening
            bogus_call = f'\n            BOGUS_CHECK(opaque_predicate_true());\n            {bogus_functions[random.randint(0, len(bogus_functions)-1)]}();\n'
            self.obfuscated_content = (
                self.obfuscated_content[:match.end()] + 
                bogus_call + 
                self.obfuscated_content[match.end():]
            )
            
        print(f"Injected {len(bogus_functions)} bogus functions and calls")
        
    def add_xor_obfuscated_strings(self):
        """
        Add XOR obfuscation for remaining string literals
        This complements the stack string pattern
        """
        print("Adding XOR obfuscation for string literals...")
        
        # Find string literals (excluding already obfuscated ones)
        string_pattern = r'"([^"]{8,})"'
        matches = re.finditer(string_pattern, self.obfuscated_content)
        
        # Only obfuscate long strings that look like paths
        for match in matches:
            string = match.group(1)
            # Skip if it's already obfuscated (contains only single characters)
            if len(string) < 8 or '//' in string or '/*' in string:
                continue
                
            # Skip if it's a log message
            if 'log' in string.lower() or 'LOG' in string:
                continue
                
            # Generate XOR key
            xor_key = random.randint(1, 255)
            
            # XOR the string
            xored_bytes = [ord(c) ^ xor_key for c in string]
            
            # Generate C array representation
            xored_array = '{' + ', '.join(hex(b) for b in xored_bytes) + '}'
            
            # Generate runtime decryption function call
            decrypt_call = f"decrypt_string({xored_array}, {len(string)}, {xor_key})"
            
            # Replace the string literal
            self.obfuscated_content = self.obfuscated_content.replace(
                match.group(0),
                decrypt_call
            )
            
        # Add decryption function if needed
        if 'decrypt_string' in self.obfuscated_content:
            decrypt_func = """
/**
 * Runtime string decryption
 */
__attribute__((visibility("hidden")))
static char* decrypt_string(const uint8_t* xored, size_t len, uint8_t key) {
    static char buffer[256];
    for (size_t i = 0; i < len && i < sizeof(buffer) - 1; i++) {
        buffer[i] = xored[i] ^ key;
    }
    buffer[len] = '\\0';
    return buffer;
}

"""
            # Insert before JNI bridge
            jni_section = self.obfuscated_content.find("// JNI BRIDGE")
            if jni_section != -1:
                self.obfuscated_content = (
                    self.obfuscated_content[:jni_section] + 
                    decrypt_func + 
                    self.obfuscated_content[jni_section:]
                )
            
        print("Added XOR obfuscation for string literals")
        
    def strip_symbols_command(self, output_so: str):
        """
        Generate command to strip symbols from the compiled .so file
        This minimizes the Dynamic Symbol Table
        """
        print("Generating symbol stripping command...")
        
        commands = [
            f"# Strip symbols from {output_so}",
            f"strip --strip-all --remove-section=.comment --remove-section=.note {output_so}",
            f"# Alternative: Use objcopy for more control",
            f"objcopy --strip-all --strip-debug --strip-unneeded {output_so}",
            f"# Minimize dynamic symbol table",
            f"objcopy --strip-symbol {output_so}",
        ]
        
        return '\n'.join(commands)
        
    def add_build_timestamp_randomization(self):
        """
        Add build timestamp randomization to prevent binary fingerprinting
        """
        print("Adding build timestamp randomization...")
        
        # Add timestamp obfuscation
        timestamp_macro = """
// ============================================
// BUILD TIMESTAMP RANDOMIZATION
// ============================================

/**
 * Obfuscated build timestamp
 * Calculated at runtime to prevent binary fingerprinting
 */
__attribute__((visibility("hidden")))
static uint32_t get_obfuscated_timestamp() {
    uint32_t timestamp = __builtin_constant_p(0) ? 0 : (uint32_t)time(NULL);
    timestamp = (timestamp ^ 0xdeadbeef) ^ 0x12345;
    timestamp = ((timestamp << 16) | (timestamp >> 16));
    return timestamp;
}

"""
        
        # Insert after runtime constant macros
        macro_section = self.obfuscated_content.find("LLVM-STYLE RUNTIME CONSTANT")
        if macro_section != -1:
            insert_pos = self.obfuscated_content.find("\n\n", macro_section) + 2
            self.obfuscated_content = (
                self.obfuscated_content[:insert_pos] + 
                timestamp_macro + 
                self.obfuscated_content[insert_pos:]
            )
            
        print("Added build timestamp randomization")
        
    def obfuscate(self):
        """
        Main obfuscation pipeline
        """
        print("=" * 60)
        print("ARAN RASP OBFUSCATOR TOOL")
        print("=" * 60)
        print(f"Processing: {self.source_file}")
        
        self.load_source()
        
        # Phase 1: Randomize state constants
        self.randomize_state_constants()
        
        # Phase 2: Add runtime constant macros
        self.add_runtime_constant_macros()
        
        # Phase 3: Inject bogus control flow
        self.inject_bogus_control_flow()
        
        # Phase 4: Add XOR obfuscation for strings
        self.add_xor_obfuscated_strings()
        
        # Phase 5: Add build timestamp randomization
        self.add_build_timestamp_randomization()
        
        # Save obfuscated code
        self.save_source()
        
        print("=" * 60)
        print("Obfuscation complete!")
        print("=" * 60)
        
        # Print state mapping for reference
        if self.state_mapping:
            print("\nState Constant Mapping:")
            for state_name, (old_val, new_val) in self.state_mapping.items():
                print(f"  {state_name}: {old_val} -> {new_val}")
        
        return self.obfuscated_content

def main():
    if len(sys.argv) < 2:
        print("Usage: python obfuscator.py <source_file> [output_file]")
        print("Example: python obfuscator.py rasp_core_engine.cpp")
        sys.exit(1)
    
    source_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(source_file):
        print(f"Error: Source file '{source_file}' not found")
        sys.exit(1)
    
    obfuscator = RASPObfuscator(source_file)
    obfuscator.obfuscate()
    
    if output_file:
        obfuscator.save_source(output_file)
    
    # Generate symbol stripping commands
    print("\n" + "=" * 60)
    print("SYMBOL STRIPPING COMMANDS")
    print("=" * 60)
    print(obfuscator.strip_symbols_command("libaran-secure.so"))

if __name__ == "__main__":
    main()
