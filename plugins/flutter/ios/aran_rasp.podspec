Pod::Spec.new do |s|
  s.name             = 'aran_rasp'
  s.version          = '1.0.0'
  s.summary          = 'Blackbox Runtime Application Self-Protection engine for Flutter iOS applications with FFI'
  s.description      = <<-DESC
    ARAN RASP is a fintech-grade Runtime Application Self-Protection engine.
    It provides root/jailbreak detection, debugger detection, and Frida detection.
    The core security logic is implemented in C++ with advanced obfuscation techniques.
    Uses FFI (Foreign Function Interface) for direct native memory access.
    DESC

  s.homepage         = 'https://github.com/aran/aran-rasp-flutter'
  s.license          = { :type => 'Proprietary', :file => 'LICENSE' }
  s.author           = { 'ARAN Security' => 'security@aran.com' }
  s.source           = { :path => '.' }

  s.ios.deployment_target = '12.0'
  s.swift_version = '5.0'

  s.source_files = 'Classes/**/*'
  s.public_header_files = 'Classes/**/*.h'

  s.dependency 'Flutter'
  # "Dumb" passthrough - the actual logic is in the Pod
  s.dependency 'AranRuntime', '~> 1.0.0'
  s.static_framework = true

  s.pod_target_xcconfig = {
    'DEFINES_MODULE' => 'YES',
    'GCC_OPTIMIZATION_LEVEL' => 's',
    'SWIFT_OPTIMIZATION_LEVEL' => '-Osize',
    'STRIP_INSTALLED_PRODUCT' => 'YES',
    'STRIP_STYLE' => 'non-global',
    'COPY_PHASE_STRIP' => 'YES',
    'DEAD_CODE_STRIPPING' => 'YES'
  }
end
