Pod::Spec.new do |s|
  s.name             = 'react-native-rasp'
  s.version          = '1.0.0'
  s.summary          = 'Blackbox Runtime Application Self-Protection engine for React Native iOS applications with TurboModule'
  s.description      = <<-DESC
    ARAN RASP is a fintech-grade Runtime Application Self-Protection engine.
    It provides root/jailbreak detection, debugger detection, and Frida detection.
    The core security logic is implemented in C++ with advanced obfuscation techniques.
    Uses TurboModule/JSI for direct native access, bypassing the React Native Bridge.
    DESC

  s.homepage         = 'https://github.com/aran/react-native-rasp'
  s.license          = { :type => 'Proprietary', :file => 'LICENSE' }
  s.author           = { 'ARAN Security' => 'security@aran.com' }
  s.source           = { :git => 'https://github.com/aran/react-native-rasp.git', :tag => s.version.to_s }

  s.ios.deployment_target = '12.0'
  s.swift_version = '5.0'

  s.source_files = 'ios/*.{h,m,mm}'
  s.public_header_files = 'ios/*.h'

  s.dependency 'React-Core'
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
