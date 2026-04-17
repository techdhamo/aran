pipeline {
    agent any
    
    environment {
        ANDROID_HOME = '/Users/dhamo/Library/Android/sdk'
        JAVA_HOME = '/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home'
        NEXUS_URL = 'https://maven.mazhai.org/nexus'
        VERSION_NAME = '1.0.0'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Build Android AAR') {
            steps {
                dir('aran-android-sdk') {
                    sh './gradlew :aran-secure:assembleRelease'
                }
            }
        }
        
        stage('Run Tests') {
            steps {
                dir('aran-android-sdk') {
                    sh './gradlew test'
                }
            }
        }
        
        stage('Publish to Nexus') {
            steps {
                dir('aran-android-sdk') {
                    sh './gradlew :aran-secure:publish'
                }
            }
        }
        
        stage('Build Cordova Demo') {
            steps {
                dir('demos/cordova_demo') {
                    sh 'npm install'
                    sh 'cordova clean'
                    sh 'cordova build android'
                }
            }
        }
        
        stage('Deploy Cordova Demo') {
            when {
                branch 'main'
            }
            steps {
                dir('demos/cordova_demo') {
                    sh 'adb install -r platforms/android/app/build/outputs/apk/debug/app-debug.apk'
                }
            }
        }
    }
    
    post {
        success {
            echo 'Pipeline completed successfully'
            archiveArtifacts artifacts: 'aran-android-sdk/aran-secure/build/outputs/aar/*.aar', fingerprint: true
            archiveArtifacts artifacts: 'demos/cordova_demo/platforms/android/app/build/outputs/apk/**/*.apk', fingerprint: true
        }
        failure {
            echo 'Pipeline failed'
        }
    }
}
