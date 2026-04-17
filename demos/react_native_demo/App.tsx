import React, { useState, useEffect } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  View,
  TouchableOpacity,
  ActivityIndicator,
} from 'react-native';
import AranRASP, { AranSelectors } from 'react-native-rasp';

interface SecurityCheckResult {
  name: string;
  result: number;
  timestamp: Date;
}

const App = () => {
  const [isInitialized, setIsInitialized] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [results, setResults] = useState<SecurityCheckResult[]>([]);

  useEffect(() => {
    initializeRASP();
  }, []);

  const initializeRASP = async () => {
    try {
      const success = await AranRASP.initialize();
      setIsInitialized(success);
    } catch (error) {
      console.error('Failed to initialize RASP:', error);
    }
  };

  const runSecurityCheck = async (name: string, selector: number) => {
    if (!isInitialized) {
      await initializeRASP();
    }

    setIsLoading(true);
    try {
      const result = await AranRASP.validate(selector);
      setResults(prev => [
        ...prev,
        {
          name,
          result,
          timestamp: new Date(),
        },
      ]);
    } catch (error) {
      console.error(`Failed to run ${name}:`, error);
    } finally {
      setIsLoading(false);
    }
  };

  const runAllChecks = async () => {
    if (!isInitialized) {
      await initializeRASP();
    }

    setResults([]);
    await runSecurityCheck('Integrity Check', AranSelectors.integrityCheck);
    await runSecurityCheck('Debugger Check', AranSelectors.debugCheck);
    await runSecurityCheck('Root Check', AranSelectors.rootCheck);
    await runSecurityCheck('Jailbreak Check', AranSelectors.jailbreakCheck);
    await runSecurityCheck('Frida Check', AranSelectors.fridaCheck);
    await runSecurityCheck('Emulator Check', AranSelectors.emulatorCheck);
  };

  const getResultColor = (result: number) => {
    if (result === 0x7F3D) return '#4CAF50'; // Green - Security OK
    if (result === 0x1A2B) return '#FF9800'; // Orange - Suspicious
    return '#F44336'; // Red - Threat detected
  };

  const getResultIcon = (result: number) => {
    if (result === 0x7F3D) return '✓';
    if (result === 0x1A2B) return '⚠';
    return '✗';
  };

  const formatTime = (date: Date) => {
    return `${date.getHours()}:${date.getMinutes().toString().padStart(2, '0')}:${date.getSeconds().toString().padStart(2, '0')}`;
  };

  return (
    <SafeAreaView style={styles.container}>
      <StatusBar barStyle="dark-content" />
      <ScrollView contentContainerStyle={styles.scrollContent}>
        <View style={styles.header}>
          <Text style={styles.title}>ARAN RASP Demo</Text>
          <Text style={styles.subtitle}>React Native TurboModule</Text>
        </View>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>RASP Engine Status</Text>
          <View style={styles.statusRow}>
            <Text style={[styles.statusIcon, { color: isInitialized ? '#4CAF50' : '#F44336' }]}>
              {isInitialized ? '●' : '○'}
            </Text>
            <Text style={[styles.statusText, { color: isInitialized ? '#4CAF50' : '#F44336' }]}>
              {isInitialized ? 'Initialized' : 'Not Initialized'}
            </Text>
          </View>
        </View>

        <TouchableOpacity
          style={[styles.button, isLoading && styles.buttonDisabled]}
          onPress={runAllChecks}
          disabled={isLoading}>
          {isLoading ? (
            <ActivityIndicator color="#FFFFFF" />
          ) : (
            <Text style={styles.buttonText}>Run All Security Checks</Text>
          )}
        </TouchableOpacity>

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Security Check Results</Text>
          {results.length === 0 ? (
            <Text style={styles.noResults}>No security checks run yet</Text>
          ) : (
            results.map((result, index) => (
              <View key={index} style={styles.resultRow}>
                <Text style={[styles.resultIcon, { color: getResultColor(result.result) }]}>
                  {getResultIcon(result.result)}
                </Text>
                <View style={styles.resultContent}>
                  <Text style={styles.resultName}>{result.name}</Text>
                  <Text style={styles.resultValue}>
                    Result: 0x{result.result.toString(16).toUpperCase()}
                  </Text>
                </View>
                <Text style={styles.resultTime}>{formatTime(result.timestamp)}</Text>
              </View>
            ))
          )}
        </View>

        <View style={styles.infoCard}>
          <Text style={styles.infoTitle}>Security Checks</Text>
          <Text style={styles.infoText}>• Integrity Check (0x1A2B)</Text>
          <Text style={styles.infoText}>• Debugger Check (0x2B3C)</Text>
          <Text style={styles.infoText}>• Root Check (0x3C4D)</Text>
          <Text style={styles.infoText}>• Jailbreak Check (0x4D5E)</Text>
          <Text style={styles.infoText}>• Frida Check (0x5E6F)</Text>
          <Text style={styles.infoText}>• Emulator Check (0x6F70)</Text>
        </View>
      </ScrollView>
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#F5F5F5',
  },
  scrollContent: {
    padding: 20,
  },
  header: {
    marginBottom: 20,
  },
  title: {
    fontSize: 28,
    fontWeight: 'bold',
    color: '#333',
  },
  subtitle: {
    fontSize: 16,
    color: '#666',
    marginTop: 4,
  },
  card: {
    backgroundColor: '#FFFFFF',
    borderRadius: 12,
    padding: 16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.1,
    shadowRadius: 4,
    elevation: 3,
  },
  cardTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#333',
    marginBottom: 12,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  statusIcon: {
    fontSize: 24,
    marginRight: 8,
  },
  statusText: {
    fontSize: 16,
    fontWeight: '600',
  },
  button: {
    backgroundColor: '#6200EE',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    marginBottom: 16,
    shadowColor: '#6200EE',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 5,
  },
  buttonDisabled: {
    backgroundColor: '#9E9E9E',
    shadowColor: 'transparent',
  },
  buttonText: {
    color: '#FFFFFF',
    fontSize: 16,
    fontWeight: '600',
  },
  noResults: {
    color: '#999',
    fontSize: 16,
    textAlign: 'center',
    paddingVertical: 20,
  },
  resultRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 12,
    borderBottomWidth: 1,
    borderBottomColor: '#E0E0E0',
  },
  resultIcon: {
    fontSize: 24,
    marginRight: 12,
    width: 30,
  },
  resultContent: {
    flex: 1,
  },
  resultName: {
    fontSize: 16,
    fontWeight: '500',
    color: '#333',
  },
  resultValue: {
    fontSize: 14,
    color: '#666',
  },
  resultTime: {
    fontSize: 12,
    color: '#999',
  },
  infoCard: {
    backgroundColor: '#E3F2FD',
    borderRadius: 12,
    padding: 16,
  },
  infoTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#1976D2',
    marginBottom: 8,
  },
  infoText: {
    fontSize: 14,
    color: '#424242',
    marginBottom: 4,
  },
});

export default App;
