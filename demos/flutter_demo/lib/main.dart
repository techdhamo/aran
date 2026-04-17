import 'package:flutter/material.dart';
import 'package:aran_rasp/aran_rasp.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'ARAN RASP Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const RASPDemoPage(),
    );
  }
}

class RASPDemoPage extends StatefulWidget {
  const RASPDemoPage({super.key});

  @override
  State<RASPDemoPage> createState() => _RASPDemoPageState();
}

class _RASPDemoPageState extends State<RASPDemoPage> {
  final List<SecurityCheckResult> _results = [];
  bool _isInitialized = false;

  @override
  void initState() {
    super.initState();
    _initializeRASP();
  }

  Future<void> _initializeRASP() async {
    final success = await AranRASP.initialize();
    setState(() {
      _isInitialized = success;
    });
  }

  Future<void> _runSecurityCheck(String name, int selector) async {
    if (!_isInitialized) {
      await _initializeRASP();
    }

    final result = await AranRASP.validate(selector);
    setState(() {
      _results.add(SecurityCheckResult(
        name: name,
        result: result,
        timestamp: DateTime.now(),
      ));
    });
  }

  Future<void> _runAllChecks() async {
    if (!_isInitialized) {
      await _initializeRASP();
    }

    setState(() {
      _results.clear();
    });

    await _runSecurityCheck('Integrity Check', AranRASP.selectors.integrityCheck);
    await _runSecurityCheck('Debugger Check', AranRASP.selectors.debugCheck);
    await _runSecurityCheck('Root Check', AranRASP.selectors.rootCheck);
    await _runSecurityCheck('Jailbreak Check', AranRASP.selectors.jailbreakCheck);
    await _runSecurityCheck('Frida Check', AranRASP.selectors.fridaCheck);
    await _runSecurityCheck('Emulator Check', AranRASP.selectors.emulatorCheck);
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('ARAN RASP Demo'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            onPressed: _runAllChecks,
            tooltip: 'Run All Checks',
          ),
        ],
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'RASP Engine Status',
                      style: Theme.of(context).textTheme.titleLarge,
                    ),
                    const SizedBox(height: 8),
                    Row(
                      children: [
                        Icon(
                          _isInitialized ? Icons.check_circle : Icons.error,
                          color: _isInitialized ? Colors.green : Colors.red,
                        ),
                        const SizedBox(width: 8),
                        Text(
                          _isInitialized ? 'Initialized' : 'Not Initialized',
                          style: TextStyle(
                            color: _isInitialized ? Colors.green : Colors.red,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: _runAllChecks,
              icon: const Icon(Icons.security),
              label: const Text('Run All Security Checks'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.all(16),
              ),
            ),
            const SizedBox(height: 16),
            Expanded(
              child: Card(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Padding(
                      padding: const EdgeInsets.all(16.0),
                      child: Text(
                        'Security Check Results',
                        style: Theme.of(context).textTheme.titleLarge,
                      ),
                    ),
                    const Divider(),
                    Expanded(
                      child: _results.isEmpty
                          ? const Center(
                              child: Text(
                                'No security checks run yet',
                                style: TextStyle(color: Colors.grey),
                              ),
                            )
                          : ListView.builder(
                              itemCount: _results.length,
                              itemBuilder: (context, index) {
                                final result = _results[index];
                                return ListTile(
                                  leading: Icon(
                                    _getResultIcon(result.result),
                                    color: _getResultColor(result.result),
                                  ),
                                  title: Text(result.name),
                                  subtitle: Text(
                                    'Result: 0x${result.result.toRadixString(16).toUpperCase()}',
                                  ),
                                  trailing: Text(
                                    _formatTime(result.timestamp),
                                    style: const TextStyle(fontSize: 12),
                                  ),
                                );
                              },
                            ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  IconData _getResultIcon(int result) {
    if (result == 0x7F3D) return Icons.check_circle;
    if (result == 0x1A2B) return Icons.warning;
    return Icons.error;
  }

  Color _getResultColor(int result) {
    if (result == 0x7F3D) return Colors.green;
    if (result == 0x1A2B) return Colors.orange;
    return Colors.red;
  }

  String _formatTime(DateTime time) {
    return '${time.hour}:${time.minute.toString().padLeft(2, '0')}:${time.second.toString().padLeft(2, '0')}';
  }
}

class SecurityCheckResult {
  final String name;
  final int result;
  final DateTime timestamp;

  SecurityCheckResult({
    required this.name,
    required this.result,
    required this.timestamp,
  });
}
