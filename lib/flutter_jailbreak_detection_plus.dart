import 'dart:async';

import 'package:flutter/services.dart';

/// Enum representing the five root detection families, matching Android implementation.
enum RootFamily {
  binaries('BINARIES'),
  packages('PACKAGES'),
  props('PROPS'),
  paths('PATHS'),
  busybox('BUSYBOX');

  const RootFamily(this.key);

  final String key;
}

class FlutterJailbreakDetectionPlus {
  static const MethodChannel _channel =
      const MethodChannel('flutter_jailbreak_detection');

  /// Checks if the device is jailbroken/rooted.
  ///
  /// ----- BELOW WORKS ONLY FOR ANDROID -----
  /// [enabledFamilies] - Set of enabled root detection families (default: BINARIES, PACKAGES, PROPS).
  /// [minFamilies] - Minimum number of triggered families to return true (default: 2).
  static Future<bool> jailbroken({
    List<RootFamily>? enabledFamilies,
    int minFamilies = 2,
  }) async {
    final List<String>? families = enabledFamilies?.map((e) => e.key).toList();
    final args = families == null
        ? null
        : <String, dynamic>{
            'enabledFamilies': families,
            'minFamilies': minFamilies,
          };
    bool? jailbroken = await _channel.invokeMethod<bool>('jailbroken', args);
    return jailbroken ?? true;
  }

  static Future<bool> get developerMode async {
    bool? developerMode = await _channel.invokeMethod<bool>('developerMode');
    return developerMode ?? true;
  }
}
