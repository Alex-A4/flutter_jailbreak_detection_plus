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
  /// Returns list of failed checks
  static Future<List<RootFamily>> jailbrokenAndroid() async {
    List<String>? jailbroken =
        await _channel.invokeMethod<List<String>>('jailbroken');
    return jailbroken
            ?.map((e) =>
                RootFamily.values.firstWhere((element) => element.key == e))
            .toList() ??
        [];
  }

  /// Checks if the device is jailbroken/rooted.
  static Future<bool> jailbrokenIos() async {
    bool? jailbroken = await _channel.invokeMethod<bool>('jailbroken');
    return jailbroken ?? false;
  }

  static Future<bool> get developerMode async {
    bool? developerMode = await _channel.invokeMethod<bool>('developerMode');
    return developerMode ?? true;
  }
}
