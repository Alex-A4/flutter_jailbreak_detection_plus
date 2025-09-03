package yazan.alkamsheh.flutterjailbreakdetectionplus

import android.content.Context
import android.provider.Settings
import com.scottyab.rootbeer.RootBeer

import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.MethodChannel.Result
import io.flutter.plugin.common.MethodChannel.MethodCallHandler
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.embedding.engine.plugins.FlutterPlugin.FlutterPluginBinding

// Define an enum of the five RootBeer signal families.
enum class RootFamily(val key: String) {
    BINARIES("BINARIES"),   // Family 1: su binaries/traces and system write access
    PACKAGES("PACKAGES"),   // Family 2: root managers/dangerous/cloaking packages
    PROPS("PROPS"),         // Family 3: "dangerous" system properties and test-keys
    PATHS("PATHS"),         // Family 4: dangerous paths and unusual permissions on system paths
    BUSYBOX("BUSYBOX")      // Family 5: presence of busybox (noisy, often yields false positives)
}


class FlutterJailbreakDetectionPlugin : FlutterPlugin, MethodCallHandler {
    private lateinit var context: Context
    private lateinit var channel: MethodChannel


    override fun onAttachedToEngine(binding: FlutterPluginBinding) {
        channel = MethodChannel(binding.binaryMessenger, "flutter_jailbreak_detection")
        context = binding.applicationContext
        channel.setMethodCallHandler(this)
    }


    override fun onDetachedFromEngine(binding: FlutterPluginBinding) {
        channel.setMethodCallHandler(null)
    }


    private fun isDevMode(): Boolean {
        return Settings.Secure.getInt(
            context.contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
        ) != 0
    }


    override fun onMethodCall(call: MethodCall, result: Result): Unit {
        if (call.method.equals("jailbroken")) {
            val rootBeer = RootBeer(context)
            // Return a list of failing (triggered) families as string keys
            val failing = isDeviceSuspicious(rootBeer)
            result.success(failing.map { it.key })
        } else if (call.method.equals("developerMode")) {
            result.success(isDevMode())
        } else {
            result.notImplemented()
        }
    }

    /**
     * Checks whether the device looks "suspicious" using the RootBeer family model.
     *
     * @param rootBeer         RootBeer instance created with the current Context.
     * @param enabledFamilies  Set of enabled families (any combination of the five).
     * @param minFamilies      Minimum number of triggered families to return true (default 2).
     *
     * @return true if the device appears "suspicious" (root/compromise likely), otherwise false.
     */
    fun isDeviceSuspicious(rootBeer: RootBeer): List<RootFamily> {
        val failedFamilies = mutableListOf<RootFamily>()
        // 1) BINARIES: check su traces and the ability to write to the system partition.
        //    Strong family: usually indicates real root/modification.
        if (rootBeer.checkForSuBinary() ||            // Look for the su binary in common locations
            rootBeer.checkSuExists()                // Additional check for the existence of su
             || rootBeer.checkForRootNative()             // Native su search from C (bypasses Java-level cloaking)
        ) {
            failedFamilies.add(RootFamily.BINARIES)
        }

        // 2) PACKAGES: check for root managers/dangerous/cloaking apps.
        //    Strong but sometimes noisy: packages can be installed without actual root.
        if (rootBeer.detectRootManagementApps() ||  // Magisk/SuperSU, etc.
            rootBeer.detectPotentiallyDangerousApps() ||// Busybox installers, su emulators, etc.
            rootBeer.detectRootCloakingApps()          // Xposed/RootCloak and any attempts to hide root
        ) {
            failedFamilies.add(RootFamily.PACKAGES)
        }

        // 3) PROPS: dangerous system properties and test-keys.
        //    Noisy family: often appears on Samsung/custom builds without real root.
        if (rootBeer.detectTestKeys() ||    // Firmware signed with test-keys (not equal to root, but suspicious)
            rootBeer.checkForDangerousProps()         // Check ro.debuggable/ro.secure and similar flags
        ) {
            failedFamilies.add(RootFamily.PROPS)
        }

        // 4) PATHS: dangerous paths and incorrect permissions on paths.
        //    Useful as a complement to BINARIES; sometimes catches bypasses through unusual directories.
        if (rootBeer.checkForRWPaths()) { // Presence of su/busybox/xposed in known "root paths"
            failedFamilies.add(RootFamily.PATHS)
        }

        // 5) BUSYBOX: presence of busybox.
        //    Found stock on some devices → high noise; enable consciously.
        if (rootBeer.checkForBusyBoxBinary()) {          // Finds busybox, but by itself this doesn't imply root
            failedFamilies.add(RootFamily.BUSYBOX)
        }

        return failedFamilies
    }
}
