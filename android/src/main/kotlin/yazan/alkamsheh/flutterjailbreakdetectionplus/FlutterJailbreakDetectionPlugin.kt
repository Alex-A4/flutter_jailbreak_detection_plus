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

    companion object {
        // Возвращает RootFamily по строковому ключу или null, если совпадений нет
        fun fromKey(key: String): RootFamily? {
            return values().firstOrNull { it.key.equals(key, ignoreCase = true) }
        }
    }
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
            // Parse arguments for enabledFamilies and minFamilies
            val familiesArg = call.argument<List<String>>("enabledFamilies")
            val minFamiliesArg = call.argument<Int>("minFamilies")

            val enabledFamilies: Set<RootFamily>? = familiesArg?.mapNotNull {
                try {
                    RootFamily.fromKey(it)
                } catch (e: Exception) {
                    null
                }
            }?.toSet()

            val minFamilies: Int = minFamiliesArg ?: 2

            result.success(isDeviceSuspicious(rootBeer, enabledFamilies, minFamilies))
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
    fun isDeviceSuspicious(
        rootBeer: RootBeer, enabledFamilies: Set<RootFamily>? = null, minFamilies: Int = 2
    ): Boolean {
        // If enabledFamilies == null → use default: the first three families (BINARIES, PACKAGES, PROPS)
        val families = enabledFamilies ?: setOf(
            RootFamily.BINARIES,
            RootFamily.PACKAGES,
            RootFamily.PROPS,
        )

        // 1) BINARIES: check su traces and the ability to write to the system partition.
        //    Strong family: usually indicates real root/modification.
        val binariesTriggered: Boolean =
            (RootFamily.BINARIES in families) && ( // Consider the family only if it's enabled
                    rootBeer.checkForSuBinary() ||            // Look for the su binary in common locations
                            rootBeer.checkSuExists() ||               // Additional check for the existence of su
                            rootBeer.checkForRWSystem() ||            // Check if /system is mounted RW (a sign of modification)
                            rootBeer.checkForRootNative()             // Native su search from C (bypasses Java-level cloaking)
                    )

        // 2) PACKAGES: check for root managers/dangerous/cloaking apps.
        //    Strong but sometimes noisy: packages can be installed without actual root.
        val packagesTriggered: Boolean =
            (RootFamily.PACKAGES in families) && (rootBeer.checkRootManagementApps() ||  // Magisk/SuperSU, etc.
                    rootBeer.checkPotentiallyDangerousApps() ||// Busybox installers, su emulators, etc.
                    rootBeer.checkRootCloakingApps()          // Xposed/RootCloak and any attempts to hide root
                    )

        // 3) PROPS: dangerous system properties and test-keys.
        //    Noisy family: often appears on Samsung/custom builds without real root.
        val propsTriggered: Boolean =
            (RootFamily.PROPS in families) && (rootBeer.checkTestKeys() ||    // Firmware signed with test-keys (not equal to root, but suspicious)
                    rootBeer.checkForDangerousProps()         // Check ro.debuggable/ro.secure and similar flags
                    )

        // 4) PATHS: dangerous paths and incorrect permissions on paths.
        //    Useful as a complement to BINARIES; sometimes catches bypasses through unusual directories.
        val pathsTriggered: Boolean =
            (RootFamily.PATHS in families) && (rootBeer.checkForDangerousPaths() ||  // Presence of su/busybox/xposed in known "root paths"
                    rootBeer.checkForWrongPathPermissions()   // Atypical permissions on system paths (not typical for stock)
                    )

        // 5) BUSYBOX: presence of busybox.
        //    Found stock on some devices → high noise; enable consciously.
        val busyboxTriggered: Boolean =
            (RootFamily.BUSYBOX in families) && rootBeer.checkForBusyBoxBinary()          // Finds busybox, but by itself this doesn't imply root

        // Count how many families have triggered (true).
        var triggeredFamilies = 0                         // Counter of triggered families
        if (binariesTriggered) triggeredFamilies += 1     // Count BINARIES when triggered
        if (packagesTriggered) triggeredFamilies += 1     // Count PACKAGES when triggered
        if (propsTriggered) triggeredFamilies += 1        // Count PROPS when triggered
        if (pathsTriggered) triggeredFamilies += 1        // Count PATHS when triggered
        if (busyboxTriggered) triggeredFamilies += 1      // Count BUSYBOX when triggered

        // Final rule: "suspicious" if >= minFamilies families have triggered.
        // Default 2 — a compromise: greatly reduces FPs, while still catching real root cases.
        return triggeredFamilies >= minFamilies
    }
}
