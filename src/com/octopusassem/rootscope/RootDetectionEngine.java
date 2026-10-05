package com.octopusassem.rootscope;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * RootDetectionEngine: Professional root detection without relying on su access.
 * 
 * Strategy:
 * 1. Non-root artifacts: check filesystem paths, build properties, installed packages
 * 2. Behavioral signals: check for suspicious process activity, permission oddities
 * 3. Manager fingerprinting: distinguish between Magisk, KernelSU, APatch, etc.
 * 4. Anti-detection measures: detect obfuscation and hiding attempts
 */
public class RootDetectionEngine {

    public static class DetectionResult {
        public boolean hasRoot;
        public String managerType; // "KernelSU", "Magisk", "APatch", "Unknown", "None"
        public int confidenceLevel; // 0-100
        public List<String> signals; // evidence list
        public Map<String, String> details; // key-value details
        public long scanDurationMs;

        public DetectionResult() {
            this.signals = new ArrayList<>();
            this.details = new HashMap<>();
            this.hasRoot = false;
            this.managerType = "None";
            this.confidenceLevel = 0;
            this.scanDurationMs = 0;
        }
    }

    // === ARTIFACT-BASED DETECTION (Non-Root) ===

    /**
     * Scan for common root manager artifacts without requiring root.
     * This is the first layer of detection and works on all devices.
     */
    public static DetectionResult scanForArtifacts() {
        DetectionResult result = new DetectionResult();
        long startTime = System.currentTimeMillis();

        // Phase 1: Check filesystem paths
        checkCommonSuPaths(result);
        checkManagerPaths(result);
        checkModulePaths(result);

        // Phase 2: Check installed packages
        checkInstalledPackages(result);

        // Phase 3: Check build properties
        checkBuildProperties(result);

        // Phase 4: Check for suspicious processes
        checkProcessSignals(result);

        // Phase 5: Fingerprint manager type
        fingerprintManager(result);

        result.scanDurationMs = System.currentTimeMillis() - startTime;

        // Calculate confidence
        result.confidenceLevel = calculateConfidence(result);

        return result;
    }

    private static void checkCommonSuPaths(DetectionResult result) {
        String[] suPaths = {
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/bin/ksu",
            "/system/xbin/ksu",
            "/data/adb/magisk",
            "/data/adb/ksud",
            "/data/adb/apd",
            "/data/adb/su",
            "/magisk",
            "/cache/magisk_manager.apk"
        };

        for (String path : suPaths) {
            File f = new File(path);
            if (f.exists()) {
                result.signals.add("Found su/manager binary: " + path);
                result.details.put("artifact_" + path, "present");
                if (!result.hasRoot) result.hasRoot = true;
            }
        }
    }

    private static void checkManagerPaths(DetectionResult result) {
        String[] managerPaths = {
            "/data/adb",
            "/data/adb/modules",
            "/data/adb/magisk",
            "/data/adb/magiskhide",
            "/data/adb/ksud",
            "/data/adb/ksu",
            "/data/adb/apd",
            "/data/adb/lkm",
            "/data/adb/riru",
            "/system/app/MagiskManager",
            "/system/app/KernelSUManager",
        };

        for (String path : managerPaths) {
            File f = new File(path);
            if (f.exists() && f.isDirectory()) {
                result.signals.add("Manager directory found: " + path);
                result.details.put("manager_dir_" + path, "present");
            }
        }
    }

    private static void checkModulePaths(DetectionResult result) {
        File modulesDir = new File("/data/adb/modules");
        if (modulesDir.exists() && modulesDir.isDirectory()) {
            File[] modules = modulesDir.listFiles();
            if (modules != null && modules.length > 0) {
                result.signals.add("Modules directory with " + modules.length + " entries");
                result.details.put("modules_count", String.valueOf(modules.length));
                for (File module : modules) {
                    if (module.isDirectory()) {
                        result.details.put("module_" + module.getName(), "present");
                    }
                }
            }
        }
    }

    private static void checkInstalledPackages(DetectionResult result) {
        String[] suspiciousPackages = {
            "com.topjohnwu.magisk",
            "com.topjohnwu.magiskhide",
            "com.example.root",
            "io.github.vvb2060.magisk",
            "me.weishu.kernelsu",
            "com.kernelsu.manager",
            "io.github.a13e300.ksuwebui",
            "me.weishu.kernelsu_next",
            "com.apatch.manager",
            "com.apatch",
            "SuperSU",
            "eu.chainfire.supersu",
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "com.zachspong.temprootremovejellybeans",
            "com.koushikdutta.superuser",
            "com.yellowes.su"
        };

        String packageList = getInstalledPackages();
        for (String pkg : suspiciousPackages) {
            if (packageList.contains(pkg)) {
                result.signals.add("Suspicious package installed: " + pkg);
                result.details.put("package_" + pkg, "installed");
                result.hasRoot = true;
            }
        }
    }

    private static void checkBuildProperties(DetectionResult result) {
        String[] suspiciousPropPatterns = {
            "ro.boot.serialno",
            "ro.debuggable",
            "ro.secure",
            "persist.sys.usb.config",
            "ro.build.fingerprint"
        };

        // Check for suspicious property modifications
        String debuggable = getProp("ro.debuggable");
        if ("1".equals(debuggable)) {
            result.signals.add("Device is debuggable (ro.debuggable=1)");
            result.details.put("ro.debuggable", debuggable);
        }

        String secure = getProp("ro.secure");
        if ("0".equals(secure)) {
            result.signals.add("Security disabled (ro.secure=0)");
            result.details.put("ro.secure", secure);
        }
    }

    private static void checkProcessSignals(DetectionResult result) {
        // Check /proc for suspicious processes
        File procDir = new File("/proc");
        if (procDir.exists()) {
            String[] processNames = {
                "magiskd",
                "magisk",
                "ksud",
                "ksu",
                "apd",
                "su",
                "adbd"
            };

            try {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(Runtime.getRuntime().exec("ps").getInputStream())
                );
                String line;
                while ((line = reader.readLine()) != null) {
                    for (String pname : processNames) {
                        if (line.contains(pname)) {
                            result.signals.add("Suspicious process found: " + pname);
                            result.details.put("process_" + pname, "running");
                        }
                    }
                }
                reader.close();
            } catch (Exception e) {
                // Silently fail - ps might not be available
            }
        }
    }

    private static void fingerprintManager(DetectionResult result) {
        // Analyze signals to determine which manager is installed
        String allSignals = String.join(" ", result.signals).toLowerCase();

        if (allSignals.contains("magisk")) {
            result.managerType = "Magisk";
        } else if (allSignals.contains("kernelsu") || allSignals.contains("ksud")) {
            result.managerType = "KernelSU";
        } else if (allSignals.contains("apatch")) {
            result.managerType = "APatch";
        } else if (allSignals.contains("riru")) {
            result.managerType = "Riru";
        } else if (allSignals.contains("xposed")) {
            result.managerType = "Xposed";
        } else if (result.hasRoot) {
            result.managerType = "Unknown";
        } else {
            result.managerType = "None";
        }
    }

    // === BEHAVIORAL DETECTION ===

    /**
     * Detect behavioral patterns that indicate root, even if artifacts are hidden.
     */
    public static DetectionResult scanBehavioral() {
        DetectionResult result = new DetectionResult();
        long startTime = System.currentTimeMillis();

        // Check for unusual SELinux state
        checkSELinuxState(result);

        // Check for mount points
        checkMountPoints(result);

        // Check for capability modifications
        checkCapabilities(result);

        result.scanDurationMs = System.currentTimeMillis() - startTime;
        result.confidenceLevel = calculateConfidence(result);

        return result;
    }

    private static void checkSELinuxState(DetectionResult result) {
        String selinux = getProp("ro.build.selinux");
        if ("0".equals(selinux)) {
            result.signals.add("SELinux disabled at build time");
            result.details.put("ro.build.selinux", "0");
        }

        // Try to read /sys/fs/selinux/enforce
        try {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec("cat /sys/fs/selinux/enforce").getInputStream())
            );
            String line = reader.readLine();
            if (line != null && "0".equals(line.trim())) {
                result.signals.add("SELinux enforcement disabled at runtime");
                result.details.put("selinux_enforce", "0");
            }
            reader.close();
        } catch (Exception e) {
            // SELinux might not be available
        }
    }

    private static void checkMountPoints(DetectionResult result) {
        // Check for unusual mount points that indicate overlayfs or bind mounts
        try {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec("mount").getInputStream())
            );
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.contains("/data/adb") || line.contains("overlay") || line.contains("/magisk")) {
                    result.signals.add("Suspicious mount: " + line);
                    result.details.put("mount_" + result.signals.size(), line);
                    result.hasRoot = true;
                }
            }
            reader.close();
        } catch (Exception e) {
            // mount command might fail
        }
    }

    private static void checkCapabilities(DetectionResult result) {
        // Check if device has unusual capabilities
        try {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec("cat /proc/sys/kernel/seccomp/actions_avail").getInputStream())
            );
            String line = reader.readLine();
            if (line != null) {
                result.details.put("seccomp_actions", line);
            }
            reader.close();
        } catch (Exception e) {
            // Seccomp might not be available
        }
    }

    // === HELPER METHODS ===

    private static String getProp(String prop) {
        try {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec(new String[]{"getprop", prop}).getInputStream())
            );
            String line = reader.readLine();
            reader.close();
            return line != null ? line.trim() : "";
        } catch (Exception e) {
            return "";
        }
    }

    private static String getInstalledPackages() {
        try {
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(Runtime.getRuntime().exec("pm list packages").getInputStream())
            );
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            reader.close();
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static int calculateConfidence(DetectionResult result) {
        int confidence = 0;

        // Artifact-based signals (strong indicators)
        int artifactCount = 0;
        for (String signal : result.signals) {
            if (signal.contains("binary") || signal.contains("directory")) {
                artifactCount++;
            }
        }
        confidence += Math.min(artifactCount * 15, 60); // Max 60 from artifacts

        // Package-based signals (medium indicators)
        if (result.signals.toString().contains("package")) {
            confidence += 20;
        }

        // Process-based signals (medium indicators)
        if (result.signals.toString().contains("process")) {
            confidence += 15;
        }

        // Behavioral signals (medium indicators)
        if (result.signals.toString().contains("SELinux") || result.signals.toString().contains("mount")) {
            confidence += 10;
        }

        return Math.min(confidence, 100);
    }

    public static String generateReport(DetectionResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ROOT DETECTION REPORT ===\n");
        sb.append("Status: ").append(result.hasRoot ? "ROOT DETECTED" : "NO ROOT").append("\n");
        sb.append("Manager: ").append(result.managerType).append("\n");
        sb.append("Confidence: ").append(result.confidenceLevel).append("%\n");
        sb.append("Scan Time: ").append(result.scanDurationMs).append("ms\n\n");

        sb.append("SIGNALS (" + result.signals.size() + "):\n");
        for (String signal : result.signals) {
            sb.append("- ").append(signal).append("\n");
        }

        sb.append("\nDETAILS:\n");
        for (Map.Entry<String, String> entry : result.details.entrySet()) {
            sb.append(entry.getKey()).append(": ").append(entry.getValue()).append("\n");
        }

        return sb.toString();
    }
}
