# Capability Detector

Minimal Android app that reads every KernelSU / ReSukiSU capability the kernel
reports to its manager, via `ksud`. If it cannot obtain root it says so.

Built with aapt2 + javac + d8 + apksigner (no Gradle). APK is uploaded as the
`CapabilityDetector` artifact.
