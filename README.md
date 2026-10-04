# RootScope

Kernel & Root Inspector for KernelSU / ReSukiSU.

One screen that reads everything the manager can see: kernel info, the five
kernel features, installed modules (name/version/author/state/WebUI/action),
SUSFS, seccomp, umount lists and the dynamic manager. If it cannot obtain root
it says so plainly.

Built with aapt2 + javac + d8 + apksigner (no Gradle). The launcher icon is
generated from `icon/*.svg` during the build with rsvg-convert.
