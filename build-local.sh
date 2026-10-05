#!/usr/bin/env bash
set -euo pipefail

# Local APK build and install helper for capability-detector
# Use on WSL or Linux with Android SDK + adb connected to a device.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

ANDROID_HOME="${ANDROID_HOME:-$HOME/Android/Sdk}"
export ANDROID_HOME
export ANDROID_SDK_ROOT="$ANDROID_HOME"

SDKMANAGER="$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager"
BUILD_TOOLS_DIR="$ANDROID_HOME/build-tools/34.0.0"
PLATFORM_DIR="$ANDROID_HOME/platforms/android-34"
KEYSTORE_PATH="$ROOT_DIR/build/release.jks"
APK_OUT="$ROOT_DIR/RootScope.apk"

mkdir -p "$ROOT_DIR/build"

if [ ! -x "$SDKMANAGER" ]; then
  echo "[1/5] Installing Android command line tools ..."
  mkdir -p "$ANDROID_HOME/cmdline-tools"
  TMP_DIR="$(mktemp -d)"
  curl -L -o "$TMP_DIR/cmdline-tools.zip" "https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip"
  unzip -q "$TMP_DIR/cmdline-tools.zip" -d "$TMP_DIR"
  mkdir -p "$ANDROID_HOME/cmdline-tools/latest"
  cp -r "$TMP_DIR/cmdline-tools/"* "$ANDROID_HOME/cmdline-tools/latest/"
  rm -rf "$TMP_DIR"
fi

if [ ! -d "$BUILD_TOOLS_DIR" ] || [ ! -d "$PLATFORM_DIR" ]; then
  echo "[2/5] Installing Android platform + build-tools ..."
  yes | "$SDKMANAGER" --licenses >/dev/null 2>&1 || true
  "$SDKMANAGER" "platforms;android-34" "build-tools;34.0.0" > /dev/null
fi

export PATH="$BUILD_TOOLS_DIR:$PATH"

if [ ! -f "$KEYSTORE_PATH" ]; then
  echo "[3/5] Generating signing keystore ..."
  mkdir -p "$ROOT_DIR/build"
  keytool -genkeypair \
    -keystore "$KEYSTORE_PATH" \
    -storepass 123456 \
    -keypass 123456 \
    -alias rootscope \
    -keyalg RSA \
    -keysize 2048 \
    -validity 10000 \
    -dname "CN=RootScope"
fi

if [ ! -f "$ROOT_DIR/res/values/strings.xml" ]; then
  echo "[4/5] Building launcher resources ..."
  if [ -d "$ROOT_DIR/icon" ]; then
    sudo apt-get update -qq
    sudo apt-get install -y -qq librsvg2-bin >/dev/null
    mkdir -p "$ROOT_DIR/res/mipmap-mdpi" "$ROOT_DIR/res/mipmap-hdpi" "$ROOT_DIR/res/mipmap-xhdpi" "$ROOT_DIR/res/mipmap-xxhdpi" "$ROOT_DIR/res/mipmap-xxxhdpi"
    declare -A legacy=( [mdpi]=48 [hdpi]=72 [xhdpi]=96 [xxhdpi]=144 [xxxhdpi]=192 )
    declare -A fg=( [mdpi]=108 [hdpi]=162 [xhdpi]=216 [xxhdpi]=324 [xxxhdpi]=432 )
    for d in "${!legacy[@]}"; do
      rsvg-convert -w "${legacy[$d]}" -h "${legacy[$d]}" "$ROOT_DIR/icon/ic_launcher.svg" -o "$ROOT_DIR/res/mipmap-$d/ic_launcher.png"
      cp "$ROOT_DIR/res/mipmap-$d/ic_launcher.png" "$ROOT_DIR/res/mipmap-$d/ic_launcher_round.png"
      rsvg-convert -w "${fg[$d]}" -h "${fg[$d]}" "$ROOT_DIR/icon/ic_launcher_foreground.svg" -o "$ROOT_DIR/res/mipmap-$d/ic_launcher_foreground.png"
    done
  fi
fi

echo "[5/5] Building APK ..."
mkdir -p "$ROOT_DIR/build/classes" "$ROOT_DIR/build/dex" "$ROOT_DIR/build/res"

if [ ! -f "$ROOT_DIR/build/res.zip" ]; then
  aapt2 compile --dir "$ROOT_DIR/res" -o "$ROOT_DIR/build/res.zip"
fi

aapt2 link \
  -o "$ROOT_DIR/build/base.apk" \
  -I "$PLATFORM_DIR/android.jar" \
  --manifest "$ROOT_DIR/AndroidManifest.xml" \
  --min-sdk-version 29 \
  --target-sdk-version 34 \
  "$ROOT_DIR/build/res.zip"

javac -source 17 -target 17 -encoding UTF-8 \
  -classpath "$PLATFORM_DIR/android.jar" \
  -d "$ROOT_DIR/build/classes" \
  "$ROOT_DIR/src/com/octopusassem/rootscope/MainActivity.java"

d8 --lib "$PLATFORM_DIR/android.jar" --min-api 29 --output "$ROOT_DIR/build/dex" $(find "$ROOT_DIR/build/classes" -name '*.class')
cp "$ROOT_DIR/build/dex/classes.dex" "$ROOT_DIR/build/classes.dex"
(cd "$ROOT_DIR/build" && zip -q -X base.apk classes.dex)

zipalign -f -p 4 "$ROOT_DIR/build/base.apk" "$ROOT_DIR/build/aligned.apk"

apksigner sign \
  --ks "$KEYSTORE_PATH" --ks-pass pass:123456 \
  --key-pass pass:123456 --ks-key-alias rootscope \
  --v1-signing-enabled true --v2-signing-enabled true \
  --out "$APK_OUT" "$ROOT_DIR/build/aligned.apk"

apksigner verify --print-certs "$APK_OUT"
ls -lh "$APK_OUT"

if command -v adb >/dev/null 2>&1; then
  echo "Installing APK to connected device..."
  adb install -r "$APK_OUT"
else
  echo "adb not found. Install Android platform-tools first, then run: adb install -r '$APK_OUT'"
fi
