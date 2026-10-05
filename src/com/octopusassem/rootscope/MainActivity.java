package com.octopusassem.rootscope;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * Universal root and manager inspector.
 *
 * - Non-root mode: tries to detect root artifacts, known manager packages and common paths.
 * - Root mode: reads KernelSU / ReSukiSU / Magisk / APatch related metadata when available.
 */
public class MainActivity extends Activity {

    private static final String PROBE =
        "set +e\n" +
        "echo '###DEVICE'\n" +
        "getprop ro.product.model\n" +
        "getprop ro.product.brand\n" +
        "getprop ro.build.version.release\n" +
        "getprop ro.build.version.sdk\n" +
        "getprop ro.build.fingerprint\n" +
        "echo '###SELINUX'\n" +
        "getenforce 2>/dev/null || cat /sys/fs/selinux/enforce 2>/dev/null || echo unknown\n" +
        "echo '###ROOT'\n" +
        "id\n" +
        "echo '###PATHS'\n" +
        "ls -ld /system/bin/su /system/xbin/su /sbin/su /data/adb /data/adb/ksud /data/adb/magisk /data/adb/apd /data/adb/modules 2>/dev/null || true\n" +
        "echo '###PKGS'\n" +
        "pm list packages 2>/dev/null | grep -Ei 'magisk|kernelsu|resukisu|apatch|ksu|root' || true\n" +
        "echo '###PROC'\n" +
        "cat /proc/modules 2>/dev/null | grep -Ei 'ksu|susfs|apatch|magisk' || true\n" +
        "echo '###INFO'\n" +
        "if [ -x \"/data/adb/ksud\" ]; then /data/adb/ksud debug info 2>/dev/null || true; fi\n" +
        "if [ -x \"/data/adb/magisk\" ]; then /data/adb/magisk --path 2>/dev/null || true; fi\n" +
        "if [ -x \"/data/adb/apd\" ]; then /data/adb/apd --help 2>/dev/null | head -n 20 || true; fi\n" +
        "echo '###FEATURES'\n" +
        "if [ -x \"/data/adb/ksud\" ]; then /data/adb/ksud feature list 2>/dev/null || true; fi\n" +
        "echo '###SECCOMP'\n" +
        "cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null || true\n" +
        "echo '###SUSFS'\n" +
        "if [ -x \"/data/adb/ksud\" ]; then /data/adb/ksud susfs show variant 2>/dev/null || true; /data/adb/ksud susfs show enabled_features 2>/dev/null || true; fi\n" +
        "echo '###UMOUNT'\n" +
        "if [ -x \"/data/adb/ksud\" ]; then /data/adb/ksud kernel umount list 2>/dev/null || true; fi\n" +
        "echo '###DYN'\n" +
        "if [ -x \"/data/adb/ksud\" ]; then /data/adb/ksud kernel dynamic-manager get 2>/dev/null || true; fi\n" +
        "echo '###MODULES'\n" +
        "if [ -x \"/data/adb/ksud\" ]; then /data/adb/ksud module list 2>/dev/null || true; fi\n" +
        "echo '###MAGISK'\n" +
        "ls -ld /data/adb/magisk /data/adb/modules 2>/dev/null || true\n" +
        "ls -l /data/adb/modules 2>/dev/null | head -n 50 || true\n" +
        "echo '###APATCH'\n" +
        "ls -ld /data/adb/apd /data/adb/modules/apatch 2>/dev/null || true\n" +
        "echo '###END'\n";

    private TextView status;
    private LinearLayout content;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String lastRaw = "";

    private static final int C_BG = Color.parseColor("#0a0e13");
    private static final int C_CARD = Color.parseColor("#141b23");
    private static final int C_LINE = Color.parseColor("#28333f");
    private static final int C_TXT = Color.parseColor("#e7eef6");
    private static final int C_MUT = Color.parseColor("#93a4b8");
    private static final int C_GRN = Color.parseColor("#34d399");
    private static final int C_RED = Color.parseColor("#f87171");
    private static final int C_AMB = Color.parseColor("#fbbf24");
    private static final int C_BLUE = Color.parseColor("#60a5fa");
    private static final int C_VIO = Color.parseColor("#a78bfa");

    @Override
    protected void onCreate(Bundle bundle) {
        super.onCreate(bundle);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(C_BG);
        root.setPadding(dp(14), dp(14), dp(14), dp(8));

        TextView title = new TextView(this);
        title.setText("RootScope Universal");
        title.setTextColor(C_TXT);
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        status = new TextView(this);
        status.setText("Running device and root detection...");
        status.setTextColor(C_MUT);
        status.setTextSize(12);
        status.setPadding(0, dp(2), 0, dp(10));
        root.addView(status);

        LinearLayout bar = new LinearLayout(this);
        bar.setOrientation(LinearLayout.HORIZONTAL);

        Button refresh = new Button(this);
        refresh.setText("REFRESH");
        refresh.setAllCaps(false);

        Button copy = new Button(this);
        copy.setText("COPY REPORT");
        copy.setAllCaps(false);

        bar.addView(refresh, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        bar.addView(copy, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f));
        root.addView(bar);

        ScrollView sc = new ScrollView(this);
        content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(0, dp(10), 0, dp(20));
        sc.addView(content);
        root.addView(sc, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);

        refresh.setOnClickListener(v -> runProbe());
        copy.setOnClickListener(v -> {
            ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
            cm.setPrimaryClip(ClipData.newPlainText("report", lastRaw));
            Toast.makeText(this, "Copied", Toast.LENGTH_SHORT).show();
        });

        runProbe();
    }

    private void runProbe() {
        content.removeAllViews();
        status.setText("Running...");
        new Thread(() -> {
            String raw;
            try {
                raw = execShell(new String[] { "su", "-c", PROBE }, 50000L);
            } catch (Exception e) {
                raw = "###ROOT\nERROR " + e + "\n###END\n";
            }
            final String rawF = raw;
            final Map<String, String> sec = parseSections(rawF);
            ui.post(() -> {
                lastRaw = rawF;
                renderAll(sec);
            });
        }).start();
    }

    private String execShell(String[] cmd, long timeoutMs) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = r.readLine()) != null) {
            sb.append(line).append('\n');
        }
        if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            p.destroyForcibly();
            sb.append("[timeout]\n");
        }
        return sb.toString();
    }

    private Map<String, String> parseSections(String raw) {
        Map<String, String> out = new LinkedHashMap<>();
        String cur = null;
        StringBuilder buf = new StringBuilder();
        for (String line : raw.split("\n")) {
            if (line.startsWith("###")) {
                if (cur != null) out.put(cur, buf.toString().trim());
                String name = line.substring(3).trim();
                if (name.equals("END")) {
                    cur = null;
                    break;
                }
                cur = name;
                buf = new StringBuilder();
            } else if (cur != null) {
                buf.append(line).append('\n');
            }
        }
        if (cur != null) out.put(cur, buf.toString().trim());
        return out;
    }

    private void renderAll(Map<String, String> sec) {
        String rootText = sec.get("ROOT");
        boolean rooted = rootText != null && rootText.contains("uid=0");
        String device = sec.get("DEVICE");
        String firstDeviceLine = firstLine(device);

        LinearLayout srow = badgeRow();
        addBadge(srow, badge(rooted ? "ROOT OK" : "ROOT NOT FOUND", rooted ? C_GRN : C_RED));
        addBadge(srow, badge("SELinux " + firstNonEmpty(sec.get("SELINUX"), "unknown"), rooted ? C_BLUE : C_MUT));
        addBadge(srow, badge("Managers: " + countManagerRefs(sec), C_VIO));
        addCard("SUMMARY", srow,
            kv("Device", firstDeviceLine),
            kv("Brand", secondLine(device)),
            kv("Android", thirdLine(device)),
            kv("Root", rooted ? "uid=0" : "not detected"));

        if (!rooted) {
            renderNonRootMode(sec);
            return;
        }

        renderRootMode(sec);
    }

    private void renderNonRootMode(Map<String, String> sec) {
        String paths = sec.get("PATHS");
        String pkgs = sec.get("PKGS");
        String selinux = sec.get("SELINUX");
        String device = sec.get("DEVICE");

        status.setTextColor(C_RED);
        status.setText("No root detected. Looking for root artifacts and manager traces.");

        addCard("NON-ROOT SIGNALS",
            kv("SELinux", firstNonEmpty(selinux, "unknown")),
            kv("su paths", firstNonEmpty(paths, "none")),
            kv("Manager packages", firstNonEmpty(pkgs, "none")),
            kv("Build fingerprint", firstNonEmpty(secondLine(device), "unknown")));

        if (paths != null && !paths.isEmpty()) {
            addCard("COMMON ROOT PATHS", mono(paths));
        }

        if (pkgs != null && !pkgs.isEmpty()) {
            addCard("PACKAGE HINTS", mono(pkgs));
        }

        renderKnownRootArtifacts();
    }

    private void renderRootMode(Map<String, String> sec) {
        status.setTextColor(C_GRN);
        status.setText("Root detected. Reading kernel and manager metadata.");

        addCard("ROOT MODE",
            kv("uid", firstNonEmpty(sec.get("ROOT"), "unknown")),
            kv("SELinux", firstNonEmpty(sec.get("SELINUX"), "unknown")),
            kv("Manager hints", detectManagerHints(sec)));

        String info = sec.get("INFO");
        String feats = sec.get("FEATURES");
        String susfs = sec.get("SUSFS");
        String modules = sec.get("MODULES");
        String magisk = sec.get("MAGISK");
        String apatch = sec.get("APATCH");
        String proc = sec.get("PROC");

        if (info != null && !info.isEmpty()) {
            addCard("KERNEL/ROOT INFO", mono(info));
        }
        if (feats != null && !feats.isEmpty()) {
            addCard("FEATURES", mono(feats));
        }
        if (susfs != null && !susfs.isEmpty()) {
            addCard("SUSFS", mono(susfs));
        }
        if (modules != null && !modules.isEmpty()) {
            renderModuleList(modules);
        }
        if (proc != null && !proc.isEmpty()) {
            addCard("PROC MODULES", mono(proc));
        }
        if (magisk != null && !magisk.isEmpty()) {
            addCard("MAGISK ARTIFACTS", mono(magisk));
        }
        if (apatch != null && !apatch.isEmpty()) {
            addCard("APATCH ARTIFACTS", mono(apatch));
        }

        renderKnownRootArtifacts();
    }

    private void renderModuleList(String modules) {
        LinearLayout c = card();
        c.addView(t("MODULES", C_BLUE, 13, true));
        String s = modules == null ? "" : modules.trim();
        if (s.isEmpty()) {
            c.addView(t("none", C_MUT, 12, false));
            content.addView(c);
            return;
        }
        if (!s.startsWith("[")) {
            c.addView(t("could not parse module list", C_RED, 12, false));
            c.addView(mono(s));
            content.addView(c);
            return;
        }
        try {
            JSONArray arr = new JSONArray(s);
            c.addView(t(arr.length() + " installed", C_MUT, 12, false));
            for (int i = 0; i < arr.length(); i++) {
                JSONObject o = arr.getJSONObject(i);
                LinearLayout m = new LinearLayout(this);
                m.setOrientation(LinearLayout.VERTICAL);
                GradientDrawable g = new GradientDrawable();
                g.setCornerRadius(dp(9));
                g.setColor(Color.parseColor("#1b2530"));
                g.setStroke(dp(1), C_LINE);
                m.setBackground(g);
                m.setPadding(dp(10), dp(10), dp(10), dp(10));
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
                lp.setMargins(0, dp(6), 0, 0);
                m.setLayoutParams(lp);

                String name = o.optString("name", o.optString("id", "?"));
                m.addView(t(name, C_TXT, 14, true));
                m.addView(t(o.optString("id", ""), C_MUT, 11, false));
                String ver = o.optString("version", "");
                String au = o.optString("author", "");
                m.addView(t((ver.isEmpty() ? "" : "v" + ver) + (au.isEmpty() ? "" : "   ·   " + au), C_VIO, 11.5f, false));
                String desc = o.optString("description", "");
                if (!desc.isEmpty()) m.addView(t(desc, C_MUT, 12, false));

                LinearLayout br = badgeRow();
                boolean en = "true".equals(o.optString("enabled"));
                addBadge(br, badge(en ? "ENABLED" : "DISABLED", en ? C_GRN : C_RED));
                if ("true".equals(o.optString("mount"))) addBadge(br, badge("MOUNT", C_BLUE));
                if ("true".equals(o.optString("web"))) addBadge(br, badge("WEBUI", C_VIO));
                if ("true".equals(o.optString("action"))) addBadge(br, badge("ACTION", C_AMB));
                if ("true".equals(o.optString("update"))) addBadge(br, badge("UPDATE", C_AMB));
                if ("true".equals(o.optString("remove"))) addBadge(br, badge("REMOVE", C_RED));
                m.addView(br);
                c.addView(m);
            }
        } catch (Exception e) {
            c.addView(t("parse error: " + e.getMessage(), C_RED, 12, false));
            c.addView(mono(s));
        }
        content.addView(c);
    }

    private void renderKnownRootArtifacts() {
        List<String> paths = new ArrayList<>();
        paths.add("/system/bin/su");
        paths.add("/system/xbin/su");
        paths.add("/sbin/su");
        paths.add("/data/adb/magisk");
        paths.add("/data/adb/ksud");
        paths.add("/data/adb/apd");
        paths.add("/data/adb/modules");
        paths.add("/data/adb/modules/apatch");
        paths.add("/data/adb/ksu");
        paths.add("/data/adb/lkm");

        LinearLayout c = card();
        c.addView(t("ROOT ARTIFACT PATHS", C_BLUE, 13, true));
        for (String p : paths) {
            File f = new File(p);
            boolean exists = f.exists();
            c.addView(kv(p, exists ? "present" : "missing"));
        }
        content.addView(c);
    }

    private int countManagerRefs(Map<String, String> sec) {
        int n = 0;
        String[] keys = new String[] { "PKGS", "PATHS", "MAGISK", "APATCH", "INFO", "MODULES", "FEATURES" };
        for (String k : keys) {
            String v = sec.get(k);
            if (v == null) continue;
            String lower = v.toLowerCase();
            if (lower.contains("magisk")) n++;
            if (lower.contains("kernelsu") || lower.contains("ksu")) n++;
            if (lower.contains("resukisu")) n++;
            if (lower.contains("apatch")) n++;
        }
        return Math.max(1, n);
    }

    private String detectManagerHints(Map<String, String> sec) {
        StringBuilder sb = new StringBuilder();
        String[] sources = new String[] {
            sec.get("PKGS"), sec.get("INFO"), sec.get("MODULES"), sec.get("MAGISK"), sec.get("APATCH"), sec.get("FEATURES")
        };
        for (String s : sources) {
            if (s == null) continue;
            String lower = s.toLowerCase();
            if (lower.contains("magisk")) sb.append("Magisk ");
            if (lower.contains("kernelsu") || lower.contains("ksu")) sb.append("KernelSU ");
            if (lower.contains("resukisu")) sb.append("ReSukiSU ");
            if (lower.contains("apatch")) sb.append("APatch ");
            if (lower.contains("susfs")) sb.append("SUSFS ");
        }
        return sb.length() == 0 ? "none detected" : sb.toString().trim();
    }

    private String firstLine(String s) {
        if (s == null || s.trim().isEmpty()) return "unknown";
        String[] parts = s.split("\n");
        return parts[0].trim();
    }

    private String secondLine(String s) {
        if (s == null || s.trim().isEmpty()) return "unknown";
        String[] parts = s.split("\n");
        return parts.length > 1 ? parts[1].trim() : "unknown";
    }

    private String thirdLine(String s) {
        if (s == null || s.trim().isEmpty()) return "unknown";
        String[] parts = s.split("\n");
        return parts.length > 2 ? parts[2].trim() : "unknown";
    }

    private String firstNonEmpty(String a, String fallback) {
        if (a == null || a.trim().isEmpty()) return fallback;
        return a.trim();
    }

    private LinearLayout badgeRow() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.HORIZONTAL);
        l.setPadding(0, dp(5), 0, 0);
        return l;
    }

    private void addBadge(LinearLayout row, TextView b) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.WRAP_CONTENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, dp(6), dp(4));
        row.addView(b, lp);
    }

    private TextView badge(String text, int color) {
        TextView v = t(text, color, 11, true);
        int p = dp(7);
        v.setPadding(p, dp(2), p, dp(2));
        GradientDrawable g = new GradientDrawable();
        g.setCornerRadius(dp(6));
        g.setColor(alpha(color, 0x22));
        g.setStroke(dp(1), alpha(color, 0x66));
        v.setBackground(g);
        return v;
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        GradientDrawable g = new GradientDrawable();
        g.setCornerRadius(dp(12));
        g.setColor(C_CARD);
        g.setStroke(dp(1), C_LINE);
        c.setBackground(g);
        c.setPadding(dp(12), dp(12), dp(12), dp(12));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.setMargins(0, 0, 0, dp(10));
        c.setLayoutParams(lp);
        return c;
    }

    private void addCard(String title, View... items) {
        LinearLayout c = card();
        if (title != null) {
            TextView h = t(title, C_BLUE, 12.5f, true);
            h.setPadding(0, 0, 0, dp(6));
            c.addView(h);
        }
        for (View v : items) c.addView(v);
        content.addView(c);
    }

    private LinearLayout kv(String k, String v) {
        LinearLayout r = new LinearLayout(this);
        r.setOrientation(LinearLayout.HORIZONTAL);
        r.setPadding(0, dp(3), 0, dp(3));
        TextView kk = t(k, C_MUT, 12, false);
        kk.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.42f));
        TextView vv = t(v, C_TXT, 12, false);
        vv.setTypeface(Typeface.MONOSPACE);
        vv.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.58f));
        r.addView(kk);
        r.addView(vv);
        return r;
    }

    private TextView t(String s, int color, float size, boolean bold) {
        TextView v = new TextView(this);
        v.setText(s);
        v.setTextColor(color);
        v.setTextSize(size);
        if (bold) v.setTypeface(Typeface.DEFAULT_BOLD);
        v.setTextIsSelectable(false);
        return v;
    }

    private TextView mono(String s) {
        TextView v = t(s, C_GRN, 11.5f, false);
        v.setTypeface(Typeface.MONOSPACE);
        v.setTextIsSelectable(true);
        return v;
    }

    private int alpha(int color, int a) {
        return Color.argb(a, Color.red(color), Color.green(color), Color.blue(color));
    }

    private int dp(int x) {
        return Math.round(getResources().getDisplayMetrics().density * x);
    }
}
