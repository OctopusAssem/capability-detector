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
import java.io.InputStreamReader;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * RootScope: reads everything the (Re)SukiSU manager can see -
 * features, modules (name/version/author/state/webui/action), SUSFS,
 * seccomp, umount lists, dynamic manager. If it cannot obtain root, it says so.
 */
public class MainActivity extends Activity {

    private static final String K = "/data/adb/ksud";
    private static final String PROBE =
        "K=" + K + "\n" +
        "echo \"###DEVICE\"\n" +
        "getprop ro.product.model\n" +
        "getprop ro.product.brand\n" +
        "getprop ro.build.version.release\n" +
        "getprop ro.build.version.sdk\n" +
        "echo \"###ROOT\"\n" +
        "id\n" +
        "echo \"###INFO\"\n" +
        "$K debug info\n" +
        "echo \"###FEATURES\"\n" +
        "$K feature list\n" +
        "echo \"###SECCOMP\"\n" +
        "cat /proc/sys/kernel/seccomp/actions_avail\n" +
        "echo \"###SUSFS\"\n" +
        "$K susfs show variant\n" +
        "$K susfs show enabled_features\n" +
        "echo \"###UMOUNT\"\n" +
        "$K kernel umount list\n" +
        "echo \"###UMOUNTCFG\"\n" +
        "$K umount-config list\n" +
        "echo \"###DYN\"\n" +
        "$K kernel dynamic-manager get\n" +
        "echo \"###MODULES\"\n" +
        "$K module list\n" +
        "echo \"###END\"\n";

    private TextView status;
    private LinearLayout content;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private String lastRaw = "";

    private int C_BG = Color.parseColor("#0a0e13");
    private int C_CARD = Color.parseColor("#141b23");
    private int C_LINE = Color.parseColor("#28333f");
    private int C_TXT = Color.parseColor("#e7eef6");
    private int C_MUT = Color.parseColor("#93a4b8");
    private int C_GRN = Color.parseColor("#34d399");
    private int C_RED = Color.parseColor("#f87171");
    private int C_AMB = Color.parseColor("#fbbf24");
    private int C_BLUE = Color.parseColor("#60a5fa");
    private int C_VIO = Color.parseColor("#a78bfa");

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(C_BG);
        root.setPadding(dp(14), dp(14), dp(14), dp(8));

        TextView title = new TextView(this);
        title.setText("RootScope");
        title.setTextColor(C_TXT);
        title.setTextSize(22);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        status = new TextView(this);
        status.setText("Requesting root... approve it in the manager if asked.");
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

        refresh.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { runProbe(); }
        });
        copy.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) {
                ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
                cm.setPrimaryClip(ClipData.newPlainText("report", lastRaw));
                Toast.makeText(MainActivity.this, "Copied", Toast.LENGTH_SHORT).show();
            }
        });

        runProbe();
    }

    private void runProbe() {
        content.removeAllViews();
        status.setText("Requesting root...");
        new Thread(new Runnable() {
            public void run() {
                String raw;
                try {
                    raw = exec(new String[] { "su", "-c", PROBE }, 40000L);
                } catch (Exception e) {
                    raw = "###ROOT\nERROR " + e + "\n###END\n";
                }
                final String rawF = raw;
                final Map<String, String> sec = parseSections(raw);
                ui.post(new Runnable() {
                    public void run() {
                        lastRaw = rawF;
                        renderAll(sec);
                    }
                });
            }
        }).start();
    }

    private String exec(String[] cmd, long timeoutMs) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = r.readLine()) != null) sb.append(line).append('\n');
        if (!p.waitFor(timeoutMs, TimeUnit.MILLISECONDS)) {
            p.destroyForcibly();
            sb.append("[timeout]\n");
        }
        return sb.toString();
    }

    private Map<String, String> parseSections(String raw) {
        Map<String, String> out = new LinkedHashMap<String, String>();
        String cur = null;
        StringBuilder buf = new StringBuilder();
        for (String line : raw.split("\n")) {
            if (line.startsWith("###")) {
                if (cur != null) out.put(cur, buf.toString().trim());
                String name = line.substring(3).trim();
                if (name.equals("END")) { cur = null; break; }
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
        String root = sec.get("ROOT");
        boolean rooted = root != null && root.contains("uid=0");
        status.setTextColor(rooted ? C_GRN : C_RED);
        status.setText(rooted ? "ROOT ok  ·  uid=0  ·  " + firstLine(sec.get("DEVICE")) : "ROOT NOT DETECTED");
        if (!rooted) {
            addCard("ROOT STATUS",
                t("ROOT: NOT DETECTED", C_RED, 15, true),
                t("The app could not obtain root (uid=0), so it cannot read kernel capabilities. "
                    + "Either there is no root solution, or the request was denied.", C_MUT, 12.5f, false),
                mono(root == null ? "(no output)" : root));
            return;
        }
        String info = sec.get("INFO");
        String feats = sec.get("FEATURES");
        String seccomp = sec.get("SECCOMP");
        String susfs = sec.get("SUSFS");
        String umount = sec.get("UMOUNT");
        String umountcfg = sec.get("UMOUNTCFG");
        String dyn = sec.get("DYN");
        String modules = sec.get("MODULES");
        Map<String, String> im = parseKv(info);
        String[] dev = (sec.get("DEVICE") == null ? "" : sec.get("DEVICE")).split("\n");

        LinearLayout srow = badgeRow();
        addBadge(srow, badge("ROOT", C_GRN));
        if (im.containsKey("runtime_mode")) addBadge(srow, badge(im.get("runtime_mode"), C_BLUE));
        addBadge(srow, badge("uapi " + im.getOrDefault("uapi_version", "?"), C_VIO));
        addBadge(srow, badge(countModules(modules) + " modules", C_AMB));
        addBadge(srow, badge("seccomp", (seccomp != null && seccomp.contains("allow")) ? C_GRN : C_RED));
        addBadge(srow, badge("susfs", (susfs != null && !susfs.trim().isEmpty()) ? C_GRN : C_MUT));
        addCard("SUMMARY", srow,
            kv("KSU version", im.getOrDefault("version", "?")),
            kv("full version", im.getOrDefault("full_version", "?")),
            kv("device", (dev.length > 0 ? dev[0] : "?") + "  ·  Android " + (dev.length > 2 ? dev[2] : "?")));

        renderFeatures(feats);
        renderModules(modules);
        renderInfo(im);
        renderSeccomp(seccomp);
        renderSusfs(susfs);
        renderLists(umount, umountcfg, dyn);
    }

    private void renderFeatures(String feats) {
        if (feats == null) return;
        String[] lines = feats.split("\n");
        LinearLayout c = card();
        c.addView(t("FEATURES", C_BLUE, 13, true));
        for (int i = 0; i < lines.length; i++) {
            String ln = lines[i].trim();
            if (!ln.startsWith("[")) continue;
            int e = ln.indexOf(']');
            if (e < 0) continue;
            String stat = ln.substring(1, e);
            String rest = ln.substring(e + 1).trim();
            boolean managed = rest.contains("MODULE_MANAGED");
            String name = rest, id = "";
            int p = rest.indexOf("(ID=");
            if (p >= 0) {
                name = rest.substring(0, p).trim();
                int q = rest.indexOf(')', p);
                if (q > 0) id = rest.substring(p + 4, q);
            }
            int col = stat.startsWith("ENABLED") ? C_GRN : (stat.startsWith("DISABLED") ? C_MUT : C_RED);
            LinearLayout row = new LinearLayout(this);
            row.setOrientation(LinearLayout.HORIZONTAL);
            row.setPadding(0, dp(5), 0, dp(2));
            TextView nn = t(name, C_TXT, 13, true);
            nn.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.6f));
            TextView ss = t(stat + (managed ? "  ·mod" : ""), col, 11.5f, true);
            ss.setGravity(Gravity.END);
            ss.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 0.4f));
            row.addView(nn);
            row.addView(ss);
            c.addView(row);
            if (i + 1 < lines.length) {
                String d = lines[i + 1].trim();
                if (!d.startsWith("[")) c.addView(t(d, C_MUT, 11, false));
            }
        }
        content.addView(c);
    }

    private void renderModules(String json) {
        LinearLayout c = card();
        c.addView(t("MODULES", C_BLUE, 13, true));
        String s = json == null ? "" : json.trim();
        if (s.isEmpty()) {
            c.addView(t("none", C_MUT, 12, false));
            content.addView(c);
            return;
        }
        if (!s.startsWith("[")) {
            c.addView(t("could not read module list", C_RED, 12, false));
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
                m.addView(t((ver.isEmpty() ? "" : "v" + ver) + (au.isEmpty() ? "" : "   ·   " + au),
                    C_VIO, 11.5f, false));
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

                String mf = o.optString("managedFeatures", "");
                if (!mf.isEmpty()) m.addView(t("manages: " + mf, C_AMB, 11, false));
                c.addView(m);
            }
        } catch (Exception e) {
            c.addView(t("parse error: " + e.getMessage(), C_RED, 12, false));
            c.addView(mono(s));
        }
        content.addView(c);
    }

    private void renderInfo(Map<String, String> im) {
        LinearLayout c = card();
        c.addView(t("KERNEL INFO", C_BLUE, 13, true));
        c.addView(kv("version", im.getOrDefault("version", "?")));
        c.addView(kv("full version", im.getOrDefault("full_version", "?")));
        c.addView(kv("uapi version", im.getOrDefault("uapi_version", "?")));
        c.addView(kv("runtime mode", im.getOrDefault("runtime_mode", "?")));
        c.addView(kv("lkm", im.getOrDefault("lkm", "?")));
        c.addView(kv("bundled", im.getOrDefault("bundled", "?")));
        c.addView(kv("late load", im.getOrDefault("late_load", "?")));
        c.addView(kv("pr build", im.getOrDefault("pr_build", "?")));
        c.addView(kv("features(max)", im.getOrDefault("features", "?") + "   (count, not a mask)"));
        String fl = im.get("flags");
        if (fl != null) {
            int f = parseInt(fl.replace("0x", ""), 16);
            StringBuilder sb = new StringBuilder();
            if ((f & 1) != 0) sb.append("LKM ");
            if ((f & 2) != 0) sb.append("MANAGER ");
            if ((f & 4) != 0) sb.append("LATE_LOAD ");
            if ((f & 8) != 0) sb.append("PR_BUILD ");
            if ((f & 16) != 0) sb.append("BUNDLED ");
            if (sb.length() == 0) sb.append("none set (from a root shell this is normal)");
            c.addView(kv("flags decoded", fl + " -> " + sb.toString().trim()));
        }
        content.addView(c);
    }

    private void renderSeccomp(String seccomp) {
        LinearLayout c = card();
        c.addView(t("SECCOMP", C_BLUE, 13, true));
        boolean ok = seccomp != null && seccomp.contains("allow");
        c.addView(t(ok ? "filter fully supported" : "not available", ok ? C_GRN : C_RED, 12.5f, true));
        if (seccomp != null) {
            LinearLayout br = badgeRow();
            for (String a : seccomp.trim().split("\\s+")) if (!a.isEmpty()) addBadge(br, badge(a, C_VIO));
            c.addView(br);
        }
        content.addView(c);
    }

    private void renderSusfs(String susfs) {
        LinearLayout c = card();
        c.addView(t("SUSFS", C_BLUE, 13, true));
        if (susfs == null || susfs.trim().isEmpty()) {
            c.addView(t("not present", C_MUT, 12, false));
            content.addView(c);
            return;
        }
        String[] lines = susfs.trim().split("\n");
        c.addView(kv("variant", lines[0].trim()));
        LinearLayout br = badgeRow();
        for (int i = 1; i < lines.length; i++) {
            String f = lines[i].trim();
            if (f.isEmpty()) continue;
            String shortName = f.replace("CONFIG_KSU_SUSFS_", "");
            addBadge(br, badge(shortName, C_GRN));
        }
        c.addView(br);
        content.addView(c);
    }

    private void renderLists(String umount, String umountcfg, String dyn) {
        LinearLayout c = card();
        c.addView(t("KERNEL LISTS", C_BLUE, 13, true));
        c.addView(t("umount list", C_MUT, 11.5f, true));
        c.addView(mono(blank(umount)));
        c.addView(t("auto-umount config", C_MUT, 11.5f, true));
        c.addView(mono(blank(umountcfg)));
        c.addView(t("dynamic manager", C_MUT, 11.5f, true));
        c.addView(mono(blank(dyn)));
        content.addView(c);
    }

    private String blank(String s) {
        return (s == null || s.trim().isEmpty()) ? "(empty)" : s.trim();
    }

    private int countModules(String json) {
        if (json == null) return 0;
        try {
            String s = json.trim();
            if (!s.startsWith("[")) return 0;
            return new JSONArray(s).length();
        } catch (Exception e) {
            return 0;
        }
    }

    private Map<String, String> parseKv(String s) {
        Map<String, String> m = new LinkedHashMap<String, String>();
        if (s == null) return m;
        for (String line : s.split("\n")) {
            int i = line.indexOf(':');
            if (i > 0) m.put(line.substring(0, i).trim(), line.substring(i + 1).trim());
        }
        return m;
    }

    private String firstLine(String s) {
        if (s == null) return "";
        int i = s.indexOf('\n');
        return (i < 0 ? s : s.substring(0, i)).trim();
    }

    private int parseInt(String s, int radix) {
        try { return Integer.parseInt(s.trim(), radix); } catch (Exception e) { return 0; }
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

    private int alpha(int color, int a) {
        return Color.argb(a, Color.red(color), Color.green(color), Color.blue(color));
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

    private int dp(int x) {
        return Math.round(getResources().getDisplayMetrics().density * x);
    }
}
