package com.octopus.capdetect;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.Typeface;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.TimeUnit;

/**
 * Capability Detector: reads every KernelSU / ReSukiSU capability the kernel
 * reports to its manager. If it cannot obtain root, it says so plainly.
 */
public class MainActivity extends Activity {

    // One combined probe. Requires root (su). ksud lives at /data/adb/ksud.
    private static final String CMD =
        "K=/data/adb/ksud; " +
        "echo \"=== ROOT ===\"; id; " +
        "echo \"=== KERNEL VERSION ===\"; $K debug version; " +
        "echo \"=== KSU INFO ===\"; $K debug info; " +
        "echo \"=== FEATURES ===\"; $K feature list; " +
        "echo \"=== SECCOMP ===\"; cat /proc/sys/kernel/seccomp/actions_avail; " +
        "echo \"=== SUSFS ===\"; $K susfs show variant; $K susfs show enabled_features; " +
        "echo \"=== DYNAMIC MANAGER ===\"; $K kernel dynamic-manager get; " +
        "echo \"=== END ===\"";

    private TextView out;
    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setBackgroundColor(Color.parseColor("#0b0f14"));
        root.setPadding(dp(16), dp(16), dp(16), dp(16));

        TextView title = new TextView(this);
        title.setText("Capability Detector");
        title.setTextColor(Color.parseColor("#e7eef6"));
        title.setTextSize(20);
        title.setTypeface(Typeface.DEFAULT_BOLD);
        root.addView(title);

        TextView sub = new TextView(this);
        sub.setText("Reads all KernelSU / ReSukiSU capabilities the kernel reports to its manager.");
        sub.setTextColor(Color.parseColor("#94a3b8"));
        sub.setTextSize(12);
        sub.setPadding(0, dp(4), 0, dp(12));
        root.addView(sub);

        Button run = new Button(this);
        run.setText("Run detection");
        root.addView(run);

        ScrollView sc = new ScrollView(this);
        out = new TextView(this);
        out.setTextColor(Color.parseColor("#34d399"));
        out.setTextSize(12);
        out.setTypeface(Typeface.MONOSPACE);
        out.setTextIsSelectable(true);
        out.setPadding(0, dp(12), 0, 0);
        sc.addView(out);
        root.addView(sc, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f));

        setContentView(root);

        run.setOnClickListener(new View.OnClickListener() {
            public void onClick(View v) { detect(); }
        });

        detect();
    }

    private void detect() {
        out.setText("Requesting root and probing capabilities...\n"
                + "(tap Allow if the superuser manager asks)");
        new Thread(new Runnable() {
            public void run() { runProbe(); }
        }).start();
    }

    private void runProbe() {
        String text;
        try {
            String res = exec(new String[] { "su", "-c", CMD }, 30000L);
            if (res.trim().isEmpty() || res.indexOf("uid=0") < 0) {
                text = "ROOT: NOT DETECTED\n\n"
                        + "The app could not obtain root (uid=0), so it cannot read the kernel's\n"
                        + "capabilities. Either there is no root solution, or the request was denied.\n\n"
                        + "----- raw output -----\n" + res.trim();
            } else {
                text = res.trim();
            }
        } catch (Exception e) {
            text = "ROOT: NOT DETECTED\n\nThe app could not run 'su' at all.\n\n" + e;
        }
        final String finalText = text;
        ui.post(new Runnable() {
            public void run() { out.setText(finalText); }
        });
    }

    private String exec(String[] cmd, long timeoutMs) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();

        StringBuilder sb = new StringBuilder();
        BufferedReader r = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line;
        while ((line = r.readLine()) != null) {
            sb.append(line).append('\n');
        }
        boolean done = p.waitFor(timeoutMs, TimeUnit.MILLISECONDS);
        if (!done) {
            p.destroyForcibly();
            sb.append("\n[timeout waiting for su output]\n");
        }
        return sb.toString();
    }

    private int dp(int x) {
        return Math.round(getResources().getDisplayMetrics().density * x);
    }
}
