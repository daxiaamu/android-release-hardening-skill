package com.daxiaamu.protector;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Process;
import android.view.Gravity;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

public final class GatewayActivity extends Activity {
    private final Handler repair = new Handler(Looper.getMainLooper());
    private AlertDialog dialog;
    private boolean exiting;
    private boolean handoffStarted;
    private boolean handoffPaused;
    private boolean splashReleaseRequested;
    private Object retainedSplashView;

    private final Runnable repairFailureSurface = new Runnable() {
        @Override public void run() {
            if (!exiting && !StubApplication.isIntegrityReady()) {
                if (dialog == null || !dialog.isShowing()) showFailureDialog();
                repair.postDelayed(this, 700L);
            }
        }
    };

    @Override protected void onCreate(Bundle state) {
        retainSystemSplash();
        super.onCreate(state);
        if (StubApplication.validateNow(this)) {
            launchOriginal();
            return;
        }
        releaseSystemSplash();
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        buildFallbackSurface();
        showFailureDialog();
        repair.postDelayed(repairFailureSurface, 700L);
    }

    @Override protected void onResume() {
        super.onResume();
        if (handoffStarted && handoffPaused) {
            releaseSystemSplash();
            finish();
            overridePendingTransition(0, 0);
            return;
        }
        if (!exiting && !StubApplication.isIntegrityReady() && (dialog == null || !dialog.isShowing())) {
            showFailureDialog();
        }
    }

    @Override protected void onPause() {
        if (handoffStarted) handoffPaused = true;
        super.onPause();
    }

    @Override protected void onStop() {
        super.onStop();
        // Keep the gateway (and its Android 12+ splash window) alive until the
        // original launcher has actually covered it. Finishing immediately after
        // startActivity() can expose the desktop while the business Activity starts.
        if (handoffStarted && !isFinishing()) {
            releaseSystemSplash();
            finish();
            overridePendingTransition(0, 0);
        }
    }

    @Override public void onBackPressed() { /* Deliberately blocked on the failure surface. */ }

    private void launchOriginal() {
        try {
            String launcher = StubApplication.originalLauncher(this);
            Intent source = getIntent();
            // Preserve launcher/deep-link semantics in full: data URI, MIME type,
            // categories, flags, ClipData, selector, bounds and extras.
            Intent target = source == null ? new Intent(Intent.ACTION_MAIN) : new Intent(source);
            target.setClassName(getPackageName(), launcher);
            // Desktop launchers add task-routing flags for the exported root. Keeping
            // them on the internal handoff can make ActivityTaskManager deliver the
            // request back to this task's current top (the gateway) instead of
            // creating the original Activity. Preserve payload/grant flags but
            // translate root-task routing into an in-task Activity transition.
            int rootTaskFlags = Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_RESET_TASK_IF_NEEDED
                    | Intent.FLAG_ACTIVITY_NEW_DOCUMENT
                    | Intent.FLAG_ACTIVITY_MULTIPLE_TASK
                    | Intent.FLAG_ACTIVITY_TASK_ON_HOME;
            target.setFlags(target.getFlags() & ~rootTaskFlags);
            handoffStarted = true;
            startActivity(target);
            overridePendingTransition(0, 0);
        } catch (Throwable ignored) {
            handoffStarted = false;
            releaseSystemSplash();
            StubApplication.revokeIntegrity();
            buildFallbackSurface();
            showFailureDialog();
            repair.postDelayed(repairFailureSurface, 700L);
        }
    }

    private void retainSystemSplash() {
        if (android.os.Build.VERSION.SDK_INT < 31) return;
        try {
            final Class<?> listenerType = Class.forName("android.window.SplashScreen$OnExitAnimationListener");
            Object listener = Proxy.newProxyInstance(listenerType.getClassLoader(), new Class<?>[] { listenerType },
                    new InvocationHandler() {
                        @Override public Object invoke(Object proxy, Method method, Object[] args) {
                            if ("onSplashScreenExit".equals(method.getName()) && args != null && args.length == 1) {
                                retainedSplashView = args[0];
                                if (splashReleaseRequested) removeRetainedSplash();
                            }
                            return null;
                        }
                    });
            Object splash = Activity.class.getMethod("getSplashScreen").invoke(this);
            Class<?> splashType = Class.forName("android.window.SplashScreen");
            splashType.getMethod("setOnExitAnimationListener", listenerType).invoke(splash, listener);
        } catch (Throwable ignored) {
            // Theme inheritance still provides the platform fallback on devices
            // where the public API is absent or vendor-modified.
        }
    }

    private void releaseSystemSplash() {
        splashReleaseRequested = true;
        removeRetainedSplash();
    }

    private void removeRetainedSplash() {
        Object view = retainedSplashView;
        retainedSplashView = null;
        if (view == null) return;
        try {
            Class.forName("android.window.SplashScreenView").getMethod("remove").invoke(view);
        } catch (Throwable ignored) { }
    }

    private void buildFallbackSurface() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setGravity(Gravity.CENTER);
        root.setPadding(72, 72, 72, 72);
        root.setBackgroundColor(Color.rgb(28, 20, 24));
        TextView message = new TextView(this);
        message.setText("应用完整性验证失败\n错误代码：" + BuildProfile.FAILURE_CODE);
        message.setTextColor(Color.WHITE);
        message.setTextSize(20f);
        message.setGravity(Gravity.CENTER);
        Button exit = new Button(this);
        exit.setText("退出");
        exit.setOnClickListener(new View.OnClickListener() { @Override public void onClick(View v) { exitApp(); } });
        root.addView(message, new LinearLayout.LayoutParams(-1, -2));
        LinearLayout.LayoutParams button = new LinearLayout.LayoutParams(-1, -2);
        button.topMargin = 48;
        root.addView(exit, button);
        setContentView(root);
    }

    private void showFailureDialog() {
        if (isFinishing() || exiting) return;
        dialog = new AlertDialog.Builder(this)
                .setTitle("安全验证失败")
                .setMessage("检测到应用文件或签名异常。为保护数据，本次无法继续运行。\n\n错误代码：" + BuildProfile.FAILURE_CODE)
                .setCancelable(false)
                .setPositiveButton("退出", new DialogInterface.OnClickListener() {
                    @Override public void onClick(DialogInterface d, int which) { exitApp(); }
                }).create();
        dialog.setCanceledOnTouchOutside(false);
        dialog.setOnKeyListener(new DialogInterface.OnKeyListener() {
            @Override public boolean onKey(DialogInterface d, int keyCode, android.view.KeyEvent event) { return true; }
        });
        dialog.show();
    }

    private void exitApp() {
        exiting = true;
        repair.removeCallbacksAndMessages(null);
        if (dialog != null) dialog.dismiss();
        finishAndRemoveTask();
        Process.killProcess(Process.myPid());
    }
}
