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

public final class GatewayActivity extends Activity {
    private final Handler repair = new Handler(Looper.getMainLooper());
    private AlertDialog dialog;
    private boolean exiting;

    private final Runnable repairFailureSurface = new Runnable() {
        @Override public void run() {
            if (!exiting && !StubApplication.isIntegrityReady()) {
                if (dialog == null || !dialog.isShowing()) showFailureDialog();
                repair.postDelayed(this, 700L);
            }
        }
    };

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        if (StubApplication.validateNow(this)) {
            launchOriginal();
            return;
        }
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        buildFallbackSurface();
        showFailureDialog();
        repair.postDelayed(repairFailureSurface, 700L);
    }

    @Override protected void onResume() {
        super.onResume();
        if (!exiting && !StubApplication.isIntegrityReady() && (dialog == null || !dialog.isShowing())) {
            showFailureDialog();
        }
    }

    @Override public void onBackPressed() { /* Deliberately blocked on the failure surface. */ }

    private void launchOriginal() {
        try {
            String launcher = StubApplication.originalLauncher(this);
            Intent source = getIntent();
            Intent target = new Intent(source == null ? Intent.ACTION_MAIN : source.getAction());
            if (source != null && source.getExtras() != null) target.putExtras(source.getExtras());
            target.setClassName(getPackageName(), launcher);
            startActivity(target);
            finish();
        } catch (Throwable ignored) {
            StubApplication.revokeIntegrity();
            buildFallbackSurface();
            showFailureDialog();
            repair.postDelayed(repairFailureSurface, 700L);
        }
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
