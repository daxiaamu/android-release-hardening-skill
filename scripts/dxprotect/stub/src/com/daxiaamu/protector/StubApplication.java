package com.daxiaamu.protector;

import android.app.Application;
import android.app.Activity;
import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageInfo;
import android.content.pm.Signature;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.content.Intent;

import dalvik.system.DexClassLoader;
import dalvik.system.InMemoryDexClassLoader;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.MessageDigest;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public final class StubApplication extends Application {
    private static volatile boolean integrityReady;
    private static volatile StubApplication instance;
    private Application delegated;
    private byte[] signerSha256;
    private byte[] capability;
    private String apkPath;
    private String enginePath;
    private String anchorPath;
    private final Handler watchdog = new Handler(Looper.getMainLooper());
    private final Runnable watchdogCheck = new Runnable() {
        @Override public void run() {
            if (!integrityReady) return;
            try {
                byte[] fresh = AnchorBridge.__DXP_ATTEST_METHOD__(signerSha256, enginePath, anchorPath);
                if (fresh == null || !NativeBridge.__DXP_RECHECK_METHOD__(signerSha256, apkPath, enginePath, anchorPath, fresh)) {
                    throw new SecurityException("watchdog verification failed");
                }
                if (capability != null) Arrays.fill(capability, (byte) 0);
                capability = fresh;
                watchdog.postDelayed(this, BuildProfile.WATCHDOG_MS);
            } catch (Throwable failure) {
                routeFailure();
            }
        }
    };

    @Override
    protected void attachBaseContext(Context base) {
        super.attachBaseContext(base);
        instance = this;
        try {
            ClassLoader loader = installPayload(base);
            delegated = createOriginalApplication(base, loader);
            if (delegated != null) publishOriginalApplication(base, delegated);
            integrityReady = true;
        } catch (Throwable failure) {
            integrityReady = false;
        }
    }

    @Override
    public void onCreate() {
        super.onCreate();
        if (delegated != null) {
            try {
                publishOriginalApplication(getBaseContext(), delegated);
            } catch (Throwable failure) {
                integrityReady = false;
                routeFailure();
                return;
            }
            delegated.onCreate();
        }
        if (integrityReady) {
            Application lifecycleOwner = delegated == null ? this : delegated;
            lifecycleOwner.registerActivityLifecycleCallbacks(new ActivityLifecycleCallbacks() {
                @Override public void onActivityResumed(Activity activity) {
                    if (activity instanceof GatewayActivity) return;
                    if (!validateNow(activity)) routeFailure();
                }
                @Override public void onActivityCreated(Activity a, Bundle b) {}
                @Override public void onActivityStarted(Activity a) {}
                @Override public void onActivityPaused(Activity a) {}
                @Override public void onActivityStopped(Activity a) {}
                @Override public void onActivitySaveInstanceState(Activity a, Bundle b) {}
                @Override public void onActivityDestroyed(Activity a) {}
            });
            watchdog.postDelayed(watchdogCheck, BuildProfile.WATCHDOG_MS);
        }
    }

    private void routeFailure() {
        integrityReady = false;
        Intent intent = new Intent(this, GatewayActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
        startActivity(intent);
    }

    private ClassLoader installPayload(Context context) throws Exception {
        signerSha256 = currentSignerSha256(context);
        ApplicationInfo info = context.getApplicationInfo();
        apkPath = info.sourceDir;
        enginePath = new File(info.nativeLibraryDir, "lib" + BuildProfile.SO_NAME + ".so").getAbsolutePath();
        anchorPath = new File(info.nativeLibraryDir, "lib" + BuildProfile.ANCHOR_SO_NAME + ".so").getAbsolutePath();
        capability = AnchorBridge.__DXP_ATTEST_METHOD__(signerSha256, enginePath, anchorPath);
        if (capability == null || capability.length != 48) throw new SecurityException("anchor attestation failed");
        Bundle metadata = info.metaData;
        String buildId = metadata == null ? "unknown" : metadata.getString(BuildProfile.META_BUILD_ID, "unknown");
        String[] assets = context.getAssets().list(BuildProfile.ASSET_DIR);
        if (assets == null || assets.length == 0) {
            throw new IllegalStateException("encrypted DEX assets are missing");
        }
        Arrays.sort(assets);

        if (Build.VERSION.SDK_INT >= 27) {
            List<ByteBuffer> buffers = new ArrayList<ByteBuffer>();
            for (String asset : assets) {
                if (!asset.endsWith(".bin")) continue;
                byte[] clear = decryptAsset(context, asset);
                ByteBuffer buffer = ByteBuffer.allocateDirect(clear.length);
                buffer.put(clear);
                buffer.flip();
                buffers.add(buffer.asReadOnlyBuffer());
                Arrays.fill(clear, (byte) 0);
            }
            if (buffers.isEmpty()) throw new IllegalStateException("no DEX payload found");
            ClassLoader loader = new InMemoryDexClassLoader(
                    buffers.toArray(new ByteBuffer[buffers.size()]),
                    info.nativeLibraryDir,
                    context.getClassLoader());
            publishClassLoader(context, loader);
            return loader;
        }

        File root = new File(context.getCodeCacheDir(), "dxp-" + safe(buildId));
        if (!root.exists() && !root.mkdirs()) {
            throw new IllegalStateException("cannot create payload directory");
        }
        StringBuilder dexPath = new StringBuilder();
        for (String asset : assets) {
            if (!asset.endsWith(".bin")) continue;
            byte[] clear = decryptAsset(context, asset);
            File dex = new File(root, asset.substring(0, asset.length() - 4) + ".dex");
            File temp = new File(root, dex.getName() + ".tmp");
            FileOutputStream output = new FileOutputStream(temp, false);
            try {
                output.write(clear);
                output.getFD().sync();
            } finally {
                output.close();
                Arrays.fill(clear, (byte) 0);
            }
            if (dex.exists() && !dex.delete()) throw new IllegalStateException("cannot replace DEX");
            if (!temp.setReadOnly()) throw new IllegalStateException("cannot seal DEX permissions");
            if (!temp.renameTo(dex)) throw new IllegalStateException("cannot publish DEX");
            if (dexPath.length() > 0) dexPath.append(File.pathSeparatorChar);
            dexPath.append(dex.getAbsolutePath());
        }
        if (dexPath.length() == 0) throw new IllegalStateException("no DEX payload found");

        ClassLoader parent = context.getClassLoader();
        DexClassLoader loader = new DexClassLoader(
                dexPath.toString(), root.getAbsolutePath(), info.nativeLibraryDir, parent);
        publishClassLoader(context, loader);
        return loader;
    }

    private void publishClassLoader(Context context, ClassLoader loader) throws Exception {
        Object loadedApk = field(context.getClass(), "mPackageInfo").get(context);
        Field classLoader = field(loadedApk.getClass(), "mClassLoader");
        classLoader.set(loadedApk, loader);
        Thread.currentThread().setContextClassLoader(loader);
    }

    private byte[] decryptAsset(Context context, String asset) throws Exception {
        byte[] sealed = readAll(context, BuildProfile.ASSET_DIR + "/" + asset);
        ApplicationInfo info = context.getApplicationInfo();
        byte[] clear = NativeBridge.__DXP_DECRYPT_METHOD__(sealed, signerSha256, info.sourceDir,
                enginePath, anchorPath, capability);
        Arrays.fill(sealed, (byte) 0);
        if (clear == null || clear.length < 112 || clear[0] != 'd' || clear[1] != 'e' || clear[2] != 'x') {
            throw new SecurityException("payload authentication failed: " + asset);
        }
        return clear;
    }

    private Application createOriginalApplication(Context base, ClassLoader loader) throws Exception {
        ApplicationInfo info = base.getPackageManager().getApplicationInfo(
                base.getPackageName(), PackageManager.GET_META_DATA);
        String name = info.metaData == null ? null : info.metaData.getString(BuildProfile.META_ORIGINAL_APP);
        if (name == null || name.length() == 0 || "android.app.Application".equals(name)) return null;
        Object value = loader.loadClass(name).newInstance();
        if (!(value instanceof Application)) throw new IllegalStateException("original Application type mismatch");
        Application app = (Application) value;
        Method attach = Application.class.getDeclaredMethod("attach", Context.class);
        attach.setAccessible(true);
        attach.invoke(app, base);
        return app;
    }

    private void publishOriginalApplication(Context base, Application app) throws Exception {
        Object loadedApk = field(base.getClass(), "mPackageInfo").get(base);
        field(loadedApk.getClass(), "mApplication").set(loadedApk, app);
        try {
            Method setOuter = base.getClass().getDeclaredMethod("setOuterContext", Context.class);
            setOuter.setAccessible(true);
            setOuter.invoke(base, app);
        } catch (NoSuchMethodException ignored) {
            field(base.getClass(), "mOuterContext").set(base, app);
        }
        Class<?> activityThreadClass = Class.forName("android.app.ActivityThread");
        Method current = activityThreadClass.getDeclaredMethod("currentActivityThread");
        current.setAccessible(true);
        Object activityThread = current.invoke(null);
        if (activityThread == null) throw new IllegalStateException("ActivityThread unavailable");
        Field initial = field(activityThreadClass, "mInitialApplication");
        if (initial.get(activityThread) == this) initial.set(activityThread, app);
        Object all = field(activityThreadClass, "mAllApplications").get(activityThread);
        if (all instanceof List) {
            @SuppressWarnings("unchecked") List<Application> applications = (List<Application>) all;
            synchronized (applications) {
                while (applications.remove(this)) { /* remove the framework stub identity */ }
                while (applications.lastIndexOf(app) != applications.indexOf(app)) {
                    applications.remove(applications.lastIndexOf(app));
                }
                if (!applications.contains(app)) applications.add(app);
            }
        }
    }

    static void completeApplicationSwap(Context context) {
        StubApplication app = instance;
        if (app == null || app.delegated == null || !integrityReady) return;
        try {
            app.publishOriginalApplication(app.getBaseContext(), app.delegated);
        } catch (Throwable failure) {
            integrityReady = false;
        }
    }

    static boolean isIntegrityReady() { return integrityReady; }

    static boolean validateNow(Context context) {
        if (!integrityReady) return false;
        StubApplication app = instance;
        if (app == null) return false;
        try {
            byte[] fresh = AnchorBridge.__DXP_ATTEST_METHOD__(app.signerSha256, app.enginePath, app.anchorPath);
            if (fresh == null || !NativeBridge.__DXP_RECHECK_METHOD__(app.signerSha256, app.apkPath, app.enginePath, app.anchorPath, fresh)) return false;
            if (app.capability != null) Arrays.fill(app.capability, (byte) 0);
            app.capability = fresh;
            return true;
        } catch (Throwable ignored) { return false; }
    }

    static void revokeIntegrity() { integrityReady = false; }

    static String originalLauncher(Context context) throws Exception {
        ApplicationInfo info = context.getPackageManager().getApplicationInfo(context.getPackageName(), PackageManager.GET_META_DATA);
        String value = info.metaData == null ? null : info.metaData.getString(BuildProfile.META_LAUNCHER);
        if (value == null || value.length() == 0) throw new SecurityException("original launcher missing");
        return value;
    }

    private static byte[] readAll(Context context, String path) throws Exception {
        InputStream input = context.getAssets().open(path);
        try {
            byte[] buffer = new byte[8192];
            int size = 0;
            byte[] output = new byte[16384];
            for (;;) {
                int count = input.read(buffer);
                if (count < 0) break;
                if (size + count > output.length) output = Arrays.copyOf(output, Math.max(output.length * 2, size + count));
                System.arraycopy(buffer, 0, output, size, count);
                size += count;
            }
            return Arrays.copyOf(output, size);
        } finally {
            input.close();
        }
    }

    private static Field field(Class<?> type, String name) throws NoSuchFieldException {
        Class<?> current = type;
        while (current != null) {
            try {
                Field result = current.getDeclaredField(name);
                result.setAccessible(true);
                return result;
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static String safe(String value) {
        return value.replaceAll("[^A-Za-z0-9_.-]", "_");
    }

    @SuppressWarnings("deprecation")
    private static byte[] currentSignerSha256(Context context) throws Exception {
        PackageManager manager = context.getPackageManager();
        Signature[] signers;
        if (Build.VERSION.SDK_INT >= 28) {
            PackageInfo info = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNING_CERTIFICATES);
            if (info.signingInfo == null || info.signingInfo.hasMultipleSigners()) {
                throw new SecurityException("unsupported signer set");
            }
            signers = info.signingInfo.getApkContentsSigners();
        } else {
            PackageInfo info = manager.getPackageInfo(context.getPackageName(), PackageManager.GET_SIGNATURES);
            signers = info.signatures;
        }
        if (signers == null || signers.length != 1) throw new SecurityException("single signer required");
        return MessageDigest.getInstance("SHA-256").digest(signers[0].toByteArray());
    }
}
