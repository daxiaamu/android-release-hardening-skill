"""Build unrelated apps and optionally verify their real resource reads on a selected device.

Explicit integration test: requires Android SDK/NDK, JDK, and apktool.
Generates its own test-only key; never uses a project or release signing key.
"""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1]

def run(args, log, env=None, allowed=(0,)):
    result = subprocess.run([str(x) for x in args], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, env=env)
    with log.open("ab") as output:
        output.write(result.stdout)
    if result.returncode not in allowed:
        raise RuntimeError("Integration command failed; see " + str(log))
    return result.stdout.decode("utf-8", "replace")

JAVA_SOURCE = r"""
package __PACKAGE__;
import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;
import java.lang.reflect.*;
import java.security.MessageDigest;
import java.util.Arrays;
public final class MainActivity extends Activity {
    __NATIVE_DECL__
    private static String digest(byte[] bytes) throws Exception {
        StringBuilder result=new StringBuilder();
        for(byte n:MessageDigest.getInstance("SHA-256").digest(bytes))
            result.append(String.format("%02x",n&255));
        return result.toString();
    }
    @Override public void onCreate(Bundle b) {
        super.onCreate(b);
        TextView view=new TextView(this);
        try {
            if(!(getApplication() instanceof OriginalApp)||!OriginalApp.ready)
                throw new SecurityException("Application not restored");
            __NATIVE_CHECK__
            if (__ENABLED__) {
                Class<?> facade=Class.forName("com.daxiaamu.shellbinding.OuterShare",true,getClassLoader());
                Method read=facade.getMethod("resource",String.class);
                String[][] expected=__EXPECTED__;
                for(String[] item:expected) {
                    byte[] bytes=(byte[])read.invoke(null,item[0]);
                    try {
                        if(!digest(bytes).equals(item[1]))throw new SecurityException("content mismatch");
                    } finally {Arrays.fill(bytes,(byte)0);}
                }
                boolean rejected=false;
                try {read.invoke(null,"missing/resource");}
                catch(InvocationTargetException error){rejected=error.getCause() instanceof SecurityException;}
                if(!rejected)throw new SecurityException("missing resource accepted");
            }
            view.setText("RESOURCE_MATRIX_PASS __PACKAGE__");
        } catch(Throwable error){view.setText("RESOURCE_MATRIX_FAIL "+error.getClass().getName());}
        setContentView(view);
    }
}
"""

def build_case(args, work, package, native, enabled, key, env):
    folder=work/package
    folder.mkdir()
    log=folder/"build.log"
    sdk=args.android_sdk
    suffix=".exe" if os.name=="nt" else ""
    bt=sdk/"build-tools"/args.build_tools
    platform=sdk/"platforms"/"android-30"/"android.jar"
    javac=args.java_home/"bin"/("javac"+suffix)
    jar=args.java_home/"bin"/("jar"+suffix)
    aapt=bt/("aapt"+suffix)
    source=folder/"src"; source.mkdir()
    classes=folder/"classes"; classes.mkdir()
    dex=folder/"dex"; dex.mkdir()
    (source/"OriginalApp.java").write_text(
        "package "+package+"; public final class OriginalApp extends android.app.Application {"
        "public static boolean ready; public void onCreate(){super.onCreate();ready=true;}}",encoding="utf-8")
    samples={
        "model/weights":("assets/models/weights.dat", bytes(range(256))*3),
        "configuration":("assets/config/rules.json",json.dumps({"project":package}).encode()),
        "page/index":("assets/pages/index.html",("<h1>"+package+"</h1>").encode()),
        "document/text":("assets/docs/示例 with spaces.txt","Portable text: 示例".encode()),
        "document/empty":("assets/docs/empty.txt",b""),
        "root/template":("templates/root.txt",b"root template"),
    }
    expected="new String[][]{"+",".join("{"+json.dumps(k)+","+json.dumps(hashlib.sha256(v[1]).hexdigest())+"}" for k,v in samples.items())+"}"
    java=JAVA_SOURCE.replace("__PACKAGE__",package).replace("__EXPECTED__",expected)
    java=java.replace("__ENABLED__","true" if enabled else "false")
    java=java.replace("__NATIVE_DECL__","private static native int value();" if native else "")
    java=java.replace("__NATIVE_CHECK__", 'System.loadLibrary("matrixjni");if(value()!=42)throw new SecurityException("JNI");' if native else "")
    (source/"MainActivity.java").write_text(java,encoding="utf-8")
    manifest=folder/"AndroidManifest.xml"
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="'+package+'" android:versionCode="1" android:versionName="1">'
        '<uses-sdk android:minSdkVersion="23" android:targetSdkVersion="30"/><application android:name=".OriginalApp" android:label="Resource matrix">'
        '<activity android:name=".MainActivity" android:exported="true"><intent-filter><action android:name="android.intent.action.MAIN"/>'
        '<category android:name="android.intent.category.LAUNCHER"/></intent-filter></activity></application></manifest>',encoding="utf-8")
    resources=folder/"res/values";resources.mkdir(parents=True)
    (resources/"strings.xml").write_text('<resources><string name="app_name">Resource matrix</string></resources>',encoding="utf-8")
    base=folder/"base.apk"
    run([aapt,"package","-f","-M",manifest,"-S",folder/"res","-I",platform,"-F",base],log)
    run([javac,"-encoding","UTF-8","-source","8","-target","8","-bootclasspath",platform,"-d",classes,*source.glob("*.java")],log)
    classes_jar=folder/"classes.jar"
    run([jar,"--create","--file",classes_jar,"-C",classes,"."],log)
    java_exe=args.java_home/"bin"/("java"+suffix)
    run([java_exe,"-cp",bt/"lib/d8.jar","com.android.tools.r8.D8","--release","--min-api","23","--lib",platform,"--output",dex,classes_jar],log,env)
    so=None
    if native:
        c=folder/"jni.c"
        c.write_text("int Java_"+package.replace(".","_")+"_MainActivity_value(void* e,void* c){return 42;}",encoding="ascii")
        so=folder/"libmatrixjni.so"
        ndk_bin=args.ndk/"toolchains/llvm/prebuilt"/("windows-x86_64" if os.name=="nt" else "linux-x86_64")/"bin"
        compiler=ndk_bin/("aarch64-linux-android23-clang.cmd" if os.name=="nt" else "aarch64-linux-android23-clang")
        run([compiler,"-shared","-fPIC","-O2","-Wl,--strip-all","-o",so,c],log)
    input_apk=folder/"input.apk"
    with zipfile.ZipFile(base) as archive, zipfile.ZipFile(input_apk,"w",compression=zipfile.ZIP_DEFLATED) as output:
        for info in archive.infolist():output.writestr(info,archive.read(info))
        output.writestr("classes.dex",(dex/"classes.dex").read_bytes())
        for entry,data in samples.values():output.writestr(entry,data)
        output.writestr("assets/public/notice.txt",b"unselected")
        if so:output.writestr("lib/arm64-v8a/libmatrixjni.so",so.read_bytes())
    selection=folder/"resources.json"
    selection.write_text(json.dumps({"schema":1,"resources":[{"id":k,"entry":v[0]} for k,v in samples.items()]}),encoding="utf-8")
    output_apk=folder/"protected.apk"
    command=[sys.executable,ROOT/"tools/protect.py","--input",input_apk,"--output",output_apk,
             "--keystore",key,"--alias","test","--ks-pass-env","DXP_MATRIX_PASSWORD","--key-pass-env","DXP_MATRIX_PASSWORD",
             "--apktool",args.apktool,"--android-sdk",sdk,"--build-tools",bt,"--android-jar",platform,
             "--ndk",args.ndk,"--java-home",args.java_home,"--d8-java-home",args.java_home,
             "--work-root",work/"tool-work","--abis","arm64-v8a"]
    if enabled:
        if native:
            config=folder/"protect-config.json"
            config.write_text(json.dumps({"sealed_resources_manifest":str(selection)}),encoding="utf-8")
            command.extend(["--config",config])
        else:
            command.extend(["--sealed-resources-manifest",selection])
    run(command,log,env)
    report=json.loads(Path(str(output_apk)+".dxprotect.json").read_text())
    assert report["sealed_resources"]["count"]==(6 if enabled else 0)
    with zipfile.ZipFile(output_apk) as archive:
        assert archive.read("assets/public/notice.txt")==b"unselected"
        for entry,data in samples.values():
            if enabled:assert entry not in archive.namelist()
            else:assert archive.read(entry)==data
        if so:assert archive.read("lib/arm64-v8a/libmatrixjni.so")==so.read_bytes()
    result={"package":package,"native":native,"resources_enabled":enabled,"static_passed":True,
            "apk":str(output_apk),"sha256":hashlib.sha256(output_apk.read_bytes()).hexdigest(),
            "runtime_passed":None}
    if args.serial:
        adb=sdk/"platform-tools"/("adb"+suffix)
        prefix=[adb,"-s",args.serial]
        existing=run(prefix+["shell","pm","path",package],log,allowed=(0,1))
        if "package:" in existing:raise RuntimeError("Refusing to replace existing package: "+package)
        run(prefix+["install",output_apk],log)
        run(prefix+["shell","am","start","-W","-n",package+"/.MainActivity"],log)
        time.sleep(2)
        remote="/data/local/tmp/dxp-resource-matrix.xml"
        run(prefix+["shell","uiautomator","dump",remote],log)
        xml=run(prefix+["shell","cat",remote],log)
        (folder/"ui.xml").write_text(xml,encoding="utf-8")
        assert "RESOURCE_MATRIX_PASS "+package in xml, "Runtime result failed; see "+str(folder/"ui.xml")
        # Leave dedicated test app installed for inspection; never uninstall unrelated apps.
        run(prefix+["shell","am","force-stop",package],log)
        result["runtime_passed"]=True
    return result

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--android-sdk",type=Path,required=True)
    p.add_argument("--ndk",type=Path,required=True)
    p.add_argument("--java-home",type=Path,required=True)
    p.add_argument("--apktool",type=Path,required=True)
    p.add_argument("--build-tools",default="37.0.0")
    p.add_argument("--out",type=Path,required=True)
    p.add_argument("--serial",help="Explicit authorized device; installs only new dedicated test packages")
    p.add_argument("--package-suffix",default="",help="Optional lowercase suffix for an isolated repeat run")
    args=p.parse_args()
    if args.package_suffix and not re.fullmatch("[a-z][a-z0-9]{0,24}",args.package_suffix):
        p.error("package suffix must match [a-z][a-z0-9]{0,24}")
    args.out.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix="resource-matrix-",dir=args.out.resolve()))
    log=work/"setup.log"
    env=os.environ.copy();env["DXP_MATRIX_PASSWORD"]="integration-test-only"
    suffix=".exe" if os.name=="nt" else ""
    key=work/"test-only.jks"
    run([args.java_home/"bin"/("keytool"+suffix),"-genkeypair","-keystore",key,"-alias","test","-storepass","integration-test-only",
         "-keypass","integration-test-only","-dname","CN=Resource Matrix TEST ONLY","-keyalg","RSA","-validity","2"],log,env)
    cases=[("org.example.dxpcatalog",False,True),("net.example.dxprenderer",True,True),("org.example.dxplegacy",False,False)]
    results=[]
    for package,native,enabled in cases:
        if args.package_suffix:package += "." + args.package_suffix
        results.append(build_case(args,work,package,native,enabled,key,env))
        (work/"results.json").write_text(json.dumps({
            "passed":len(results)==len(cases),
            "expected_cases":len(cases),"completed_cases":len(results),
            "cases":results},indent=2),encoding="utf-8")
        print("PASS "+package,flush=True)
    print(work/"results.json",flush=True)

if __name__=="__main__":main()
