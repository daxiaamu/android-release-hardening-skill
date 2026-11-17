"""Authorized, isolated Android negative tests; no production APK/key is modified.

PM spoofing is simulated in a temporary source copy, NOT a Frida claim.
Resource mutations are re-signed with the same TEST certificate to isolate
resource authentication from Android's installer/APK signature rejection.
"""
import argparse
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
import xml.etree.ElementTree as ET
import run_resource_matrix as matrix

ROOT = Path(__file__).resolve().parents[1]

def generate_key(args,path,log,env):
    matrix.run([args.java_home/"bin/keytool.exe","-genkeypair","-keystore",path,"-alias","test",
                "-storepass","integration-test-only","-keypass","integration-test-only",
                "-dname","CN=Negative Test ONLY","-keyalg","RSA","-validity","2"],log,env)

def resign(args,source,output,key,log,env,replacements=None):
    unsigned=output.with_suffix(".unsigned.apk")
    with zipfile.ZipFile(source) as archive, zipfile.ZipFile(unsigned,"w") as target:
        for info in archive.infolist():
            upper=info.filename.upper()
            if upper=="META-INF/MANIFEST.MF" or (upper.startswith("META-INF/") and upper.endswith((".SF",".RSA",".DSA",".EC"))):
                continue
            data=(replacements or {}).get(info.filename)
            target.writestr(info,archive.read(info) if data is None else data)
    bt=args.android_sdk/"build-tools"/args.build_tools
    aligned=output.with_suffix(".aligned.apk")
    matrix.run([bt/"zipalign.exe","-f","-p","4",unsigned,aligned],log)
    command=[args.java_home/"bin/java.exe","-jar",bt/"lib/apksigner.jar"]
    matrix.run(command+["sign","--ks",key,"--ks-key-alias","test","--ks-pass","env:DXP_MATRIX_PASSWORD",
                       "--key-pass","env:DXP_MATRIX_PASSWORD","--v1-signing-enabled","true",
                       "--v2-signing-enabled","true","--v3-signing-enabled","true","--out",output,aligned],log,env)
    matrix.run(command+["verify","--verbose",output],log,env)

def observe(args,apk,package,gateway,work,label):
    log=work/"device.log"
    adb=[args.android_sdk/"platform-tools/adb.exe","-s",args.serial]
    matrix.run(adb+["install","-r",apk],log)
    matrix.run(adb+["shell","am","force-stop",package],log)
    matrix.run(adb+["shell","am","start","-W","-n",package+"/"+gateway],log)
    time.sleep(2)
    remote="/data/local/tmp/dxp-security-regression.xml"
    matrix.run(adb+["shell","uiautomator","dump",remote],log)
    xml=matrix.run(adb+["shell","cat",remote],log)
    (work/(label+".xml")).write_text(xml,encoding="utf-8")
    return xml

def require(value,message):
    if not value:raise AssertionError(message)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("android-sdk","ndk","java-home","apktool","out"):
        p.add_argument("--"+name,type=Path,required=True)
    p.add_argument("--serial",required=True)
    p.add_argument("--build-tools",default="37.0.0")
    p.add_argument("--package-suffix",default="secondaudit")
    args=p.parse_args()
    if not re.fullmatch("[a-z][a-z0-9]{0,24}",args.package_suffix):p.error("Invalid package suffix")
    args.out.mkdir(parents=True,exist_ok=True)
    work=Path(tempfile.mkdtemp(prefix="security-negative-",dir=args.out.resolve()))
    env=os.environ.copy();env["DXP_MATRIX_PASSWORD"]="integration-test-only"
    log=work/"setup.log"
    official=work/"test-only.jks";attacker=work/"attacker-only.jks"
    generate_key(args,official,log,env);generate_key(args,attacker,log,env)
    a="org.example.dxpnegative.a."+args.package_suffix
    b="org.example.dxpnegative.b."+args.package_suffix
    spoof="org.example.dxpnegative.spoof."+args.package_suffix
    results=[]
    # Both positives exercise real App processes before any negative samples.
    for package in (a,b):
        result=matrix.build_case(args,work,package,False,True,official,env)
        results.append({"case":"baseline "+package,"passed":result["runtime_passed"]})
    source=work/a/"protected.apk"
    report=json.loads(Path(str(source)+".dxprotect.json").read_text())
    gateway=report["diversification"]["gateway_fqcn"]
    index="assets/"+report["diversification"]["asset_dir"]+"/resources.idx"
    with zipfile.ZipFile(source) as z:
        original=z.read(index)
        resource_names=["assets/"+report["diversification"]["asset_dir"]+"/"+v["ciphertext"]
                        for v in report["sealed_resources"]["resources"]]
        first,second=resource_names[:2]
        cipher_a=z.read(first);cipher_b=z.read(second)
    other_report=json.loads((work/b/"protected.apk.dxprotect.json").read_text())
    with zipfile.ZipFile(work/b/"protected.apk") as z:
        other_index=z.read("assets/"+other_report["diversification"]["asset_dir"]+"/resources.idx")
    damaged=bytearray(original);damaged[40]^=1
    variants=[
        ("index-bitflip",{index:bytes(damaged)}),
        ("index-other-build",{index:other_index}),
        ("index-as-resource",{index:cipher_a}),
        ("resource-swap",{first:cipher_b,second:cipher_a}),
    ]
    for label,replacements in variants:
        output=work/(label+".apk")
        resign(args,source,output,official,log,env,replacements)
        xml=observe(args,output,a,gateway,work,label)
        require("RESOURCE_MATRIX_FAIL java.lang.SecurityException" in xml,label+" did not reject at resource API")
        require("安全验证失败" not in xml,label+" was intercepted before the resource API")
        results.append({"case":label,"passed":True,"isolation":"valid same TEST signer; original business DEX/SO unchanged"})
    xml=observe(args,source,a,gateway,work,"restored-baseline")
    require("RESOURCE_MATRIX_PASS "+a in xml,"Baseline restoration failed")
    # Isolated source copy only; production getter and gates are untouched.
    isolated=work/"simulated-pm-tool"
    shutil.copytree(ROOT/"stub",isolated/"stub")
    shutil.copytree(ROOT/"tools",isolated/"tools",ignore=shutil.ignore_patterns("__pycache__"))
    stub=isolated/"stub/src/com/daxiaamu/protector/StubApplication.java"
    text=stub.read_text(encoding="utf-8")
    marker="private static byte[] currentSignerSha256(Context context) throws Exception {"
    start=text.index(marker)+len(marker);depth=1;end=start
    while depth:
        if text[end]=="{":depth+=1
        elif text[end]=="}":depth-=1
        end+=1
    text=text[:start]+"\n        // TEST ONLY: simulate PM returning the pinned signer.\n        return BuildProfile.SIGNER_SHA256.clone();\n    }"+text[end:]
    stub.write_text(text,encoding="utf-8")
    prior=matrix.ROOT;matrix.ROOT=isolated
    try:
        matrix.build_case(args,work,spoof,False,True,official,env)
    finally:matrix.ROOT=prior
    spoof_apk=work/spoof/"protected.apk"
    spoof_report=json.loads(Path(str(spoof_apk)+".dxprotect.json").read_text())
    spoof_gateway=spoof_report["diversification"]["gateway_fqcn"]
    negative=work/"pm-spoof-resigned.apk"
    resign(args,spoof_apk,negative,attacker,log,env)
    adb=[args.android_sdk/"platform-tools/adb.exe","-s",args.serial]
    # Only remove the just-created, baseline-verified synthetic fixture to change its signer.
    matrix.run(adb+["uninstall",spoof],log)
    xml=observe(args,negative,spoof,spoof_gateway,work,"pm-spoof-resigned")
    require("安全验证失败" in xml and "RESOURCE_MATRIX_PASS" not in xml,"Independent APK signer path did not reject")
    buttons=[node.get("text") for node in ET.fromstring(xml).iter("node") if node.get("class")=="android.widget.Button"]
    require(buttons==["退出"],"Failure dialog did not have exactly one Exit button")
    matrix.run(adb+["shell","input","keyevent","KEYCODE_BACK"],log)
    matrix.run(adb+["shell","input","tap","10","10"],log)
    matrix.run(adb+["shell","uiautomator","dump","/data/local/tmp/dxp-security-after-back.xml"],log)
    after=matrix.run(adb+["shell","cat","/data/local/tmp/dxp-security-after-back.xml"],log)
    (work/"pm-spoof-after-back.xml").write_text(after,encoding="utf-8")
    require("安全验证失败" in after,"Failure dialog did not persist after Back/outside")
    results.append({"case":"pm-spoof-resigned","passed":True,
                    "scope":"source-level simulated PM result, not a live Frida test"})
    for package in (a,b,spoof):matrix.run(adb+["uninstall",package],log)
    output={"passed":True,"serial":args.serial,"results":results,
            "production_apk_modified":False,"test_keys_only":True}
    (work/"results.json").write_text(json.dumps(output,indent=2),encoding="utf-8")
    print(work/"results.json",flush=True)

if __name__=="__main__":main()
