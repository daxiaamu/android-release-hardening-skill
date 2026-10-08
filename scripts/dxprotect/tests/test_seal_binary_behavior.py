import os, re, shutil, subprocess, tempfile, unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
class SealBinaryBehaviorTest(unittest.TestCase):
    def test_patched_optimized_binary(self):
        cc = os.environ.get('DXP_HOST_CC') or shutil.which('gcc')
        if not cc: self.skipTest('Host C compiler required')
        for filename, name in [('anchor.c', 'eq_seal'), ('dxprotect.c', 'equal_seal32')]:
            with self.subTest(module=filename), tempfile.TemporaryDirectory() as temp:
                source=(ROOT/'stub/native'/filename).read_text(encoding='utf-8')
                function=re.search(r'static int '+name+r'\([^\n]+',source).group(0)
                marker=bytes.fromhex('AD7234BB018CDA442658B3ACED907A61')
                c,exe=Path(temp)/'probe.c',Path(temp)/('probe.exe' if os.name=='nt' else 'probe')
                c.write_text('#include <stdint.h>\n'+function+'\n__attribute__((used)) static const uint8_t slot[48]={'+','.join(str(v) for v in marker)+'};\nint main(void){uint8_t e[32];int i;for(i=0;i<32;i++)e[i]=i+1;return '+name+'(e,slot+16)?0:7;}\n',encoding='ascii')
                subprocess.run([cc,'-O2',str(c),'-o',str(exe)],check=True)
                self.assertEqual(7,subprocess.run([str(exe)]).returncode)
                binary=bytearray(exe.read_bytes())
                self.assertEqual(1,binary.count(marker))
                offset=binary.index(marker)+16
                binary[offset:offset+32]=bytes(range(1,33))
                exe.write_bytes(binary)
                self.assertEqual(0,subprocess.run([str(exe)]).returncode)
                binary[offset+13]^=1
                exe.write_bytes(binary)
                self.assertEqual(7,subprocess.run([str(exe)]).returncode)
