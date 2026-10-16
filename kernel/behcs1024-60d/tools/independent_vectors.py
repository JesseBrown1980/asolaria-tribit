#!/usr/bin/env python3
"""Independent standard-library SHA-256 parity, no external modules or JSON."""
from pathlib import Path
import hashlib
cases=[
 ("empty",b"",[831,408,169,987,87,301,61,840],"a93505a95d0aace1",0),
 ("abc",b"abc",[813,428,103,701,206,505,788,597],"ff504d90899902cd",0),
 ("demo",b"demo",[660,554,864,544,519,408,307,253],"2834d01cd22e962e",0),
 ("boundary508",b"B"*508,[760,475,404,897,943,763,994,891],"ccf39512e5da6fdc",0),
 ("boundary509",b"B"*509,[481,827,862,35,658,245,339,1014],"7c092ab69457d613",1),
 ("boundary512",b"B"*512,[913,534,916,925,298,717,311,170],"7f519cdfbabf95bc",1)]
rows=["HBP1|schema=ASOLARIA-CLEAN-BEHCS1024-60D-PYTHON-GOLDEN-V1|algorithm=HASHLIB-SHA256|json=0"]
for name,raw,first,pid,rep in cases:
    raw=raw[:512]
    glyph=[]
    for c in range(4):
        h=hashlib.sha256((raw+c.to_bytes(4,"big"))[:512]).digest()
        glyph.extend(int.from_bytes(h[i:i+2],"big")&1023 for i in range(0,32,2))
    glyph=glyph[:60]
    out=hashlib.sha256(b"".join(v.to_bytes(2,"big") for v in glyph)).hexdigest()[:16]
    assert len(glyph)==60 and all(0<=x<1024 for x in glyph)
    assert glyph[:8]==first and out==pid and int(glyph[:16]==glyph[16:32])==rep
    rows.append("VECTOR|name="+name+"|bytes="+str(len(raw))+"|glyphs=60|first8="+".".join(map(str,first))+"|host8="+pid+"|counter_alias="+str(rep)+"|json=0")
rows.append("VERDICT|independent_python=PASS|counter_len_gt_508=UNSAFE|input_identity=NOT_REVERSIBLE|json=0")
report="\n".join(rows)+"\n"
assert report==(Path(__file__).resolve().parent.parent/"GOLDEN-VECTORS.hbp").read_text()
print(report,end="")
