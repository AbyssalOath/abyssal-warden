//! PE (Windows executable) structure heuristics.

use memchr::memmem;
use object::LittleEndian as LE;
use object::pe::{
    IMAGE_DIRECTORY_ENTRY_SECURITY, IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_WRITE,
};
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile};

use crate::entropy;

/// Section names left by packers and protectors.
const PACKER_SECTIONS: &[(&str, &str)] = &[
    ("UPX0", "UPX"),
    ("UPX1", "UPX"),
    ("UPX2", "UPX"),
    (".UPX", "UPX"),
    (".aspack", "ASPack"),
    (".adata", "ASPack"),
    ("ASPack", "ASPack"),
    ("MPRESS1", "MPRESS"),
    ("MPRESS2", "MPRESS"),
    (".MPRESS1", "MPRESS"),
    (".petite", "Petite"),
    (".themida", "Themida"),
    (".winlice", "WinLicense"),
    (".vmp0", "VMProtect"),
    (".vmp1", "VMProtect"),
    (".vmp2", "VMProtect"),
    (".enigma1", "Enigma"),
    (".enigma2", "Enigma"),
    (".nsp0", "NsPack"),
    (".nsp1", "NsPack"),
    ("PEC2", "PECompact"),
    ("pec1", "PECompact"),
    (".packed", "RLPack"),
    ("PELOCKnt", "PELock"),
    (".yP", "Y0da"),
    (".perplex", "Perplex"),
    ("kkrunchy", "kkrunchy"),
    (".MaskPE", "MaskPE"),
];

/// Function sets that together implement code injection or hollowing.
const INJECTION_SETS: &[(&str, &[&[&str]])] = &[
    (
        "remote thread injection",
        &[
            &[
                "VirtualAllocEx",
                "NtAllocateVirtualMemory",
                "ZwAllocateVirtualMemory",
            ],
            &[
                "WriteProcessMemory",
                "NtWriteVirtualMemory",
                "ZwWriteVirtualMemory",
            ],
            &[
                "CreateRemoteThread",
                "CreateRemoteThreadEx",
                "NtCreateThreadEx",
                "RtlCreateUserThread",
                "QueueUserAPC",
                "NtQueueApcThread",
            ],
        ],
    ),
    (
        "process hollowing",
        &[
            &["NtUnmapViewOfSection", "ZwUnmapViewOfSection"],
            &[
                "SetThreadContext",
                "Wow64SetThreadContext",
                "NtSetContextThread",
            ],
            &["ResumeThread", "NtResumeThread"],
        ],
    ),
];

/// Entropy (bits per byte) above which code is considered packed.
const HIGH_ENTROPY: f64 = 7.2;
/// Imports at or below which a high-entropy program looks packed.
const FEW_IMPORTS: usize = 10;
const MAX_IMPORTS: usize = 20_000;

/// Observations about one PE file.
#[derive(Debug, Default)]
pub(crate) struct PeFacts {
    pub(crate) rwx_sections: Vec<String>,
    pub(crate) entry_outside_code: Option<String>,
    pub(crate) packers: Vec<String>,
    pub(crate) code_entropy: Option<f64>,
    pub(crate) imports: Vec<String>,
    pub(crate) injection: Vec<(&'static str, Vec<String>)>,
    pub(crate) embedded_pe_at: Option<u64>,
    pub(crate) signed: bool,
    /// UEFI image (boot loaders, the Linux kernel's EFI stub).
    pub(crate) efi: bool,
}

/// Whether `data` has MZ and PE signatures.
pub(crate) fn looks_like_pe(data: &[u8]) -> bool {
    pe_header_at(data, 0)
}

fn pe_header_at(data: &[u8], start: usize) -> bool {
    let Some(d) = data.get(start..) else {
        return false;
    };
    if d.len() < 0x40 || &d[..2] != b"MZ" {
        return false;
    }
    let lfanew = u32::from_le_bytes([d[0x3c], d[0x3d], d[0x3e], d[0x3f]]) as usize;
    (0x40..(1 << 20)).contains(&lfanew) && d.get(lfanew..lfanew + 4) == Some(b"PE\0\0")
}

pub(crate) fn analyze(data: &[u8]) -> Result<PeFacts, String> {
    match object::FileKind::parse(data) {
        Ok(object::FileKind::Pe32) => analyze_as::<object::pe::ImageNtHeaders32>(data),
        Ok(object::FileKind::Pe64) => analyze_as::<object::pe::ImageNtHeaders64>(data),
        Ok(other) => Err(format!("not a PE image ({other:?})")),
        Err(e) => Err(e.to_string()),
    }
}

fn analyze_as<Pe: ImageNtHeaders>(data: &[u8]) -> Result<PeFacts, String> {
    let file = PeFile::<Pe>::parse(data).map_err(|e| e.to_string())?;
    let mut facts = PeFacts::default();
    let optional = file.nt_headers().optional_header();
    let entry = optional.address_of_entry_point();
    facts.efi = (10..=13).contains(&optional.subsystem());

    let mut code = Vec::new();
    let mut end_of_sections = 0u64;
    let mut entry_section: Option<(String, bool)> = None;
    for s in file.section_table().iter() {
        let name = String::from_utf8_lossy(s.raw_name()).into_owned();
        let chars = s.characteristics.get(LE);
        let va = s.virtual_address.get(LE);
        let raw_size = s.size_of_raw_data.get(LE);
        let size = s.virtual_size.get(LE).max(raw_size);
        let exec = chars & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) != 0;
        if chars & IMAGE_SCN_MEM_EXECUTE != 0 && chars & IMAGE_SCN_MEM_WRITE != 0 {
            facts.rwx_sections.push(name.clone());
        }
        if entry >= va && u64::from(entry) < u64::from(va) + u64::from(size) {
            entry_section = Some((name.clone(), exec));
        }
        if let Some((_, packer)) = PACKER_SECTIONS
            .iter()
            .find(|(n, _)| name.eq_ignore_ascii_case(n))
            && !facts.packers.iter().any(|p| p == packer)
        {
            facts.packers.push((*packer).to_owned());
        }
        if exec && let Ok(d) = s.pe_data(data) {
            code.extend_from_slice(&d[..d.len().min(16 << 20)]);
        }
        let end = u64::from(s.pointer_to_raw_data.get(LE)) + u64::from(raw_size);
        end_of_sections = end_of_sections.max(end);
    }
    if entry != 0 {
        facts.entry_outside_code = match entry_section {
            None => Some(format!(
                "entry point RVA {entry:#x} is not inside any section"
            )),
            Some((name, false)) => Some(format!(
                "entry point RVA {entry:#x} is in non-executable section {name}"
            )),
            Some((_, true)) => None,
        };
    }
    if code.len() >= 1024 {
        facts.code_entropy = Some(entropy(&code));
    }

    if let Ok(Some(table)) = file.import_table()
        && let Ok(mut descriptors) = table.descriptors()
    {
        'outer: while let Ok(Some(d)) = descriptors.next() {
            let thunk_rva = match d.original_first_thunk.get(LE) {
                0 => d.first_thunk.get(LE),
                n => n,
            };
            let Ok(mut thunks) = table.thunks(thunk_rva) else {
                continue;
            };
            while let Ok(Some(t)) = thunks.next::<Pe>() {
                if let Ok(object::read::pe::Import::Name(_, name)) = table.import::<Pe>(t) {
                    facts
                        .imports
                        .push(String::from_utf8_lossy(name).into_owned());
                    if facts.imports.len() >= MAX_IMPORTS {
                        break 'outer;
                    }
                }
            }
        }
    }
    for (label, groups) in INJECTION_SETS {
        let hits: Vec<String> = groups
            .iter()
            .filter_map(|g| {
                g.iter()
                    .find(|f| facts.imports.iter().any(|i| i == *f))
                    .map(|f| (*f).to_owned())
            })
            .collect();
        if hits.len() == groups.len() {
            facts.injection.push((label, hits));
        }
    }

    // Overlay: bytes after the last section, excluding the signature.
    let (sig_start, sig_len) = file
        .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
        .map(|d| {
            (
                u64::from(d.virtual_address.get(LE)),
                u64::from(d.size.get(LE)),
            )
        })
        .unwrap_or((0, 0));
    facts.signed = sig_len > 0;
    let len = data.len() as u64;
    if end_of_sections < len {
        let start = end_of_sections as usize;
        let overlay = &data[start..data.len().min(start + (64 << 20))];
        for pos in memmem::find_iter(overlay, b"MZ").take(4096) {
            let abs = (start + pos) as u64;
            if sig_len > 0 && abs >= sig_start && abs < sig_start + sig_len {
                continue;
            }
            if pe_header_at(data, start + pos) {
                facts.embedded_pe_at = Some(abs);
                break;
            }
        }
    }
    Ok(facts)
}

/// Whether the facts describe a probably packed image.
pub(crate) fn looks_packed(f: &PeFacts) -> bool {
    // UEFI images (e.g. the compressed Linux kernel) import nothing and
    // carry compressed payloads by design.
    !f.efi && f.code_entropy.is_some_and(|e| e >= HIGH_ENTROPY) && f.imports.len() <= FEW_IMPORTS
}
