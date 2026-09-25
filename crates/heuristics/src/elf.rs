//! ELF (Linux/Unix executable) structure heuristics.

use memchr::memmem;
use object::Endianness;
use object::elf::{
    DT_NULL, DT_RPATH, DT_RUNPATH, DT_STRSZ, DT_STRTAB, ET_DYN, ET_EXEC, PF_W, PF_X, PT_DYNAMIC,
    PT_GNU_STACK, PT_INTERP, PT_LOAD,
};
use object::read::elf::{Dyn, FileHeader, ProgramHeader};

/// Observations about one ELF file.
#[derive(Debug, Default)]
pub(crate) struct ElfFacts {
    pub(crate) executable: bool,
    pub(crate) rwx_segments: usize,
    pub(crate) exec_stack: bool,
    pub(crate) upx: bool,
    pub(crate) no_sections: bool,
    pub(crate) entry_outside_code: Option<String>,
    pub(crate) unsafe_rpath: Vec<String>,
    pub(crate) interpreter: Option<String>,
    pub(crate) odd_interpreter: bool,
}

const TEMP_DIRS: &[&str] = &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/shm/"];

pub(crate) fn analyze(data: &[u8]) -> Result<ElfFacts, String> {
    match object::FileKind::parse(data) {
        Ok(object::FileKind::Elf32) => analyze_as::<object::elf::FileHeader32<Endianness>>(data),
        Ok(object::FileKind::Elf64) => analyze_as::<object::elf::FileHeader64<Endianness>>(data),
        Ok(other) => Err(format!("not an ELF file ({other:?})")),
        Err(e) => Err(e.to_string()),
    }
}

fn analyze_as<H: FileHeader<Endian = Endianness>>(data: &[u8]) -> Result<ElfFacts, String> {
    let header = H::parse(data).map_err(|e| e.to_string())?;
    let endian = header.endian().map_err(|e| e.to_string())?;
    let phdrs = header
        .program_headers(endian, data)
        .map_err(|e| e.to_string())?;
    let e_type = header.e_type(endian);
    let mut f = ElfFacts {
        executable: e_type == ET_EXEC || e_type == ET_DYN,
        ..ElfFacts::default()
    };
    let entry: u64 = header.e_entry(endian).into();

    let mut loads: Vec<(u64, u64, u64, u64, bool)> = Vec::new(); // vaddr, memsz, offset, filesz, exec
    let mut dynamic = None;
    for ph in phdrs {
        let flags = ph.p_flags(endian);
        match ph.p_type(endian) {
            PT_LOAD => {
                if flags & PF_W != 0 && flags & PF_X != 0 {
                    f.rwx_segments += 1;
                }
                loads.push((
                    ph.p_vaddr(endian).into(),
                    ph.p_memsz(endian).into(),
                    ph.p_offset(endian).into(),
                    ph.p_filesz(endian).into(),
                    flags & PF_X != 0,
                ));
            }
            PT_GNU_STACK => f.exec_stack = flags & PF_X != 0,
            PT_INTERP => {
                if let Ok(Some(i)) = ph.interpreter(endian, data) {
                    let i = String::from_utf8_lossy(i).into_owned();
                    let base = i.rsplit('/').next().unwrap_or("");
                    let standard = base.starts_with("ld-")
                        || base.starts_with("ld64")
                        || base.starts_with("ld.so");
                    f.odd_interpreter = !standard
                        || TEMP_DIRS.iter().any(|t| i.starts_with(t))
                        || !i.starts_with('/');
                    f.interpreter = Some(i);
                }
            }
            PT_DYNAMIC => dynamic = ph.dynamic(endian, data).ok().flatten(),
            _ => {}
        }
    }
    f.no_sections = f.executable
        && header.e_shnum(endian) == 0
        && header.e_shoff(endian).into() == 0
        && !loads.is_empty();
    if f.executable && entry != 0 && !loads.is_empty() {
        let in_exec = loads
            .iter()
            .any(|&(va, memsz, _, _, x)| x && entry >= va && entry < va.saturating_add(memsz));
        if !in_exec {
            f.entry_outside_code = Some(format!(
                "entry point {entry:#x} is not in an executable segment"
            ));
        }
    }

    // RPATH/RUNPATH, found through the dynamic segment so stripped section
    // headers do not hide it.
    if let Some(entries) = dynamic {
        let (mut strtab, mut strsz) = (None, 0u64);
        let mut paths = Vec::new();
        for d in entries.iter().take(4096) {
            let tag: i64 = d.d_tag(endian).into();
            let val: u64 = d.d_val(endian).into();
            match tag {
                DT_NULL => break,
                DT_STRTAB => strtab = Some(val),
                DT_STRSZ => strsz = val,
                DT_RPATH | DT_RUNPATH => paths.push(val),
                _ => {}
            }
        }
        if let Some(addr) = strtab {
            let file_off = loads
                .iter()
                .find(|&&(va, _, _, filesz, _)| addr >= va && addr < va.saturating_add(filesz))
                .map(|&(va, _, off, _, _)| off + (addr - va));
            if let Some(base) = file_off {
                for p in paths {
                    if p >= strsz {
                        continue;
                    }
                    let Some(bytes) = usize::try_from(base + p).ok().and_then(|s| data.get(s..))
                    else {
                        continue;
                    };
                    let end = memchr::memchr(0, bytes).unwrap_or(bytes.len()).min(4096);
                    let text = String::from_utf8_lossy(&bytes[..end]).into_owned();
                    for entry in text.split(':') {
                        let bad = entry.is_empty()
                            || entry == "."
                            || (!entry.starts_with('/')
                                && !entry.starts_with("$ORIGIN")
                                && !entry.starts_with("${ORIGIN}"))
                            || TEMP_DIRS
                                .iter()
                                .any(|t| entry.starts_with(t) || format!("{entry}/") == *t);
                        if bad && !f.unsafe_rpath.contains(&entry.to_owned()) {
                            f.unsafe_rpath.push(if entry.is_empty() {
                                "(empty: current directory)".into()
                            } else {
                                entry.to_owned()
                            });
                        }
                    }
                }
            }
        }
    }

    // UPX writes its `UPX!` header right after the program headers; the
    // string elsewhere (e.g. in a program's constants) means nothing.
    f.upx = f.executable && memmem::find(&data[..data.len().min(1024)], b"UPX!").is_some();
    Ok(f)
}
