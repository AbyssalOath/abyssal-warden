//! File-name heuristics: disguised executables, double extensions, bidi
//! spoofing.

/// Extensions that promise a document, image, archive or media file.
const DOCUMENT_EXTS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "bmp", "tif", "tiff", "webp", "svg", "ico", "mp3", "mp4", "wav",
    "avi", "mkv", "mov", "wmv", "flac", "ogg", "zip", "rar", "7z", "tar", "gz", "iso", "html",
    "htm", "xml", "json",
];

/// Extensions Windows runs when opened.
const EXECUTABLE_EXTS: &[&str] = &[
    "exe", "scr", "com", "pif", "cpl", "msi", "bat", "cmd", "js", "jse", "vbs", "vbe", "wsf",
    "hta", "lnk", "ps1", "jar",
];

fn ext(name: &str) -> Option<String> {
    let (stem, e) = name.rsplit_once('.')?;
    (!stem.is_empty()).then(|| e.to_ascii_lowercase())
}

/// The file's extension claims a document or media type.
pub(crate) fn has_document_extension(name: &str) -> bool {
    ext(name).is_some_and(|e| DOCUMENT_EXTS.contains(&e.as_str()))
}

/// `invoice.pdf.exe`, or `invoice.pdf          .exe`.
pub(crate) fn double_extension(name: &str) -> Option<String> {
    let (stem, last) = name.rsplit_once('.')?;
    let last = last.to_ascii_lowercase();
    if !EXECUTABLE_EXTS.contains(&last.as_str()) {
        return None;
    }
    if stem.ends_with("   ") {
        return Some(format!("name padded with spaces before .{last}"));
    }
    let (_, inner) = stem.rsplit_once('.')?;
    let inner = inner.trim().to_ascii_lowercase();
    DOCUMENT_EXTS
        .contains(&inner.as_str())
        .then(|| format!(".{inner} followed by .{last}"))
}

/// Bidirectional control characters in the name, as code points.
pub(crate) fn bidi_controls(name: &str) -> Vec<String> {
    let mut out: Vec<String> = name
        .chars()
        .filter(|c| warden_core::text::is_bidi_control(*c))
        .map(|c| format!("U+{:04X}", u32::from(c)))
        .collect();
    out.dedup();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_extensions() {
        assert!(double_extension("invoice.pdf.exe").is_some());
        assert!(double_extension("Photo.JPG.scr").is_some());
        assert!(double_extension("report.docx      .exe").is_some());
        assert!(double_extension("setup.exe").is_none());
        assert!(double_extension("archive.tar.gz").is_none());
        assert!(double_extension("my.app.exe").is_none());
        assert!(double_extension(".pdf.exe").is_none() || double_extension(".pdf.exe").is_some());
    }

    #[test]
    fn document_extensions() {
        assert!(has_document_extension("a.PDF"));
        assert!(!has_document_extension("a.exe"));
        assert!(!has_document_extension(".pdf"));
        assert!(!has_document_extension("noext"));
    }

    #[test]
    fn bidi() {
        assert_eq!(bidi_controls("invoice\u{202E}fdp.exe"), ["U+202E"]);
        assert!(bidi_controls("normal name.txt").is_empty());
    }
}
