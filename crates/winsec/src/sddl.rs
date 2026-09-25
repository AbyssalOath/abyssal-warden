//! Security descriptor strings (SDDL): parsing and the questions Abyssal
//! Warden asks of them ("who, besides trusted principals, can write
//! here?"). Pure, so it is tested on every platform.

/// Well-known SIDs.
pub const SYSTEM: &str = "S-1-5-18";
pub const ADMINISTRATORS: &str = "S-1-5-32-544";
pub const TRUSTED_INSTALLER: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// OWNER RIGHTS: applies to whoever owns the object.
pub const OWNER_RIGHTS: &str = "S-1-3-4";
/// CREATOR OWNER: a placeholder in inheritable ACEs only.
pub const CREATOR_OWNER: &str = "S-1-3-0";

/// SDDL alias to SID.
fn alias(a: &str) -> Option<&'static str> {
    Some(match a {
        "SY" => SYSTEM,
        "BA" => ADMINISTRATORS,
        "BU" => "S-1-5-32-545",
        "BG" => "S-1-5-32-546",
        "PU" => "S-1-5-32-547",
        "WD" => "S-1-1-0",
        "AU" => "S-1-5-11",
        "IU" => "S-1-5-4",
        "SU" => "S-1-5-6",
        "NU" => "S-1-5-2",
        "AN" => "S-1-5-7",
        "LS" => "S-1-5-19",
        "NS" => "S-1-5-20",
        "OW" => OWNER_RIGHTS,
        "CO" => CREATOR_OWNER,
        "CG" => "S-1-3-1",
        "AC" => "S-1-15-2-1",
        "RC" => "S-1-5-12",
        "PS" => "S-1-5-10",
        _ => return None,
    })
}

/// A SID or alias as a SID string (unknown aliases are kept as they are).
pub fn normalize_sid(s: &str) -> String {
    alias(s).map_or_else(|| s.to_ascii_uppercase(), str::to_owned)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ace {
    pub allow: bool,
    /// Applies only to children (`IO`), not to the object itself.
    pub inherit_only: bool,
    pub mask: u32,
    /// Normalised SID.
    pub sid: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Descriptor {
    pub owner: Option<String>,
    /// `P`: the DACL does not inherit from the parent.
    pub protected: bool,
    /// `None`: no DACL (everyone has full access).
    pub dacl: Option<Vec<Ace>>,
}

/// Access mask of an SDDL rights string (`FA`, `0x1200a9`, `GRGW`, ...).
fn rights(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut mask = 0u32;
    for i in (0..s.len()).step_by(2) {
        mask |= match s.get(i..i + 2)? {
            "GA" => 0x1000_0000,
            "GR" => 0x8000_0000,
            "GW" => 0x4000_0000,
            "GX" => 0x2000_0000,
            "RC" => 0x0002_0000,
            "SD" => 0x0001_0000,
            "WD" => 0x0004_0000,
            "WO" => 0x0008_0000,
            "RP" => 0x10,
            "WP" => 0x20,
            "CC" => 0x1,
            "DC" => 0x2,
            "LC" => 0x4,
            "SW" => 0x8,
            "LO" => 0x80,
            "DT" => 0x40,
            "CR" => 0x100,
            "FA" => 0x001f_01ff,
            "FR" => 0x0012_0089,
            "FW" => 0x0012_0116,
            "FX" => 0x0012_00a0,
            "KA" => 0x000f_003f,
            "KR" => 0x0002_0019,
            "KW" => 0x0002_0006,
            "KX" => 0x0002_0019,
            _ => return None,
        };
    }
    Some(mask)
}

/// Rights that let a principal change a file or directory (or its
/// security): write/append data, add files or subdirectories, write
/// attributes or extended attributes, delete children, delete, change the
/// DACL or owner, and generic all/write.
pub const WRITE_RIGHTS: u32 = 0x2
    | 0x4
    | 0x10
    | 0x40
    | 0x100
    | 0x0001_0000
    | 0x0004_0000
    | 0x0008_0000
    | 0x1000_0000
    | 0x4000_0000;

/// A SID value in an SDDL owner/group field: `S-...` or a two-letter alias.
fn take_sid(s: &str) -> (&str, &str) {
    if s.starts_with("S-") {
        let end = s
            .find(|c: char| !(c.is_ascii_digit() || c == '-' || c == 'S'))
            .unwrap_or(s.len());
        s.split_at(end)
    } else {
        s.split_at(s.len().min(2))
    }
}

/// Parses owner and DACL of an SDDL string. Group and SACL are skipped.
pub fn parse(sddl: &str) -> Option<Descriptor> {
    let mut d = Descriptor::default();
    let mut rest = sddl.trim();
    while !rest.is_empty() {
        let (tag, body) = (rest.get(..2)?, &rest[2..]);
        match tag {
            "O:" | "G:" => {
                let (sid, r) = take_sid(body);
                if sid.is_empty() {
                    return None;
                }
                if tag == "O:" {
                    d.owner = Some(normalize_sid(sid));
                }
                rest = r;
            }
            "D:" | "S:" => {
                let flags_end = body
                    .find('(')
                    .unwrap_or_else(|| body.find(':').map_or(body.len(), |i| i.saturating_sub(1)));
                let flags = &body[..flags_end];
                if tag == "D:" {
                    d.protected = flags.contains('P');
                    if flags.contains("NO_ACCESS_CONTROL") {
                        d.dacl = None;
                    } else {
                        d.dacl = Some(Vec::new());
                    }
                }
                let mut r = &body[flags_end..];
                while let Some(inner) = r.strip_prefix('(') {
                    let end = inner.find(')')?;
                    if tag == "D:" {
                        let f: Vec<&str> = inner[..end].split(';').collect();
                        if f.len() < 6 {
                            return None;
                        }
                        let allow = match f[0] {
                            "A" | "OA" | "XA" | "ZA" => true,
                            "D" | "OD" | "XD" => false,
                            // Unknown ACE types make the descriptor unanalysable.
                            _ => return None,
                        };
                        if let Some(list) = d.dacl.as_mut() {
                            list.push(Ace {
                                allow,
                                inherit_only: f[1].contains("IO"),
                                mask: rights(f[2])?,
                                sid: normalize_sid(f[5]),
                            });
                        }
                    }
                    r = &inner[end + 1..];
                }
                rest = r;
            }
            _ => return None,
        }
    }
    Some(d)
}

/// SIDs, other than `trusted`, that some allow-ACE effective on the object
/// grants any of `rights`. With no DACL, everyone ("S-1-1-0") has access.
pub fn granted_to_others(d: &Descriptor, rights: u32, trusted: &[&str]) -> Vec<String> {
    let trusted: Vec<String> = trusted.iter().map(|t| normalize_sid(t)).collect();
    let Some(dacl) = &d.dacl else {
        return vec!["S-1-1-0".into()];
    };
    let mut out: Vec<String> = Vec::new();
    for ace in dacl {
        if !ace.allow || ace.inherit_only || ace.mask & rights == 0 {
            continue;
        }
        // OWNER RIGHTS applies to the owner, who must then be trusted.
        let effective = if ace.sid == OWNER_RIGHTS {
            d.owner.clone().unwrap_or_else(|| OWNER_RIGHTS.into())
        } else {
            ace.sid.clone()
        };
        if !trusted.contains(&effective) && !out.contains(&effective) {
            out.push(effective);
        }
    }
    out
}

/// The protected DACL for a private directory (store, state): full control
/// for SYSTEM, Administrators and `owner`, inherited by everything inside.
pub fn private_dacl(owner_sid: &str) -> String {
    format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;{owner_sid})")
}

/// Checks a private directory's descriptor: protected, and no principal
/// other than `trusted` has any access.
pub fn check_private(sddl: &str, trusted: &[&str]) -> Result<(), String> {
    let d = parse(sddl).ok_or("unreadable security descriptor")?;
    if !d.protected {
        return Err("the DACL inherits from the parent directory".into());
    }
    let others = granted_to_others(&d, u32::MAX, trusted);
    if others.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "other principals have access: {}",
            others.join(", ")
        ))
    }
}

/// Checks that only `trusted` principals can modify an object (a
/// configuration file, a program the service runs, a restore target).
pub fn check_write_restricted(sddl: &str, trusted: &[&str]) -> Result<(), String> {
    let d = parse(sddl).ok_or("unreadable security descriptor")?;
    let others = granted_to_others(&d, WRITE_RIGHTS, trusted);
    if others.is_empty() {
        Ok(())
    } else {
        Err(format!("writable by {}", others.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_descriptors() {
        let d = parse("O:BAG:SYD:PAI(A;OICI;FA;;;SY)(A;OICIIO;GA;;;CO)(A;;0x1200a9;;;S-1-5-21-1-2-3-1001)(D;;WD;;;WD)").expect("parse");
        assert_eq!(d.owner.as_deref(), Some(ADMINISTRATORS));
        assert!(d.protected);
        let dacl = d.dacl.expect("dacl");
        assert_eq!(dacl.len(), 4);
        assert_eq!(
            dacl[0],
            Ace {
                allow: true,
                inherit_only: false,
                mask: 0x1f01ff,
                sid: SYSTEM.into()
            }
        );
        assert!(dacl[1].inherit_only);
        assert_eq!(dacl[2].sid, "S-1-5-21-1-2-3-1001");
        assert!(!dacl[3].allow);
        let o = parse("O:S-1-5-21-9-9-9-500D:(A;;FA;;;OW)").expect("parse");
        assert_eq!(o.owner.as_deref(), Some("S-1-5-21-9-9-9-500"));
        assert!(!o.protected);
        assert_eq!(parse("D:NO_ACCESS_CONTROL").expect("parse").dacl, None);
        assert!(parse("garbage").is_none());
        assert!(parse("D:(A;;ZZ;;;SY)").is_none(), "unknown rights");
        assert!(parse("D:(Q;;FA;;;SY)").is_none(), "unknown ACE type");
    }

    #[test]
    fn private_directories() {
        let me = "S-1-5-21-1-2-3-1001";
        let trusted = [SYSTEM, ADMINISTRATORS, me];
        assert!(check_private(&format!("O:{me}{}", private_dacl(me)), &trusted).is_ok());
        assert!(
            check_private("D:(A;OICI;FA;;;SY)", &trusted)
                .unwrap_err()
                .contains("inherits")
        );
        let leaky = format!("{}(A;;FR;;;BU)", private_dacl(me));
        assert!(
            check_private(&leaky, &trusted)
                .unwrap_err()
                .contains("S-1-5-32-545")
        );
        assert!(check_private("D:PNO_ACCESS_CONTROL", &trusted).is_err());
        // An inherit-only CREATOR OWNER entry does not grant access to the directory itself.
        assert!(
            check_private(&format!("{}(A;OICIIO;GA;;;CO)", private_dacl(me)), &trusted).is_ok()
        );
    }

    #[test]
    fn write_restrictions() {
        let trusted = [SYSTEM, ADMINISTRATORS, TRUSTED_INSTALLER];
        // Typical Program Files / System32 file.
        assert!(check_write_restricted(&format!("O:{TRUSTED_INSTALLER}D:PAI(A;;FA;;;{TRUSTED_INSTALLER})(A;;0x1200a9;;;BA)(A;;0x1200a9;;;SY)(A;;0x1200a9;;;BU)"), &trusted).is_ok());
        // Users can modify: refused.
        let e = check_write_restricted("D:(A;;0x1301bf;;;BU)(A;;FA;;;SY)", &trusted).unwrap_err();
        assert!(e.contains("S-1-5-32-545"));
        // Users may only add files (e.g. C:\Users\Public, ProgramData): refused.
        assert!(check_write_restricted("D:(A;;0x100006;;;BU)", &trusted).is_err());
        // OWNER RIGHTS resolves to the owner.
        assert!(check_write_restricted("O:SYD:(A;;FA;;;OW)", &trusted).is_ok());
        assert!(check_write_restricted("O:S-1-5-21-5-5-5-1000D:(A;;FA;;;OW)", &trusted).is_err());
        assert!(
            check_write_restricted("D:(A;;FA;;;WD)", &trusted)
                .unwrap_err()
                .contains("S-1-1-0")
        );
        // Without a DACL everyone has access, so an absent D: part is refused.
        assert!(check_write_restricted("O:SY", &trusted).is_err());
    }
}
