// Synthetic, harmless test rule for exercising the YARA pipeline.
// Matches a file containing the marker below. Create one with:
//   printf 'ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER\n' > marker.txt
rule AbyssalWarden_Test_SyntheticMarker {
  meta:
    description = "Harmless synthetic YARA test marker; not a threat."
    aw_kind = "known_indicator"
    aw_confidence = "high"
    aw_severity = "info"
    aw_category = "test_indicator"
    aw_name = "AbyssalWarden.Test.SyntheticYaraMarker"
    aw_rule_version = 1
  strings:
    $marker = "ABYSSAL-WARDEN-YARA-SYNTHETIC-MARKER"
  condition:
    $marker
}
