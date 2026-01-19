use extanalyzer::unpack::{ExtensionFormat, detect_format};

#[test]
fn test_detect_crx_format() {
    // CRX3 magic: "Cr24"
    let crx_data = b"Cr24\x03\x00\x00\x00";
    assert_eq!(detect_format(crx_data), ExtensionFormat::Crx3);
}

#[test]
fn test_detect_zip_format() {
    // ZIP magic: "PK\x03\x04"
    let zip_data = b"PK\x03\x04";
    assert_eq!(detect_format(zip_data), ExtensionFormat::Zip);
}

#[test]
fn test_detect_unknown_format() {
    let unknown = b"UNKNOWN";
    assert_eq!(detect_format(unknown), ExtensionFormat::Unknown);
}
