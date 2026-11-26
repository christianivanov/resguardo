//! IBANs (Annex F.5, ADR 0010): the length of each country in the SWIFT IBAN Registry and
//! mod 97 = 1.
// Test helpers may panic: a scanning error is a test failure.
#![allow(clippy::unwrap_used)]

use std::ops::Range;
use std::sync::LazyLock;

use resguardo_core::DataClass;
use resguardo_core::config::ScanConfig;
use resguardo_scan::Pipeline;

/// The example of every entry of the SWIFT IBAN Registry (TXT downloaded on 2026-11-26), in
/// electronic and print format, generated from the registry file, not typed.
const REGISTRY_EXAMPLES: &[(&str, &str)] = &[
    ("AD1200012030200359100100", "AD12 0001 2030 2003 5910 0100"),
    ("AE070331234567890123456", "AE07 0331 2345 6789 0123 456"),
    (
        "AL47212110090000000235698741",
        "AL47 2121 1009 0000 0002 3569 8741",
    ),
    ("AT611904300234573201", "AT61 1904 3002 3457 3201"),
    (
        "AZ21NABZ00000000137010001944",
        "AZ21 NABZ 0000 0000 1370 1000 1944",
    ),
    ("BA391290079401028494", "BA39 1290 0794 0102 8494"),
    ("BE68539007547034", "BE68 5390 0754 7034"),
    ("BG80BNBG96611020345678", "BG80 BNBG 9661 1020 3456 78"),
    ("BH67BMAG00001299123456", "BH67 BMAG 0000 1299 1234 56"),
    (
        "BI4210000100010000332045181",
        "BI42 10000 10001 00003320451 81",
    ),
    (
        "BR6699999A03000010009795493C1",
        "BR66 9999 9A03 0000 1000 9795 493C 1",
    ),
    (
        "BY13NBRB3600900000002Z00AB00",
        "BY13 NBRB 3600 9000 0000 2Z00 AB00",
    ),
    ("CH9300762011623852957", "CH93 0076 2011 6238 5295 7"),
    ("CR05015202001026284066", "CR05 0152 0200 1026 2840 66"),
    (
        "CY17002001280000001200527600",
        "CY17 0020 0128 0000 0012 0052 7600",
    ),
    ("CZ6508000000192000145399", "CZ65 0800 0000 1920 0014 5399"),
    ("DE89370400440532013000", "DE89 3704 0044 0532 0130 00"),
    (
        "DJ2100010000000154000100186",
        "DJ21 0001 0000 0001 5400 0100 186",
    ),
    ("DK5000400440116243", "DK50 0040 0440 1162 43"),
    (
        "DO28BAGR00000001212453611324",
        "DO28 BAGR 0000 0001 2124 5361 1324",
    ),
    ("EE382200221020145685", "EE38 2200 2210 2014 5685"),
    (
        "EG380019000500000000263180002",
        "EG38 0019 0005 0000 0000 2631 8000 2",
    ),
    ("ES9121000418450200051332", "ES91 2100 0418 4502 0005 1332"),
    ("FI2112345600000785", "FI21 1234 5600 0007 85"),
    ("FK88SC123456789012", "FK88 SC12 3456 7890 12"),
    ("FO6264600001631634", "FO62 6460 0001 6316 34"),
    (
        "FR1420041010050500013M02606",
        "FR14 2004 1010 0505 0001 3M02 606",
    ),
    ("GB29NWBK60161331926819", "GB29 NWBK 6016 1331 9268 19"),
    ("GE29NB0000000101904917", "GE29 NB00 0000 0101 9049 17"),
    ("GI75NWBK000000007099453", "GI75 NWBK 0000 0000 7099 453"),
    ("GL8964710001000206", "GL89 6471 0001 0002 06"),
    (
        "GR1601101250000000012300695",
        "GR16 0110 1250 0000 0001 2300 695",
    ),
    (
        "GT82TRAJ01020000001210029690",
        "GT82 TRAJ 0102 0000 0012 1002 9690",
    ),
    (
        "HN88CABF00000000000250005469",
        "HN88 CABF 0000 0000 0002 5000 5469",
    ),
    ("HR1210010051863000160", "HR12 1001 0051 8630 0016 0"),
    (
        "HU42117730161111101800000000",
        "HU42 1177 3016 1111 1018 0000 0000",
    ),
    ("IE29AIBK93115212345678", "IE29 AIBK 9311 5212 3456 78"),
    ("IL620108000000099999999", "IL62 0108 0000 0009 9999 999"),
    ("IQ98NBIQ850123456789012", "IQ98 NBIQ 8501 2345 6789 012"),
    (
        "IS140159260076545510730339",
        "IS14 0159 2600 7654 5510 7303 39",
    ),
    (
        "IT60X0542811101000000123456",
        "IT60 X054 2811 1010 0000 0123 456",
    ),
    (
        "JO94CBJO0010000000000131000302",
        "JO94 CBJO 0010 0000 0000 0131 0003 02",
    ),
    (
        "KW81CBKU0000000000001234560101",
        "KW81 CBKU 0000 0000 0000 1234 5601 01",
    ),
    ("KZ86125KZT5004100100", "KZ86 125K ZT50 0410 0100"),
    (
        "LB62099900000001001901229114",
        "LB62 0999 0000 0001 0019 0122 9114",
    ),
    (
        "LC55HEMM000100010012001200023015",
        "LC55 HEMM 0001 0001 0012 0012 0002 3015",
    ),
    ("LI21088100002324013AA", "LI21 0881 0000 2324 013A A"),
    ("LT121000011101001000", "LT12 1000 0111 0100 1000"),
    ("LU280019400644750000", "LU28 0019 4006 4475 0000"),
    ("LV80BANK0000435195001", "LV80 BANK 0000 4351 9500 1"),
    ("LY83002048000020100120361", "LY83 002 048 000020100120361"),
    (
        "MC5811222000010123456789030",
        "MC58 1122 2000 0101 2345 6789 030",
    ),
    ("MD24AG000225100013104168", "MD24 AG00 0225 1000 1310 4168"),
    ("ME25505000012345678951", "ME25 5050 0001 2345 6789 51"),
    ("MK07250120000058984", "MK07 2501 2000 0058 984"),
    ("MN121234123456789123", "MN12 1234 1234 5678 9123"),
    (
        "MR1300020001010000123456753",
        "MR13 0002 0001 0100 0012 3456 753",
    ),
    (
        "MT84MALT011000012345MTLCAST001S",
        "MT84 MALT 0110 0001 2345 MTLC AST0 01S",
    ),
    (
        "MU17BOMM0101101030300200000MUR",
        "MU17 BOMM 0101 1010 3030 0200 000M UR",
    ),
    (
        "NI45BAPR00000013000003558124",
        "NI45 BAPR 0000 0013 0000 0355 8124",
    ),
    ("NL91ABNA0417164300", "NL91 ABNA 0417 1643 00"),
    ("NO9386011117947", "NO93 8601 1117 947"),
    ("OM810180000001299123456", "OM81 0180 0000 0129 9123 456"),
    ("PK36SCBL0000001123456702", "PK36 SCBL 0000 0011 2345 6702"),
    (
        "PL61109010140000071219812874",
        "PL61 1090 1014 0000 0712 1981 2874",
    ),
    (
        "PS92PALS000000000400123456702",
        "PS92 PALS 0000 0000 0400 1234 5670 2",
    ),
    (
        "PT50000201231234567890154",
        "PT50 0002 0123 1234 5678 9015 4",
    ),
    (
        "QA58DOHB00001234567890ABCDEFG",
        "QA58 DOHB 0000 1234 5678 90AB CDEF G",
    ),
    ("RO49AAAA1B31007593840000", "RO49 AAAA 1B31 0075 9384 0000"),
    ("RS35260005601001611379", "RS35 2600 0560 1001 6113 79"),
    (
        "RU0304452522540817810538091310419",
        "RU03 0445 2522 5408 1781 0538 0913 1041 9",
    ),
    ("SA0380000000608010167519", "SA03 8000 0000 6080 1016 7519"),
    (
        "SC18SSCB11010000000000001497USD",
        "SC18 SSCB 1101 0000 0000 0000 1497 USD",
    ),
    ("SD2129010501234001", "SD21 2901 0501 2340 01"),
    ("SE4550000000058398257466", "SE45 5000 0000 0583 9825 7466"),
    ("SI56263300012039086", "SI56 2633 0001 2039 086"),
    ("SK3112000000198742637541", "SK31 1200 0000 1987 4263 7541"),
    (
        "SM86U0322509800000000270100",
        "SM86 U032 2509 8000 0000 0270 100",
    ),
    ("SO211000001001000100141", "SO21 1000 0010 0100 0100 141"),
    (
        "ST23000100010051845310146",
        "ST23 0001 0001 0051 8453 1014 6",
    ),
    (
        "SV62CENR00000000000000700025",
        "SV 62 CENR 00000000000000700025",
    ),
    ("TL380080012345678910157", "TL38 0080 0123 4567 8910 157"),
    ("TN5910006035183598478831", "TN59 1000 6035 1835 9847 8831"),
    (
        "TR330006100519786457841326",
        "TR33 0006 1005 1978 6457 8413 26",
    ),
    (
        "UA213223130000026007233566001",
        "UA21 3223 1300 0002 6007 2335 6600 1",
    ),
    ("VA59001123000012345678", "VA59 001 1230 0001 2345 678"),
    ("VG96VPVG0000012345678901", "VG96 VPVG 0000 0123 4567 8901"),
    ("XK051212012345678906", "XK05 1212 0123 4567 8906"),
    (
        "YE15CBYE0001018861234567891234",
        "YE15 CBYE 0001 0188 6123 4567 8912 34",
    ),
];

/// Built once: compiling the detector patterns for each of the 356 scans would dominate the
/// test's time.
static PIPELINE: LazyLock<Pipeline> =
    LazyLock::new(|| Pipeline::new(&ScanConfig::default()).unwrap());

/// (class, span) of every finding.
fn found(text: &str) -> Vec<(DataClass, Range<usize>)> {
    PIPELINE
        .scan_text("/messages/0/content", text)
        .unwrap()
        .findings
        .into_iter()
        .map(|f| (f.class, f.span))
        .collect()
}

fn ibans(text: &str) -> Vec<Range<usize>> {
    found(text)
        .into_iter()
        .filter(|(class, _)| *class == DataClass::Iban)
        .map(|(_, span)| span)
        .collect()
}

#[test]
fn every_registry_example_is_one_iban_in_both_formats() {
    assert_eq!(REGISTRY_EXAMPLES.len(), 89);
    for &(electronic, printed) in REGISTRY_EXAMPLES {
        for text in [electronic, printed] {
            assert_eq!(ibans(text), vec![0..text.len()], "{text}");
            // A card, phone or id inside the IBAN is a coincidence of digits (ADR 0010).
            let others: Vec<_> = found(text)
                .into_iter()
                .filter(|(class, _)| {
                    matches!(class, DataClass::Card | DataClass::Phone | DataClass::EsId)
                })
                .collect();
            assert!(others.is_empty(), "{text}: {others:?}");
        }
    }
}

#[test]
fn lower_case_is_accepted() {
    assert_eq!(ibans("es91 2100 0418 4502 0005 1332"), vec![0..29]);
}

#[test]
fn an_iban_in_a_sentence_is_found_without_what_follows() {
    let text = "Cuenta: ES91 2100 0418 4502 0005 1332 1234, gracias.";
    assert_eq!(ibans(text), vec![8..37]);
}

#[test]
fn unknown_countries_and_wrong_lengths_are_not_ibans() {
    for text in [
        // Valid mod 97 is not enough: XX is not in the registry.
        "XX91 2100 0418 4502 0005 1332",
        // One digit more than the 24 of ES.
        "ES91 2100 0418 4502 0005 13320",
        // One digit less.
        "ES91 2100 0418 4502 0005 133",
    ] {
        assert!(ibans(text).is_empty(), "{text}");
    }
}

#[test]
fn an_iban_glued_to_other_characters_is_not_reported() {
    assert!(ibans("ES9121000418450200051332X").is_empty());
    assert!(ibans("XES9121000418450200051332").is_empty());
}

#[test]
fn only_spaces_separate_the_groups_of_an_iban() {
    assert!(ibans("ES91-2100-0418-4502-0005-1332").is_empty());
    assert!(ibans("ES91.2100.0418.4502.0005.1332").is_empty());
}

#[test]
fn check_digits_must_be_digits() {
    // The same account with letters where the check digits go.
    assert!(ibans("ESAB21000418450200051332").is_empty());
}
