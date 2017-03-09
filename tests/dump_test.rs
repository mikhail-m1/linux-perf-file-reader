use std::io::Read;

#[test]
fn test_chdir() {
    let output = std::process::Command::new("target/debug/examples/dump")
        .arg("tests/perf.data")
        .output()
        .expect("failed to run dump example");

    let mut expected = Vec::new();

    std::fs::File::open("tests/dump.stdout").expect("cannot open dump.stdout")
        .read_to_end(&mut expected).expect("cannot read dump.stdout");

    assert_eq!(expected, output.stdout);
}
