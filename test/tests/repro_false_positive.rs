#[tokio::test]
async fn test_false_positive_repro() {
    tokio::spawn(async {
        panic!("This should fail the test but might not!");
    });

    // Give some time for the panic to happen
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

    println!("Test finishing - if it passes, we have a false positive!");
}
