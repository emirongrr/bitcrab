//! Integration tests for the RPC layer.

use bitcrab_net::p2p::message::Magic;
use bitcrab_node::Node;
use serde_json::json;
use std::net::SocketAddr;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_rpc_getblockchaininfo() {
    // 1. Initialize an in-memory node
    let node = Node::in_memory(Magic::Regtest).expect("Failed to create node");

    // 2. Start RPC server on a random port
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener); // Release port so axum can bind it

    node.start_rpc(actual_addr);

    // Give the server a moment to start
    sleep(Duration::from_millis(500)).await;

    // 3. Make an RPC request using reqwest
    let client = reqwest::Client::new();
    let body = json!({
        "jsonrpc": "1.0",
        "id": "test",
        "method": "getblockchaininfo",
        "params": []
    });

    let res = client
        .post(format!("http://{}", actual_addr))
        .json(&body)
        .send()
        .await
        .expect("Failed to send RPC request");

    assert!(res.status().is_success());

    let json: serde_json::Value = res.json().await.expect("Failed to parse response");

    // 4. Verify fields
    let result = &json["result"];
    assert_eq!(result["blocks"], 0);
    assert!(result["bestblockhash"].is_string());
    assert_eq!(result["chain"], "regtest");
}

#[tokio::test]
async fn test_rpc_getnetworkinfo() {
    let node = Node::in_memory(Magic::Regtest).expect("Failed to create node");
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    drop(listener);

    node.start_rpc(actual_addr);
    sleep(Duration::from_millis(500)).await;

    let client = reqwest::Client::new();
    let body = json!({
        "jsonrpc": "1.0",
        "id": "test",
        "method": "getnetworkinfo",
        "params": []
    });

    let res = client
        .post(format!("http://{}", actual_addr))
        .json(&body)
        .send()
        .await
        .expect("Failed to send RPC request");

    assert!(res.status().is_success());

    let json: serde_json::Value = res.json().await.expect("Failed to parse response");
    let result = &json["result"];

    assert!(result["subversion"].as_str().unwrap().contains("bitcrab"));
    assert_eq!(result["protocolversion"], 70016);
}
