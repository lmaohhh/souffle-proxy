//! Synthetic acceptance traffic through the production router and real QUIC.
use super::tests::{completed, native_state, request, server, Captured, Reply};
use super::*;
use bytes::Buf;
use std::net::SocketAddr;
use std::sync::Mutex;
use tower::ServiceExt;

#[tokio::test]
async fn native_mounted_routes_forward_all_aliases_and_queries() {
    for prefix in ["/v1/responses", "/responses"] {
        for (suffix, wire) in [
            ("", r#"{"status":"completed","output":[]}"#),
            (
                "/compact",
                r#"{"object":"response.compaction","output":[]}"#,
            ),
            (
                "/input_tokens",
                r#"{"object":"response.input_tokens","input_tokens":7}"#,
            ),
        ] {
            let (addr, captured) = server(Reply {
                status: 200,
                headers: vec![("content-type", "application/json")],
                chunks: vec![Bytes::from_static(wire.as_bytes())],
            })
            .await;
            let state = native_state(&format!("http://{addr}/custom/v1"));
            let response = build_router(state.clone())
                .oneshot(request(
                    &format!("{prefix}{suffix}?fixture=mounted"),
                    r#"{"input":"synthetic fixture"}"#,
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
            assert_eq!(
                axum::body::to_bytes(response.into_body(), 4096)
                    .await
                    .unwrap(),
                wire
            );
            let records = captured.lock().unwrap();
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].path,
                format!("/custom/v1/responses{suffix}?fixture=mounted")
            );
            let payload: Value = serde_json::from_slice(&records[0].body).unwrap();
            assert_eq!(payload["model"], "test-model");
            assert_eq!(payload["input"], "synthetic fixture");
            if suffix.is_empty() {
                assert_eq!(payload["store"], false);
            } else {
                assert!(payload.get("store").is_none());
                assert!(payload.get("reasoning").is_none());
            }
            assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        }
    }
}

#[tokio::test]
async fn native_mounted_methods_stored_operations_and_unknown_routes() {
    let state = native_state("http://127.0.0.1:1/v1");
    let router = build_router(state.clone());
    for prefix in ["/v1/responses", "/responses"] {
        for suffix in ["", "/compact", "/input_tokens"] {
            let path = format!("{prefix}{suffix}");
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(Method::OPTIONS)
                        .uri(&path)
                        .header(header::ORIGIN, "https://client.example")
                        .header(header::ACCESS_CONTROL_REQUEST_METHOD, "POST")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{path}");
            assert_eq!(response.headers()[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
            for method in [Method::GET, Method::PUT, Method::DELETE] {
                let response = router
                    .clone()
                    .oneshot(
                        Request::builder()
                            .method(method)
                            .uri(&path)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED, "{path}");
                assert!(response.headers()[header::ALLOW]
                    .to_str()
                    .unwrap()
                    .contains("POST"));
            }
        }
        for (method, suffix) in [
            (Method::GET, "/resp_old"),
            (Method::DELETE, "/resp_old"),
            (Method::GET, "/resp_old/input_items"),
            (Method::POST, "/resp_old/cancel"),
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(format!("{prefix}{suffix}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let body = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let error: Value = serde_json::from_slice(&body).unwrap();
            assert!(error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("stateless"));
        }
        let response = router
            .clone()
            .oneshot(request(&format!("{prefix}/typo"), "{}"))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let error: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(error["error"]["code"], "404");
    }
    assert_eq!(state.stats.total_requests.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn native_mounted_mixed_slots_use_virtual_model_ids() {
    let (chat_addr, chat_calls) = server(Reply {
        status: 200,
        headers: vec![("content-type", "application/json")],
        chunks: vec![Bytes::from_static(
            br#"{"choices":[{"message":{"content":"chat fixture"},"finish_reason":"stop"}]}"#,
        )],
    })
    .await;
    let (native_addr, native_calls) = server(Reply {
        status: 200,
        headers: vec![("content-type", "application/json")],
        chunks: vec![Bytes::from_static(br#"{"status":"completed","output":[]}"#)],
    })
    .await;
    let mut state = crate::tests::make_test_app_state(&format!("http://{chat_addr}/v1"), false, 1);
    let native = native_state(&format!("http://{native_addr}/v1"));
    Arc::get_mut(&mut state)
        .unwrap()
        .slots
        .push(native.slots[0].clone());
    let router = build_router(state.clone());
    for (path, body, expected) in [
        (
            "/v1/chat/completions",
            r#"{"model":"deepseek-souffle","messages":[{"role":"user","content":"fixture"}]}"#,
            StatusCode::OK,
        ),
        (
            "/v1/responses",
            r#"{"model":"deepseek-sol","input":"fixture"}"#,
            StatusCode::OK,
        ),
        (
            "/v1/chat/completions",
            r#"{"model":"deepseek-sol","messages":[]}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "/v1/responses",
            r#"{"model":"actual-gpt-model","input":"fixture"}"#,
            StatusCode::BAD_REQUEST,
        ),
        (
            "/v1/responses",
            r#"{"input":"fixture"}"#,
            StatusCode::BAD_REQUEST,
        ),
    ] {
        let response = router.clone().oneshot(request(path, body)).await.unwrap();
        assert_eq!(response.status(), expected, "{body}");
        axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
    }
    assert_eq!(chat_calls.lock().unwrap().len(), 1);
    assert_eq!(native_calls.lock().unwrap().len(), 1);
    assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 2);
    assert_eq!(state.stats.error_count.load(Ordering::Relaxed), 3);
    assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
    assert_eq!(state.semaphore.available_permits(), 20);
}

struct H3Fixture {
    addr: SocketAddr,
    captured: Arc<Mutex<Vec<Captured>>>,
    endpoint: quinn::Endpoint,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for H3Fixture {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"fixture complete");
        self.task.abort();
    }
}

fn h3_server(reply: Reply, tail_gate: Option<Arc<Semaphore>>) -> H3Fixture {
    let endpoint = quinn::Endpoint::server(
        upstream::tests::h3_server_config(),
        "127.0.0.1:0".parse().unwrap(),
    )
    .unwrap();
    let addr = endpoint.local_addr().unwrap();
    let captured = Arc::new(Mutex::new(Vec::new()));
    let records = captured.clone();
    let listener = endpoint.clone();
    let task = tokio::spawn(async move {
        while let Some(incoming) = listener.accept().await {
            let records = records.clone();
            let reply = reply.clone();
            let tail_gate = tail_gate.clone();
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok(mut connection) =
                    h3::server::Connection::new(h3_quinn::Connection::new(connection)).await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = connection.accept().await {
                    let records = records.clone();
                    let reply = reply.clone();
                    let tail_gate = tail_gate.clone();
                    tokio::spawn(async move {
                        let Ok((request, mut stream)) = resolver.resolve_request().await else {
                            return;
                        };
                        let mut body = Vec::new();
                        while let Ok(Some(mut chunk)) = stream.recv_data().await {
                            body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
                        }
                        records.lock().unwrap().push(Captured {
                            path: request.uri().path_and_query().unwrap().to_string(),
                            headers: request.into_parts().0.headers,
                            body,
                        });
                        let mut response = http::Response::builder().status(reply.status);
                        for (name, value) in &reply.headers {
                            response = response.header(*name, *value);
                        }
                        if stream
                            .send_response(response.body(()).unwrap())
                            .await
                            .is_err()
                        {
                            return;
                        }
                        for (index, chunk) in reply.chunks.iter().enumerate() {
                            if index == 1 {
                                if let Some(gate) = &tail_gate {
                                    let _ = gate.acquire().await;
                                }
                            }
                            if stream.send_data(chunk.clone()).await.is_err() {
                                return;
                            }
                        }
                        let _ = stream.finish().await;
                    });
                }
            });
        }
    });
    H3Fixture {
        addr,
        captured,
        endpoint,
        task,
    }
}

fn h3_state(addr: SocketAddr) -> Arc<AppState> {
    let base = format!("https://{addr}/custom/v1");
    let mut state = native_state(&base);
    let slot = Arc::get_mut(&mut Arc::get_mut(&mut state).unwrap().slots[0]).unwrap();
    Arc::get_mut(&mut slot.config).unwrap().http3_enabled = true;
    slot.client = UpstreamClient::H3(H3Client::new(&base, Duration::from_secs(5), true).unwrap());
    state
}

#[tokio::test]
async fn native_h3_buffered_sse_and_errors_preserve_wire_and_never_replay() {
    let sse = format!(
        "event: future.event\ndata: {{\"type\":\"future.event\",\"opaque\":\"\\u0041\"}}\n\n{}",
        completed()
    );
    for (status, content_type, wire, streaming) in [
        (200, "application/json", r#"{"status":"completed","output":[ {"type":"reasoning","encrypted_content":"OPAQUE\\\u0041","summary":[]} ],"future":{"raw":1}}"#.to_owned(), false),
        (200, "text/event-stream", sse, true),
        (429, "application/json", r#"{"error":{"code":"rate_limit_exceeded","message":"synthetic fixture"}}"#.to_owned(), true),
        (524, "application/json", r#"{"error":{"code":"provider_timeout","message":"synthetic fixture"}}"#.to_owned(), false),
    ] {
        let fixture = h3_server(Reply {
            status,
            headers: vec![("content-type", content_type), ("x-request-id", "req-h3-fixture"), ("retry-after", "17")],
            chunks: wire.as_bytes().chunks(7).map(Bytes::copy_from_slice).collect(),
        }, None);
        let state = h3_state(fixture.addr);
        let source = format!(r#"{{"input":[ {{"type":"reasoning","encrypted_content":"OPAQUE\\\u0041","summary":[]}}, {{"role":"user","content":"fixture"}} ],"stream":{streaming}}}"#);
        let original: BTreeMap<String, Box<RawValue>> = serde_json::from_str(&source).unwrap();
        let response = build_router(state.clone()).oneshot(
            request("/v1/responses?fixture=h3", &source),
        ).await.unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["x-request-id"], "req-h3-fixture");
        assert_eq!(response.headers()["retry-after"], "17");
        assert_eq!(axum::body::to_bytes(response.into_body(), 8192).await.unwrap(), wire);
        let records = fixture.captured.lock().unwrap();
        assert_eq!(records.len(), 1, "native status {status} must not replay");
        assert_eq!(records[0].path, "/custom/v1/responses?fixture=h3");
        assert_eq!(records[0].headers[header::USER_AGENT], "Hermes-local-verification");
        assert_eq!(records[0].headers["openai-project"], "project-local-fixture");
        assert_eq!(records[0].headers[header::AUTHORIZATION], "Bearer sk-test");
        assert_eq!(records[0].headers[header::ACCEPT_ENCODING], "identity");
        assert!(!records[0].headers.contains_key("x-hop-fixture"));
        let payload: BTreeMap<String, Box<RawValue>> = serde_json::from_slice(&records[0].body).unwrap();
        assert_eq!(payload["input"].get(), original["input"].get());
        assert_eq!(state.stats.success_count.load(Ordering::Relaxed), u64::from(status == 200));
        assert_eq!(state.stats.error_count.load(Ordering::Relaxed), u64::from(status != 200));
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.semaphore.available_permits(), 20);
    }
}

#[tokio::test]
async fn native_h3_polled_disconnect_and_idle_timeout_release_slots() {
    for idle_timeout in [false, true] {
        let gate = Arc::new(Semaphore::new(0));
        let first = Bytes::from_static(
            b"event: response.created\ndata: {\"type\":\"response.created\"}\n\n",
        );
        let fixture = h3_server(
            Reply {
                status: 200,
                headers: vec![("content-type", "text/event-stream")],
                chunks: vec![first.clone(), Bytes::from_static(completed().as_bytes())],
            },
            Some(gate.clone()),
        );
        let mut state = h3_state(fixture.addr);
        if idle_timeout {
            let slot = Arc::get_mut(&mut Arc::get_mut(&mut state).unwrap().slots[0]).unwrap();
            // The short deadline should measure an idle body, not a cold QUIC handshake.
            slot.client.prewarm().await.unwrap();
            Arc::get_mut(&mut slot.config).unwrap().read_timeout = Duration::from_millis(100);
        }
        let response = build_router(state.clone())
            .oneshot(request(
                "/v1/responses",
                r#"{"input":"fixture","stream":true}"#,
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body().into_data_stream();
        assert_eq!(body.next().await.unwrap().unwrap(), first);
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 1);
        assert_eq!(state.semaphore.available_permits(), 19);
        if idle_timeout {
            let next = tokio::time::timeout(Duration::from_secs(2), body.next())
                .await
                .unwrap();
            assert!(
                next.unwrap().is_err(),
                "idle SSE must break the downstream transfer"
            );
        }
        drop(body);
        assert_eq!(state.stats.active_requests.load(Ordering::Relaxed), 0);
        assert_eq!(state.semaphore.available_permits(), 20);
        // A caller cancellation is neutral; an upstream idle timeout is a failure.
        assert_eq!(
            state.stats.error_count.load(Ordering::Relaxed),
            u64::from(idle_timeout)
        );
        assert_eq!(state.stats.success_count.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.captured.lock().unwrap().len(), 1);
        gate.add_permits(1);
    }
}
