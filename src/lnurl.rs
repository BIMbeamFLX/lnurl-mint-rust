//! The HTTP side: LNURL endpoints, always answering 200 with LUD-01's
//! `{"status": "ERROR", "reason"}` on failure.

use axum::{
    Json, Router,
    extract::{Path, RawQuery, State},
    http::{HeaderMap, header},
    response::{Html, IntoResponse, Response},
    routing::get,
};
use serde_json::{Value, json};

use crate::{
    mint::{MintError, MintResult},
    state::AppState,
};

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(frontend))
        .route("/.well-known/lnurlp/{username}", get(lnurlp))
        .route("/.well-known/lnurlw/{username}", get(lnurlw))
        .route("/.well-known/nostr.json", get(nostr_json))
        .route("/p/cb", get(pay_callback))
        .route(
            "/p/{username}",
            get(pay_callback_for_username)
                .post(register_username)
                .delete(unregister_username),
        )
        .route("/verify/{payment_hash}", get(verify))
        .route("/w", get(withdraw_request))
        .route("/w/cb", get(withdraw_callback))
        .with_state(state)
}

fn respond(result: MintResult<Value>) -> Response {
    let body = result.unwrap_or_else(|e| json!({"status": "ERROR", "reason": e.reason()}));
    ([(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")], Json(body)).into_response()
}

fn request_host(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::HOST).and_then(|h| h.to_str().ok())
}

/// The query as ordered pairs: `k1` repeats for a merge.
fn query_pairs(query: Option<String>) -> Vec<(String, String)> {
    url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
        .into_owned()
        .collect()
}

fn param<'a>(pairs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    pairs
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

fn amount_param(pairs: &[(String, String)], name: &str) -> MintResult<Option<u64>> {
    match param(pairs, name) {
        None => Ok(None),
        Some(v) => v
            .parse()
            .map(Some)
            .map_err(|_| MintError::Reject(format!("Invalid {name}."))),
    }
}

fn required<'a>(pairs: &'a [(String, String)], name: &str) -> MintResult<&'a str> {
    param(pairs, name).ok_or_else(|| MintError::Reject(format!("Missing {name}.")))
}

async fn lnurlp(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Response {
    respond(state.pay_request(&username, request_host(&headers)))
}

async fn lnurlw(
    State(state): State<AppState>,
    Path(username): Path<String>,
    headers: HeaderMap,
) -> Response {
    respond(state.mint_address(&username, request_host(&headers)))
}

async fn nostr_json(State(state): State<AppState>, RawQuery(query): RawQuery) -> Response {
    let pairs = query_pairs(query);
    respond(state.nip05(param(&pairs, "name")))
}

async fn pay_callback(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let pairs = query_pairs(query);
    respond(pay(&state, None, &pairs, request_host(&headers)))
}

async fn pay_callback_for_username(
    State(state): State<AppState>,
    Path(username): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let pairs = query_pairs(query);
    respond(pay(&state, Some(&username), &pairs, request_host(&headers)))
}

fn pay(
    state: &AppState,
    username: Option<&str>,
    pairs: &[(String, String)],
    host: Option<&str>,
) -> MintResult<Value> {
    if param(pairs, "nostr").is_some() {
        return Err(MintError::Reject(
            "Zaps are not offered for this address.".into(),
        ));
    }
    let amount = amount_param(pairs, "amount")?
        .ok_or_else(|| MintError::Reject("Missing amount.".into()))?;
    state.pay_callback(username, amount, param(pairs, "comment"), host)
}

async fn register_username(
    State(state): State<AppState>,
    Path(username): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let pairs = query_pairs(query);
    respond((|| {
        state.register(
            &username,
            required(&pairs, "cx1")?,
            required(&pairs, "sig")?,
            param(&pairs, "npub"),
            request_host(&headers),
        )
    })())
}

async fn unregister_username(
    State(state): State<AppState>,
    Path(username): Path<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let pairs = query_pairs(query);
    respond(
        required(&pairs, "sig")
            .and_then(|sig| state.unregister(&username, sig, request_host(&headers))),
    )
}

async fn verify(State(state): State<AppState>, Path(payment_hash): Path<String>) -> Response {
    respond(state.verify(&payment_hash.to_ascii_lowercase()))
}

async fn withdraw_request(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    // `amount` and `c` ride along on a note URL; they are ignored here
    let pairs = query_pairs(query);
    respond(state.withdraw_request(
        param(&pairs, "k1"),
        param(&pairs, "p"),
        request_host(&headers),
    ))
}

async fn withdraw_callback(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let pairs = query_pairs(query);
    let host = request_host(&headers).map(str::to_string);
    // every k1 is a run of Bitcoin Core's interpreter: off the async workers
    let result = tokio::task::spawn_blocking(move || {
        if param(&pairs, "p").is_some() {
            return Err(MintError::Reject(
                "p is only accepted at the informational endpoint.".into(),
            ));
        }
        let k1s: Vec<String> = pairs
            .iter()
            .filter(|(k, _)| k == "k1")
            .map(|(_, v)| v.clone())
            .collect();
        state.withdraw_callback(
            &k1s,
            param(&pairs, "pr"),
            amount_param(&pairs, "amount")?,
            param(&pairs, "p1"),
            param(&pairs, "p2"),
            host.as_deref(),
        )
    })
    .await
    .unwrap_or_else(|e| Err(MintError::Internal(e.into())));
    respond(result)
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A one-page frontend: the mint's Lightning Address and LNURL as a QR code.
async fn frontend(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let s = &state.settings;
    let (base, host) = s.public_base_url_and_host(request_host(&headers));
    let address = format!("{}@{host}", s.username);
    let lnurl =
        lnurlcash_core::to_bech32_lnurl(&format!("{base}/.well-known/lnurlp/{}", s.username))
            .map(|l| l.to_ascii_uppercase())
            .unwrap_or_default();
    let qr = qrcode::QrCode::new(format!("lightning:{lnurl}").as_bytes())
        .map(|code| {
            code.render::<qrcode::render::svg::Color>()
                .min_dimensions(240, 240)
                .dark_color(qrcode::render::svg::Color("#111"))
                .light_color(qrcode::render::svg::Color("#fff"))
                .build()
        })
        .unwrap_or_default();
    let outstanding = state
        .store
        .stats()
        .map(|st| st.outstanding_msat / 1000)
        .unwrap_or(0);
    let fees = if s.has_fee() {
        format!(
            "{} msat + {} ppm per mint",
            s.base_fee_msat, s.fee_percent_ppm
        )
    } else {
        "none".into()
    };
    let sunset = if s.sunset_mint {
        "<p class=warn>This mint is winding down: minting and splitting are disabled.</p>"
    } else {
        ""
    };
    Html(format!(
        r#"<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>{title}</title>
<style>
:root{{color-scheme:light dark;--fg:#111;--bg:#fafafa;--muted:#666}}
@media (prefers-color-scheme:dark){{:root{{--fg:#eee;--bg:#161616;--muted:#999}}}}
body{{font:16px/1.5 system-ui,sans-serif;color:var(--fg);background:var(--bg);max-width:36rem;margin:2rem auto;padding:0 16px}}
.qr svg{{width:240px;height:240px;border-radius:8px}} code{{word-break:break-all}} .muted{{color:var(--muted)}} .warn{{color:#c33}}
</style></head><body>
<h1>{title}</h1><p>{description}</p>{sunset}
<p>Pay <b>{address}</b> from a wallet that can attach a LUD-12 comment to mint an
<a href="https://github.com/lnurl/luds/blob/luds/25.md">LNURLcash</a> bearer note.</p>
<div class=qr><a href="lightning:{lnurl}">{qr}</a></div>
<p><code>{lnurl}</code></p>
<p class=muted>Mint fee: {fees} &middot; Outstanding notes: {outstanding} sat</p>
</body></html>"#,
        title = escape(&s.title),
        description = escape(&s.description),
    ))
    .into_response()
}

/// The protocol over HTTP, for everything that needs no Lightning: notes are
/// credited straight into the store, as a settled mint invoice would.
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{body::Body, http::Request};
    use http_body_util::BodyExt;
    use lnurlcash_core::{
        recoverable::{
            PURPOSE_WALLET, derive_note_secret_key, encode_ck1, encode_cp1, encode_cx1,
            sign_note_ownership,
        },
        signature::{sign_address_proof, verify_note_signature_hash},
    };
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    use super::*;
    use crate::{
        db::{INVALID_K1, NoteStore},
        ln::{Ln, Network},
        spend,
        state::test_settings,
        vectors::{certifies_rotation, cr1_signature},
    };

    fn app() -> AppState {
        AppState::new(
            test_settings(),
            std::sync::Arc::new(NoteStore::in_memory().unwrap()),
            Ln::new(Network::Regtest),
        )
    }

    async fn call(state: &AppState, method: &str, uri: &str) -> Value {
        let req = Request::builder()
            .method(method)
            .uri(uri)
            .header(header::HOST, "mint.example")
            .body(Body::empty())
            .unwrap();
        let res = router(state.clone()).oneshot(req).await.unwrap();
        assert_eq!(res.status(), 200, "LUD-01: errors are 200s too");
        let body = res.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&body).unwrap()
    }

    async fn get(state: &AppState, uri: &str) -> Value {
        call(state, "GET", uri).await
    }

    fn reason(v: &Value) -> &str {
        assert_eq!(v["status"], "ERROR", "{v}");
        v["reason"].as_str().unwrap()
    }

    fn ok(v: &Value) {
        assert_eq!(v["status"], "OK", "{v}");
    }

    /// A bearer note: its spend (the preimage, hex) and its reference (`h`).
    fn bearer(seed: u8) -> (String, String) {
        let preimage = [seed; 32];
        (hex::encode(preimage), hex::encode(Sha256::digest(preimage)))
    }

    /// Credit the note `h` names with `amount_msat`, as a paid mint would.
    fn credit(state: &AppState, h: &str, amount_msat: u64) {
        let note_id = spend::note_id_of_ref(h).unwrap();
        let payment_hash = hex::encode(Sha256::digest(h.as_bytes()));
        state
            .store
            .create_mint(&payment_hash, "lnbcrt1", amount_msat, &note_id)
            .unwrap();
        state.store.settle_mint(&payment_hash).unwrap();
    }

    async fn value_of(state: &AppState, k1: &str) -> Value {
        get(state, &format!("/w?k1={k1}")).await["maxWithdrawable"].clone()
    }

    /// The node key of the mints that sign their certificates.
    const NODE_KEY: [u8; 32] = [7; 32];

    /// A mint on `store` that signs, except messages starting with `refused`.
    fn signing_on(store: Arc<NoteStore>, refused: Option<&'static str>) -> AppState {
        let ln = Ln::signing(Network::Regtest, NODE_KEY, refused);
        AppState::new(test_settings(), store, ln)
    }

    /// The node id their certificates verify against.
    fn node_id() -> String {
        let key = secp256k1::SecretKey::from_secret_bytes(NODE_KEY).unwrap();
        hex::encode(key.public_key().serialize())
    }

    /// A mint that signs its certificates, with the node id they verify against.
    fn signing_app() -> (AppState, String) {
        let store = Arc::new(NoteStore::in_memory().unwrap());
        (signing_on(store, None), node_id())
    }

    fn note_id(h: &str) -> String {
        spend::note_id_of_ref(h).unwrap()
    }

    /// A key-path note: its spend at this mint (`ck1`), its reference (`cp1`)
    /// and its id, `hex(Q)`.
    fn key_path(seed: u8) -> (String, String, String) {
        let secret = [seed; 32];
        let q = secp256k1::Keypair::from_secret_bytes(secret)
            .unwrap()
            .x_only_public_key()
            .0
            .to_byte_array();
        let ck1 = encode_ck1(&sign_note_ownership(&secret, "mint.example").unwrap());
        (ck1, encode_cp1(&q), hex::encode(q))
    }

    #[tokio::test]
    async fn the_informational_request_never_burns() {
        let state = app();
        let (k1, h) = bearer(1);
        credit(&state, &h, 50_000);
        for _ in 0..2 {
            let v = get(&state, &format!("/w?k1={k1}&amount=999")).await;
            assert_eq!(v["tag"], "withdrawRequest");
            assert_eq!(v["k1"], k1, "echoes the secret it was queried with");
            assert_eq!(v["maxWithdrawable"], 50_000);
            assert_eq!(v["callback"], "https://mint.example/w/cb");
        }
        assert_eq!(
            get(&state, &format!("/w?p={h}")).await["maxWithdrawable"],
            50_000
        );
        assert_eq!(reason(&get(&state, "/w?k1=00").await), "Unknown note.");
    }

    #[tokio::test]
    async fn rotate_burns_and_answers_a_retry_with_the_same_result() {
        let state = app();
        let (k1, h) = bearer(1);
        let (k1b, hb) = bearer(2);
        credit(&state, &h, 50_000);
        let uri = format!("/w/cb?k1={k1}&p1={hb}");
        ok(&get(&state, &uri).await);
        assert_eq!(value_of(&state, &k1b).await, 50_000);
        // the same request again is the same rotate, not a double spend
        ok(&get(&state, &uri).await);
        assert_eq!(value_of(&state, &k1b).await, 50_000);
        // into anything else, the burned note is gone
        let (_, hc) = bearer(3);
        let again = get(&state, &format!("/w/cb?k1={k1}&p1={hc}")).await;
        assert_eq!(reason(&again), INVALID_K1);
        assert_eq!(
            reason(&get(&state, &format!("/w?k1={k1}")).await),
            "Note already spent."
        );
    }

    #[tokio::test]
    async fn a_rotate_is_certified_from_note_to_note() {
        let (state, mint) = signing_app();
        let (k1, h) = bearer(1);
        let (_, hb) = bearer(2);
        let (_, hc) = bearer(3);
        credit(&state, &h, 50_000);
        let uri = format!("/w/cb?k1={k1}&p1={hb}");
        let rotated = get(&state, &uri).await;
        ok(&rotated);
        let r = rotated["r"].as_str().unwrap();
        assert!(r.starts_with("cr500n1"), "{r}");
        let (spent, new) = (note_id(&h), note_id(&hb));
        assert!(certifies_rotation(&mint, &spent, &new, 50_000, r));
        // never another amount, the way back, or a look-alike minted on the side
        assert!(!certifies_rotation(&mint, &spent, &new, 50_001, r));
        assert!(!certifies_rotation(&mint, &new, &spent, 50_000, r));
        assert!(!certifies_rotation(&mint, &spent, &note_id(&hc), 50_000, r));
        // `c` is the new note's own certificate. Either is refused where the
        // other belongs by its prefix alone, before any signature is looked at
        let c = rotated["c"].as_str().unwrap();
        assert!(verify_note_signature_hash(&new, 50_000, c, &mint));
        assert!(!verify_note_signature_hash(&new, 50_000, r, &mint));
        assert!(!certifies_rotation(&mint, &spent, &new, 50_000, c));
        // and `r`'s bare signature certifies neither of the notes it names
        let bare = hex::encode(cr1_signature(r).unwrap());
        assert!(!verify_note_signature_hash(&new, 50_000, &bare, &mint));
        assert!(!verify_note_signature_hash(&spent, 50_000, &bare, &mint));
        // no table of its own: an exact retry reads the burn on record and is
        // signed again, to the same bytes by this deterministic signer
        assert_eq!(get(&state, &uri).await, rotated);
    }

    #[tokio::test]
    async fn rotation_certificates_chain_step_by_step() {
        let (state, mint) = signing_app();
        let (k1a, ha) = bearer(1);
        let (k1b, hb) = bearer(2);
        let (_, hc) = bearer(3);
        credit(&state, &ha, 50_000);
        let ab = get(&state, &format!("/w/cb?k1={k1a}&p1={hb}")).await;
        let bc = get(&state, &format!("/w/cb?k1={k1b}&p1={hc}")).await;
        let (ab, bc) = (ab["r"].as_str().unwrap(), bc["r"].as_str().unwrap());
        let (a, b, c) = (note_id(&ha), note_id(&hb), note_id(&hc));
        let certifies =
            |r: &str, from: &str, to: &str| certifies_rotation(&mint, from, to, 50_000, r);
        // each certifies its own step
        assert!(certifies(ab, &a, &b) && certifies(bc, &b, &c));
        // and no other: not the step beside it, nor a shortcut past B
        assert!(!certifies(ab, &b, &c) && !certifies(bc, &a, &b));
        assert!(!certifies(ab, &a, &c) && !certifies(bc, &a, &c));
    }

    #[tokio::test]
    async fn a_key_path_note_is_certified_by_its_output_key() {
        // a signature spends these notes, no preimage: Q names them all the same
        let (state, mint) = signing_app();
        let (ck1, cp1, q) = key_path(3);
        let (ck1b, cp1b, qb) = key_path(4);
        let (_, h) = bearer(5);
        credit(&state, &cp1, 50_000);
        let rotated = get(&state, &format!("/w/cb?k1={ck1}&p1={cp1b}")).await;
        let r = rotated["r"].as_str().unwrap();
        assert!(certifies_rotation(&mint, &q, &qb, 50_000, r));
        // and on from there, into a bearer note
        let rotated = get(&state, &format!("/w/cb?k1={ck1b}&p1={h}")).await;
        let r = rotated["r"].as_str().unwrap();
        assert!(certifies_rotation(&mint, &qb, &note_id(&h), 50_000, r));
    }

    #[tokio::test]
    async fn only_a_rotate_gets_a_rotation_certificate() {
        let (state, _) = signing_app();
        let (k1, h) = bearer(1);
        let (k1a, ha) = bearer(2);
        let (k1b, hb) = bearer(3);
        let (_, hc) = bearer(4);
        credit(&state, &h, 50_000);
        // asking about a note rotates nothing
        let info = get(&state, &format!("/w?k1={k1}")).await;
        assert!(info["c"].is_string() && info.get("r").is_none(), "{info}");
        // a split: two notes came out of one, and neither is the note it became
        let split = format!("/w/cb?k1={k1}&amount=20000&p1={ha}&p2={hb}");
        // a merge: no one note became the new one
        let merge = format!("/w/cb?k1={k1a}&k1={k1b}&p1={hc}");
        for uri in [split, merge] {
            let first = get(&state, &uri).await;
            ok(&first);
            assert!(
                first["c"].is_string() && first.get("r").is_none(),
                "{first}"
            );
            // nor does a retry of either
            assert_eq!(get(&state, &uri).await, first);
        }
        // and neither is replayed as a rotate of one of its notes into one of its outputs
        for uri in [
            format!("/w/cb?k1={k1}&p1={ha}"),
            format!("/w/cb?k1={k1a}&p1={hc}"),
        ] {
            assert_eq!(reason(&get(&state, &uri).await), INVALID_K1);
        }
    }

    #[tokio::test]
    async fn a_rotation_certificate_lost_to_its_signing_comes_with_a_retry() {
        // one store, and a node that signs no rotation until it is back
        let store = Arc::new(NoteStore::in_memory().unwrap());
        let down = signing_on(store.clone(), Some("LNURLcash:rotate:"));
        let (up, mint) = (signing_on(store, None), node_id());
        let (k1, h) = bearer(1);
        let (_, hb) = bearer(2);
        credit(&down, &h, 50_000);
        let uri = format!("/w/cb?k1={k1}&p1={hb}");
        // the rotate stands and the new note is certified, without its `r`
        let first = get(&down, &uri).await;
        ok(&first);
        assert!(
            first["c"].is_string() && first.get("r").is_none(),
            "{first}"
        );
        // the same request again is how the rest is had
        let retried = get(&up, &uri).await;
        assert_eq!(retried["c"], first["c"]);
        let r = retried["r"].as_str().unwrap();
        assert!(certifies_rotation(
            &mint,
            &note_id(&h),
            &note_id(&hb),
            50_000,
            r
        ));
    }

    #[tokio::test]
    async fn a_rotate_no_one_could_sign_still_stands() {
        // no node, no signature: the note moved all the same
        let state = app();
        let (k1, h) = bearer(1);
        let (k1b, hb) = bearer(2);
        credit(&state, &h, 50_000);
        let rotated = get(&state, &format!("/w/cb?k1={k1}&p1={hb}")).await;
        assert_eq!(rotated, json!({"status": "OK"}));
        assert_eq!(value_of(&state, &k1b).await, 50_000);
    }

    #[tokio::test]
    async fn split_takes_the_base_fee_from_the_change() {
        let state = app();
        let (k1, h) = bearer(1);
        let (k1a, ha) = bearer(2);
        let (k1b, hb) = bearer(3);
        credit(&state, &h, 50_000);
        let v = get(
            &state,
            &format!("/w/cb?k1={k1}&amount=20000&p1={ha}&p2={hb}"),
        )
        .await;
        ok(&v);
        assert_eq!(value_of(&state, &k1a).await, 20_000);
        assert_eq!(value_of(&state, &k1b).await, 50_000 - 20_000 - 1000);
    }

    #[tokio::test]
    async fn split_bounds() {
        let state = app();
        let (k1, h) = bearer(1);
        let (_, ha) = bearer(2);
        let (_, hb) = bearer(3);
        credit(&state, &h, 50_000);
        let at = |amount: &str| format!("/w/cb?k1={k1}&amount={amount}&p1={ha}&p2={hb}");
        assert!(reason(&get(&state, &at("0")).await).starts_with("amount must be between"));
        assert!(reason(&get(&state, &at("50000")).await).starts_with("amount must be between"));
        assert_eq!(
            reason(&get(&state, &at("49500")).await),
            "insufficient value"
        );
        assert_eq!(
            reason(&get(&state, &format!("/w/cb?k1={k1}&amount=100&p1={ha}")).await),
            "missing p2"
        );
        // nothing above burned anything
        assert_eq!(value_of(&state, &k1).await, 50_000);
    }

    #[tokio::test]
    async fn merge_refunds_the_split_fees() {
        let state = app();
        let (k1a, ha) = bearer(1);
        let (k1b, hb) = bearer(2);
        let (k1c, hc) = bearer(3);
        credit(&state, &ha, 30_000);
        credit(&state, &hb, 19_000);
        ok(&get(&state, &format!("/w/cb?k1={k1a}&k1={k1b}&p1={hc}")).await);
        assert_eq!(value_of(&state, &k1c).await, 30_000 + 19_000 + 1000);
    }

    #[tokio::test]
    async fn one_bad_k1_and_nothing_happens() {
        let state = app();
        let (k1a, ha) = bearer(1);
        let (k1b, _) = bearer(2);
        let (_, hc) = bearer(3);
        credit(&state, &ha, 30_000);
        let v = get(&state, &format!("/w/cb?k1={k1a}&k1={k1b}&p1={hc}")).await;
        assert_eq!(reason(&v), INVALID_K1);
        assert_eq!(value_of(&state, &k1a).await, 30_000);
        // and naming one note twice is no merge either
        let v = get(&state, &format!("/w/cb?k1={k1a}&k1={k1a}&p1={hc}")).await;
        assert_eq!(reason(&v), INVALID_K1);
        assert_eq!(value_of(&state, &k1a).await, 30_000);
    }

    #[tokio::test]
    async fn outputs_must_be_fresh_and_present() {
        let state = app();
        let (k1a, ha) = bearer(1);
        let (_, hb) = bearer(2);
        credit(&state, &ha, 30_000);
        credit(&state, &hb, 30_000);
        let v = get(&state, &format!("/w/cb?k1={k1a}&p1={hb}")).await;
        assert_eq!(reason(&v), "already in use");
        assert_eq!(
            reason(&get(&state, &format!("/w/cb?k1={k1a}")).await),
            "missing p1"
        );
        let v = get(&state, &format!("/w/cb?k1={k1a}&p1={hb}&p=x")).await;
        assert!(reason(&v).starts_with("p is only accepted"));
        assert_eq!(value_of(&state, &k1a).await, 30_000);
    }

    #[tokio::test]
    async fn sunset_refuses_splits_but_not_rotates() {
        let mut settings = test_settings();
        settings.sunset_mint = true;
        let state = AppState::new(
            settings,
            std::sync::Arc::new(NoteStore::in_memory().unwrap()),
            Ln::new(Network::Regtest),
        );
        let (k1, h) = bearer(1);
        let (_, ha) = bearer(2);
        let (_, hb) = bearer(3);
        credit(&state, &h, 50_000);
        let v = get(&state, &format!("/w/cb?k1={k1}&amount=100&p1={ha}&p2={hb}")).await;
        assert!(reason(&v).contains("sunsetting"));
        let v = get(&state, &format!("/p/cb?amount=20000&comment={ha}")).await;
        assert!(reason(&v).contains("sunsetting"));
        ok(&get(&state, &format!("/w/cb?k1={k1}&p1={ha}")).await);
    }

    #[tokio::test]
    async fn no_node_no_mint_and_no_melt_and_no_reservation() {
        let state = app();
        let (k1, h) = bearer(1);
        let (_, hb) = bearer(2);
        credit(&state, &h, 50_000);
        let v = get(&state, &format!("/p/cb?amount=20000&comment={hb}")).await;
        assert_eq!(reason(&v), "Minting is temporarily unavailable.");
        let v = get(&state, &format!("/w/cb?k1={k1}&pr=lnbcrt1")).await;
        assert_eq!(reason(&v), "Melting is temporarily unavailable.");
        // the note was never reserved
        assert_eq!(value_of(&state, &k1).await, 50_000);
        let v = get(&state, &format!("/w/cb?k1={k1}&k1={k1}&pr=lnbcrt1")).await;
        assert!(reason(&v).starts_with("pr cannot be combined"));
    }

    #[tokio::test]
    async fn the_fixed_identity_answers_to_its_name_and_to_underscore() {
        let state = app();
        for name in ["mint", "MINT", "_"] {
            let v = get(&state, &format!("/.well-known/lnurlp/{name}")).await;
            assert_eq!(v["tag"], "payRequest");
            assert_eq!(v["callback"], "https://mint.example/p/cb");
            assert_eq!(v["commentAllowed"], 64);
            assert_eq!(v["withdrawLink"], "https://mint.example/w");
            let metadata: Value = serde_json::from_str(v["metadata"].as_str().unwrap()).unwrap();
            assert!(metadata.to_string().contains("Mint fees: 1000,2000"));
        }
        let v = get(&state, "/.well-known/lnurlp/nobody").await;
        assert_eq!(reason(&v), "Unknown user.");
    }

    #[tokio::test]
    async fn a_registered_address_advertises_its_branch() {
        let state = app();
        let branch_sk = [11u8; 32];
        let chain_code = [2u8; 32];
        let kp = secp256k1::Keypair::from_secret_bytes(branch_sk).unwrap();
        let point = kp.x_only_public_key().0.to_byte_array();
        let cx1 = encode_cx1(&point, &chain_code);
        let sk0 = derive_note_secret_key(&branch_sk, &chain_code, PURPOSE_WALLET, 0).unwrap();
        let sig = |action: &str| {
            hex::encode(sign_address_proof(&sk0, action, "mint.example", "alice").unwrap())
        };
        let npub = "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg";

        let bad = call(
            &state,
            "POST",
            &format!("/p/alice?cx1={cx1}&sig={}", sig("unregister")),
        )
        .await;
        assert_eq!(reason(&bad), "Invalid ownership signature.");
        let reg = format!("/p/alice?cx1={cx1}&sig={}&npub={npub}", sig("register"));
        ok(&call(&state, "POST", &reg).await);

        let v = get(&state, "/.well-known/lnurlp/Alice").await;
        assert_eq!(v["callback"], "https://mint.example/p/alice");
        assert!(v.get("commentAllowed").is_none());
        assert!(
            v["metadata"]
                .as_str()
                .unwrap()
                .contains(&format!("{cx1}:0"))
        );
        let v = get(&state, "/.well-known/nostr.json?name=alice").await;
        assert_eq!(
            v["names"]["alice"],
            "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e"
        );

        let reserved = call(&state, "POST", &format!("/p/mint?cx1={cx1}&sig=00")).await;
        assert_eq!(reason(&reserved), "Invalid or reserved username.");

        ok(&call(
            &state,
            "DELETE",
            &format!("/p/alice?sig={}", sig("unregister")),
        )
        .await);
        assert_eq!(
            reason(&get(&state, "/.well-known/lnurlp/alice").await),
            "Unknown user."
        );
        assert_eq!(
            get(&state, "/.well-known/nostr.json?name=alice").await["names"],
            json!({})
        );
    }

    #[tokio::test]
    async fn verify_knows_only_its_own_invoices() {
        let state = app();
        assert_eq!(
            reason(&get(&state, &format!("/verify/{}", "ab".repeat(32))).await),
            "Not found"
        );
    }

    #[tokio::test]
    async fn the_front_page_renders() {
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();
        let res = router(app()).oneshot(req).await.unwrap();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("mint@mint.example"));
        assert!(html.contains("<svg"));
    }
}
