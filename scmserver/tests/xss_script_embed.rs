// xss_script_embed.rs — data embedded in <script> blocks must not be able to
// close the block.
//
// The Systems page embeds the container inventory as JSON inside
// <script type="application/json">. Container names arrive from an agent
// heartbeat, and JSON does not escape "/", so a container named
// `</script><img src=x onerror=...>` closed the block and executed as HTML in
// an administrator's session — a monitored host attacking the console.

#[test]
fn a_script_tag_in_agent_data_cannot_escape_the_block() {
    let hostile = r#"</script><img src=x onerror=alert(1)>"#;
    let json = serde_json::to_string(&serde_json::json!({ "name": hostile })).unwrap();

    // Plain JSON is NOT safe here — this is the bug, asserted so the test
    // fails loudly if someone "simplifies" the escaping away.
    assert!(json.contains("</script>"), "premise changed: serde now escapes '/'");

    let safe = scmserver::handlers::escape_json_for_script(&json);
    assert!(!safe.contains("</script>"), "escaped output still closes the script block");
    assert!(!safe.contains('<') && !safe.contains('>'), "angle brackets must not survive");
}

// The escaping must survive a round trip: JSON.parse turns < back into
// '<', so the displayed name is unchanged — this is an encoding fix, not
// sanitisation, and must not mangle legitimate names.
#[test]
fn escaping_preserves_the_value() {
    let name = "web<1> & co";
    let json = serde_json::to_string(&serde_json::json!({ "name": name })).unwrap();
    let safe = scmserver::handlers::escape_json_for_script(&json);

    let parsed: serde_json::Value = serde_json::from_str(&safe).expect("still valid JSON");
    assert_eq!(parsed["name"], name, "escaping changed the value");
}

// The vulnerable site itself must go through the helper.
#[test]
fn the_systems_page_escapes_its_container_json() {
    let src = include_str!("../src/systems.rs");
    // Exactly the construction region: from the binding to the point the value
    // is handed to the template. An arbitrary byte window silently passes when
    // the code moves, which is how this test failed to mean anything at first.
    let start = src.find("let containers_by_system_json").expect("binding must exist");
    let end = src[start..]
        .find(r#"context.insert("containers_by_system_json""#)
        .expect("value must reach the template") + start;
    let region = &src[start..end];
    assert!(
        region.contains("escape_json_for_script"),
        "containers_by_system_json must be escaped before it reaches the template"
    );
}
