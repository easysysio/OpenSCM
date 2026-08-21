// tour_preview.rs — renders the tour partial to a standalone HTML file so the
// modal can be looked at without standing up the whole server.
//
// Ignored by default: it writes a file and exists for eyeballing, not for CI.
//   cargo test -p scmserver --test tour_preview -- --ignored --nocapture
use tera::Context;

#[test]
#[ignore]
fn render_tour_preview() {
    let tera = scmserver::init_tera().expect("templates parse");

    for (name, server_url, has_token, screens) in [
        ("tour_admin.html", "https://scm.example.com", true, vec![1u8, 2, 3, 4, 5]),
        ("tour_runner.html", "", false, vec![1u8, 4, 5]),
    ] {
        let mut ctx = Context::new();
        ctx.insert("show_tour", &true);
        ctx.insert(
            "tour",
            &serde_json::json!({
                "server_url": server_url,
                "has_token": has_token,
                "screens": screens,
            }),
        );
        let body = tera
            .render("partials/tour.html", &ctx)
            .expect("tour partial renders");

        let page = format!(
            r#"<!doctype html><html><head><meta charset="utf-8">
<link rel="stylesheet" href="/scmserver/static/plugins/fontawesome-free/css/all.min.css">
<link rel="stylesheet" href="/scmserver/static/dist/css/adminlte.min.css">
<style>body{{padding:2rem;background:#f4f6f9}}</style>
<!-- Loaded in <head> because the partial's inline script needs jQuery already
     present. base.html satisfies this by loading jQuery at line ~326, well
     before the tour include near the end of the document. -->
<script src="/scmserver/static/plugins/jquery/jquery.min.js"></script>
<script src="/scmserver/static/plugins/bootstrap/js/bootstrap.bundle.min.js"></script>
</head>
<body><p class="text-muted">Preview harness — not part of the app.</p>{body}
</body></html>"#,
            body = body,
        );

        let out = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../target")
            .join(name);
        std::fs::write(&out, page).unwrap();
        eprintln!("wrote {}", out.display());
    }
}
