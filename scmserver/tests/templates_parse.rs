// templates_parse.rs — startup smoke test for the embedded Tera templates.
//
// init_tera() parses every embedded template up front; if any template has a
// syntax error the server panics/exits at boot (a crash-loop in production,
// surfacing as 502 behind the proxy). This guards the easy-to-miss case of a
// Tera token (`{% … %}`, `{{ … }}`, `{# … #}`) accidentally embedded in inline
// JavaScript — e.g. a literal "{% block scripts %}" inside a JS comment, which
// Tera parses as a real tag and unbalances the document.

// Every embedded template must parse cleanly, so a broken template fails CI
// instead of the production server at startup.
#[test]
fn all_embedded_templates_parse() {
    scmserver::init_tera().expect("all embedded templates must parse under Tera");
}


// The tour lives in a subdirectory, which is a first for this project.
// include_dir's `.files()` iterator is NOT recursive, so a template under
// templates/partials/ is silently absent from the registry and only fails when
// something tries to `{% include %}` it — i.e. at request time, as a 500.
#[test]
fn subdirectory_templates_are_registered() {
    let tera = scmserver::init_tera().expect("templates must parse");
    let names: Vec<_> = tera.get_template_names().collect();
    assert!(
        names.contains(&"partials/tour.html"),
        "partials/tour.html was not loaded. Known templates: {names:?}"
    );
}
