// pdf.rs — minimal page-layout engine over printpdf, for the report builders.
//
// WHY THIS EXISTS
//
// The report builders used to sit on `genpdf`, which supplied a document model,
// automatic pagination, and a bordered table layout. genpdf has been
// unmaintained since 2021 and pins lopdf 0.26, which is the sole root of every
// finding `cargo audit` reports against this project. printpdf 0.12 is
// maintained and carries lopdf 0.44 (above the advisory's fix threshold), but
// it is a PDF *writer*, not a layout engine: it draws text at coordinates and
// nothing more. This module is the layout layer that gap leaves behind.
//
// It is deliberately small. It implements the handful of primitives the three
// report builders actually use — styled text, wrapped paragraphs, vertical
// space, centred images, and bordered tables that paginate — and nothing else.
// It is not a general-purpose layout engine and should not grow into one.
//
// printpdf 0.12 also ships an HTML/CSS renderer (`PdfDocument::from_html`),
// which was evaluated first and rejected: its pagination does not repeat table
// headers and does not apply page margins to continuation pages, so rows on
// page 2 onwards sit flush against the paper edge where printers clip them.
// Both are engine-internal and unreachable from CSS.
//
// COORDINATES
//
// PDF's origin is bottom-left with Y increasing upwards. Reasoning about a
// document that way is a reliable source of sign errors, so this module tracks
// `y` as millimetres *down from the top of the text area* and converts once,
// at the point of drawing, in `baseline_pt`. Nothing outside this file should
// need to think about PDF coordinates at all.

use printpdf::{
    Color, Mm, Op, ParsedFont, PdfDocument, PdfFontHandle, PdfPage, PdfSaveOptions, Point, Pt,
    RawImage, Rect, Rgb, TextItem, XObjectId, XObjectTransform,
};

// A4 in millimetres, and the margin genpdf's SimplePageDecorator was
// configured with — kept identical so the port does not silently reflow every
// existing report.
pub const PAGE_WIDTH_MM: f32 = 210.0;
pub const PAGE_HEIGHT_MM: f32 = 297.0;
pub const MARGIN_MM: f32 = 15.0;

// Usable text area.
const CONTENT_WIDTH_MM: f32 = PAGE_WIDTH_MM - 2.0 * MARGIN_MM;
const CONTENT_HEIGHT_MM: f32 = PAGE_HEIGHT_MM - 2.0 * MARGIN_MM;

// 72 pt to the inch, 25.4 mm to the inch.
const PT_PER_MM: f32 = 72.0 / 25.4;

// Multiplier from font size to line box height. 1.2 is the usual typographic
// default and matches what genpdf produced closely enough that page breaks
// land in comparable places.
const LINE_HEIGHT: f32 = 1.2;

// Fraction of the font size from the top of the line box down to the baseline.
// An approximation of ascent that avoids a per-font metrics lookup on a
// document where every face is Liberation Sans.
const BASELINE_RATIO: f32 = 0.8;

// Padding inside a table cell, in millimetres.
const CELL_PAD_MM: f32 = 1.2;

// The report logo is 250px square and genpdf rendered it at 40 DPI, which
// works out to 250/40 inch = 158.75mm. Kept as a named constant so the number
// is traceable rather than magic.
pub const LOGO_WIDTH_MM: f32 = 158.75;

// Fallback advance width, in font units, for a glyph the font does not carry.
// 500/1000 em is a conventional stand-in and only affects wrap decisions for
// characters that will render as .notdef anyway.
const FALLBACK_ADVANCE: f32 = 500.0;


// ─────────────────────────────────────────────────────────────────────────────
// Helper: mm_to_pt / pt_to_mm
// ─────────────────────────────────────────────────────────────────────────────
fn mm_to_pt(mm: f32) -> f32 { mm * PT_PER_MM }
fn pt_to_mm(pt: f32) -> f32 { pt / PT_PER_MM }


// ============================================================
// STYLE
// ============================================================

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Align { Left, Center, Right }

// Text appearance. Colours are 0-255 per channel to match the call sites the
// builders already had under genpdf (`Color::Rgb(0, 0, 128)`).
#[derive(Clone, Copy, Debug)]
pub struct Style {
    pub size: f32,
    pub bold: bool,
    pub italic: bool,
    pub color: (u8, u8, u8),
    pub align: Align,
}

impl Default for Style {
    fn default() -> Self {
        Style { size: 11.0, bold: false, italic: false, color: (0, 0, 0), align: Align::Left }
    }
}

impl Style {
    pub fn new() -> Self { Style::default() }
    pub fn size(mut self, size: f32) -> Self { self.size = size; self }
    pub fn bold(mut self) -> Self { self.bold = true; self }
    pub fn italic(mut self) -> Self { self.italic = true; self }
    pub fn color(mut self, r: u8, g: u8, b: u8) -> Self { self.color = (r, g, b); self }
    pub fn align(mut self, align: Align) -> Self { self.align = align; self }

    fn line_height_mm(&self) -> f32 { pt_to_mm(self.size * LINE_HEIGHT) }
}


// ============================================================
// TABLE
// ============================================================

// One table cell. Cells hold plain text; the builders never needed anything
// richer, and keeping it that way is what lets the table code stay short.
#[derive(Clone, Debug)]
pub struct Cell {
    pub text: String,
    pub style: Style,
}

impl Cell {
    pub fn new(text: impl Into<String>, style: Style) -> Self {
        Cell { text: text.into(), style }
    }
}

// A bordered table with relative column widths, mirroring genpdf's
// `TableLayout::new(vec![5, 1])` weighting.
//
// Unlike genpdf, the header row repeats at the top of every page the table
// spans. That is a deliberate improvement, not an accident of the port: a
// multi-page findings table whose columns are unlabelled after page 1 is
// materially harder to read as an audit artefact.
pub struct Table {
    weights: Vec<u16>,
    header: Option<Vec<Cell>>,
    rows: Vec<Vec<Cell>>,
}

impl Table {
    pub fn new(weights: Vec<u16>) -> Self {
        Table { weights, header: None, rows: Vec::new() }
    }

    pub fn header(mut self, cells: Vec<Cell>) -> Self {
        self.header = Some(cells);
        self
    }

    pub fn row(&mut self, cells: Vec<Cell>) {
        self.rows.push(cells);
    }

    // Column widths in mm, derived from the relative weights.
    fn column_widths(&self) -> Vec<f32> {
        let total: f32 = self.weights.iter().map(|w| *w as f32).sum();
        if total <= 0.0 {
            return vec![CONTENT_WIDTH_MM];
        }
        self.weights
            .iter()
            .map(|w| CONTENT_WIDTH_MM * (*w as f32) / total)
            .collect()
    }
}


// ============================================================
// DOCUMENT
// ============================================================

// A font plus its handle. The parsed copy stays around because text
// measurement — and therefore wrapping — needs per-glyph advance widths.
struct FontSlot {
    handle: PdfFontHandle,
    parsed: ParsedFont,
}

pub struct Doc {
    pdf: PdfDocument,
    pages: Vec<PdfPage>,
    ops: Vec<Op>,
    regular: FontSlot,
    bold: FontSlot,
    italic: FontSlot,
    bold_italic: FontSlot,
    // Millimetres from the top of the text area to the next line's top edge.
    y: f32,
}

impl Doc {
    // ─────────────────────────────────────────────────────────────────────────
    // Public: new
    // Builds an empty document with the four Liberation Sans faces registered.
    // Returns Err(()) if any face fails to parse, matching the builders'
    // existing error type.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn new(
        title: &str,
        regular: &[u8],
        bold: &[u8],
        italic: &[u8],
        bold_italic: &[u8],
    ) -> Result<Self, ()> {
        let mut pdf = PdfDocument::new(title);

        let mut load = |bytes: &[u8]| -> Result<FontSlot, ()> {
            let parsed = ParsedFont::from_bytes(bytes, 0, &mut Vec::new()).ok_or(())?;
            let id = pdf.add_font(&parsed);
            Ok(FontSlot { handle: PdfFontHandle::External(id), parsed })
        };

        let regular = load(regular)?;
        let bold = load(bold)?;
        let italic = load(italic)?;
        let bold_italic = load(bold_italic)?;

        Ok(Doc {
            pdf,
            pages: Vec::new(),
            ops: Vec::new(),
            regular,
            bold,
            italic,
            bold_italic,
            y: 0.0,
        })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: slot
    // Face selection for a style.
    // ─────────────────────────────────────────────────────────────────────────
    fn slot(&self, style: &Style) -> &FontSlot {
        match (style.bold, style.italic) {
            (true, true) => &self.bold_italic,
            (true, false) => &self.bold,
            (false, true) => &self.italic,
            (false, false) => &self.regular,
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: text_width_mm
    // Sum of glyph advances for `s` at `style`'s size. This is what makes
    // wrapping possible at all — printpdf draws text but never measures it.
    // ─────────────────────────────────────────────────────────────────────────
    fn text_width_mm(&self, s: &str, style: &Style) -> f32 {
        // With the `text_layout` feature on, printpdf's ParsedFont wraps
        // azul's; `as_azul()` is the only route to per-glyph advances.
        let font = self.slot(style).parsed.as_azul();
        let upem = font.font_metrics.units_per_em.max(1) as f32;
        let units: f32 = s
            .chars()
            .map(|c| {
                font.lookup_glyph_index(c as u32)
                    .map(|g| font.get_horizontal_advance(g) as f32)
                    .unwrap_or(FALLBACK_ADVANCE)
            })
            .sum();
        pt_to_mm(units / upem * style.size)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: wrap
    // Greedy word wrap to `width_mm`. A single word wider than the line is
    // broken character by character rather than allowed to overflow the
    // margin — the case that long unbroken filesystem paths hit constantly in
    // compliance output.
    // ─────────────────────────────────────────────────────────────────────────
    fn wrap(&self, text: &str, width_mm: f32, style: &Style) -> Vec<String> {
        let mut lines = Vec::new();

        for para in text.split('\n') {
            let mut line = String::new();

            for word in para.split_whitespace() {
                let candidate = if line.is_empty() {
                    word.to_string()
                } else {
                    format!("{line} {word}")
                };

                if self.text_width_mm(&candidate, style) <= width_mm {
                    line = candidate;
                    continue;
                }

                if !line.is_empty() {
                    lines.push(std::mem::take(&mut line));
                }

                // The word alone may still not fit; hard-break it.
                if self.text_width_mm(word, style) <= width_mm {
                    line = word.to_string();
                } else {
                    let mut chunk = String::new();
                    for ch in word.chars() {
                        let mut trial = chunk.clone();
                        trial.push(ch);
                        if !chunk.is_empty() && self.text_width_mm(&trial, style) > width_mm {
                            lines.push(std::mem::take(&mut chunk));
                        }
                        chunk.push(ch);
                    }
                    line = chunk;
                }
            }

            lines.push(line);
        }

        // An all-whitespace input still occupies one line.
        if lines.is_empty() {
            lines.push(String::new());
        }
        lines
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: baseline_pt
    // Converts the top-down `y` cursor into a PDF baseline coordinate.
    // ─────────────────────────────────────────────────────────────────────────
    fn baseline_pt(&self, y_mm: f32, style: &Style) -> f32 {
        let from_top = y_mm + pt_to_mm(style.size * BASELINE_RATIO);
        mm_to_pt(PAGE_HEIGHT_MM - MARGIN_MM - from_top)
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: draw_line_at
    // Emits one already-wrapped, already-fitted line of text.
    // ─────────────────────────────────────────────────────────────────────────
    fn draw_line_at(&mut self, text: &str, y_mm: f32, x_mm: f32, width_mm: f32, style: &Style) {
        if text.is_empty() {
            return;
        }

        let x = match style.align {
            Align::Left => x_mm,
            Align::Center => x_mm + (width_mm - self.text_width_mm(text, style)) / 2.0,
            Align::Right => x_mm + width_mm - self.text_width_mm(text, style),
        };

        let (r, g, b) = style.color;
        let handle = self.slot(style).handle.clone();
        let baseline = self.baseline_pt(y_mm, style);

        self.ops.extend([
            Op::StartTextSection,
            Op::SetFont { font: handle, size: Pt(style.size) },
            Op::SetFillColor {
                col: Color::Rgb(Rgb::new(r as f32 / 255.0, g as f32 / 255.0, b as f32 / 255.0, None)),
            },
            Op::SetTextCursor { pos: Point { x: Pt(mm_to_pt(x)), y: Pt(baseline) } },
            Op::ShowText { items: vec![TextItem::Text(text.to_string())] },
            Op::EndTextSection,
        ]);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: ensure_space
    // Starts a new page if `needed_mm` will not fit in what remains.
    // ─────────────────────────────────────────────────────────────────────────
    fn ensure_space(&mut self, needed_mm: f32) {
        if self.y + needed_mm > CONTENT_HEIGHT_MM && self.y > 0.0 {
            self.page_break();
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: page_break
    // Finalises the current page. A break on an untouched page is ignored, so
    // a trailing `page_break()` cannot leave a blank sheet at the end.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn page_break(&mut self) {
        if self.ops.is_empty() {
            self.y = 0.0;
            return;
        }
        let ops = std::mem::take(&mut self.ops);
        self.pages.push(PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), ops));
        self.y = 0.0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: text
    // Wrapped, styled text block. Paginates mid-block when it has to.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn text(&mut self, text: &str, style: Style) {
        let lh = style.line_height_mm();
        for line in self.wrap(text, CONTENT_WIDTH_MM, &style) {
            self.ensure_space(lh);
            let y = self.y;
            self.draw_line_at(&line, y, MARGIN_MM, CONTENT_WIDTH_MM, &style);
            self.y += lh;
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: space
    // Vertical gap measured in lines of 11pt text, matching genpdf's
    // `Break::new(n)` so the ported call sites keep their existing spacing.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn space(&mut self, lines: f32) {
        self.y += lines * pt_to_mm(11.0 * LINE_HEIGHT);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: image_centered
    // Places a decoded raster image, horizontally centred, scaled to
    // `width_mm`. A failure to decode is not fatal — the report is still
    // worth producing without its logo.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn image_centered(&mut self, bytes: &[u8], width_mm: f32) {
        let Some(image) = RawImage::decode_from_bytes(bytes, &mut Vec::new()).ok() else {
            return;
        };

        let px_w = image.width.max(1) as f32;
        let px_h = image.height.max(1) as f32;
        let height_mm = width_mm * px_h / px_w;

        self.ensure_space(height_mm);

        let id: XObjectId = self.pdf.add_image(&image);
        let x_mm = MARGIN_MM + (CONTENT_WIDTH_MM - width_mm) / 2.0;
        // Translation addresses the image's bottom-left corner.
        let y_mm_from_top = self.y + height_mm;
        let y_pt = mm_to_pt(PAGE_HEIGHT_MM - MARGIN_MM - y_mm_from_top);

        // printpdf scales an image by DPI: at D dots-per-inch a px-wide image
        // occupies px/D inches. Solve for the DPI that lands it on width_mm.
        let dpi = px_w / (width_mm / 25.4);

        self.ops.push(Op::UseXobject {
            id,
            transform: XObjectTransform {
                translate_x: Some(Pt(mm_to_pt(x_mm))),
                translate_y: Some(Pt(y_pt)),
                dpi: Some(dpi),
                ..Default::default()
            },
        });

        self.y += height_mm;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: row_height_mm
    // Tallest wrapped cell in the row, plus padding.
    // ─────────────────────────────────────────────────────────────────────────
    fn row_height_mm(&self, cells: &[Cell], widths: &[f32]) -> f32 {
        let mut tallest: f32 = 0.0;
        for (i, cell) in cells.iter().enumerate() {
            let w = widths.get(i).copied().unwrap_or(CONTENT_WIDTH_MM) - 2.0 * CELL_PAD_MM;
            let lines = self.wrap(&cell.text, w.max(1.0), &cell.style).len() as f32;
            tallest = tallest.max(lines * cell.style.line_height_mm());
        }
        tallest + 2.0 * CELL_PAD_MM
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Private: draw_row
    // Draws one row's borders and wrapped cell text at the current cursor.
    // ─────────────────────────────────────────────────────────────────────────
    fn draw_row(&mut self, cells: &[Cell], widths: &[f32], height_mm: f32, shaded: bool) {
        let top = self.y;
        let mut x = MARGIN_MM;

        for (i, cell) in cells.iter().enumerate() {
            let w = widths.get(i).copied().unwrap_or(CONTENT_WIDTH_MM);
            let rect_y = mm_to_pt(PAGE_HEIGHT_MM - MARGIN_MM - top - height_mm);

            // Header shading, drawn before the border so the stroke stays crisp.
            if shaded {
                self.ops.push(Op::SetFillColor {
                    col: Color::Rgb(Rgb::new(0.93, 0.93, 0.93, None)),
                });
                self.ops.push(Op::DrawRectangle {
                    rectangle: Rect {
                        x: Pt(mm_to_pt(x)),
                        y: Pt(rect_y),
                        width: Pt(mm_to_pt(w)),
                        height: Pt(mm_to_pt(height_mm)),
                        mode: Some(printpdf::PaintMode::Fill),
                        winding_order: None,
                    },
                });
            }

            self.ops.push(Op::SetOutlineColor {
                col: Color::Rgb(Rgb::new(0.6, 0.6, 0.6, None)),
            });
            self.ops.push(Op::SetOutlineThickness { pt: Pt(0.5) });
            self.ops.push(Op::DrawRectangle {
                rectangle: Rect {
                    x: Pt(mm_to_pt(x)),
                    y: Pt(rect_y),
                    width: Pt(mm_to_pt(w)),
                    height: Pt(mm_to_pt(height_mm)),
                    mode: Some(printpdf::PaintMode::Stroke),
                    winding_order: None,
                },
            });

            let inner_w = (w - 2.0 * CELL_PAD_MM).max(1.0);
            let mut line_y = top + CELL_PAD_MM;
            for line in self.wrap(&cell.text, inner_w, &cell.style) {
                let style = cell.style;
                self.draw_line_at(&line, line_y, x + CELL_PAD_MM, inner_w, &style);
                line_y += style.line_height_mm();
            }

            x += w;
        }

        self.y = top + height_mm;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: table
    // Draws a bordered table, breaking pages between rows and repeating the
    // header on each new page. A row taller than a whole page is emitted
    // anyway rather than looping forever — it will overflow, but a pathological
    // cell must not hang report generation.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn table(&mut self, table: &Table) {
        let widths = table.column_widths();

        let header_height = table
            .header
            .as_ref()
            .map(|h| self.row_height_mm(h, &widths))
            .unwrap_or(0.0);

        if let Some(header) = &table.header {
            let header = header.clone();
            self.ensure_space(header_height);
            self.draw_row(&header, &widths, header_height, true);
        }

        for row in &table.rows {
            let h = self.row_height_mm(row, &widths);

            if self.y + h > CONTENT_HEIGHT_MM && h <= CONTENT_HEIGHT_MM {
                self.page_break();
                if let Some(header) = &table.header {
                    let header = header.clone();
                    self.draw_row(&header, &widths, header_height, true);
                }
            }

            let row = row.clone();
            self.draw_row(&row, &widths, h, false);
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Public: finish
    // Flushes the trailing page and serialises. Font subsetting is on by
    // default in PdfSaveOptions and is the reason output is a fraction of the
    // ~2.7 MB genpdf produced, which embedded four full faces every time.
    // ─────────────────────────────────────────────────────────────────────────
    pub fn finish(mut self) -> Vec<u8> {
        if !self.ops.is_empty() {
            let ops = std::mem::take(&mut self.ops);
            self.pages.push(PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), ops));
        }
        // A document with no pages at all is not a valid PDF.
        if self.pages.is_empty() {
            self.pages.push(PdfPage::new(Mm(PAGE_WIDTH_MM), Mm(PAGE_HEIGHT_MM), Vec::new()));
        }
        let pages = std::mem::take(&mut self.pages);
        self.pdf
            .with_pages(pages)
            .save(&PdfSaveOptions::default(), &mut Vec::new())
    }
}


// ─────────────────────────────────────────────────────────────────────────────
// Public: status_badge
// PASS/FAIL/NA/EXCLUDED label and colour for a result cell. Shared by all
// three report builders so the three tables cannot drift apart — under genpdf
// this mapping was copy-pasted into each one.
// ─────────────────────────────────────────────────────────────────────────────
pub fn status_badge(status: &str, is_excluded: bool) -> (&'static str, (u8, u8, u8)) {
    if is_excluded {
        return ("EXCLUDED", (100, 100, 100));
    }
    match status {
        "PASS" => ("PASS", (0, 128, 0)),
        "FAIL" => ("FAIL", (200, 0, 0)),
        "NA"   => ("NA",   (100, 100, 100)),
        _      => ("—", (150, 150, 150)),
    }
}
