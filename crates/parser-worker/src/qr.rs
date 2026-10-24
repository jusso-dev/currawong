//! QR codes in images and, with the `pdfium` feature, the first pages of a
//! PDF. URLs in them join the message's links for link analysis. Nothing is
//! fetched. Work is bounded per image and per message. An image with
//! dimensions no camera or scanner produces is a possible decode bomb,
//! [`Skipped::TooLarge`] (the part fails closed as `LimitExceeded`); one
//! merely too large to decode, or past the per-message QR budget, is
//! [`Skipped::Budget`] (flagged `QrSkipped`, the message is not held).
use image::{DynamicImage, GrayImage, ImageError, ImageReader, Limits, Luma};
use std::io::Cursor;
use std::time::{Duration, Instant};

/// A 24 MP phone photo decodes; larger images are skipped.
const MAX_DECODE_PIXELS: u64 = 25_000_000;
/// Past this (an A4 page at 1,200 dpi is 140 MP) an image is a possible
/// decode bomb rather than a large photo or scan.
const BOMB_PIXELS: u64 = 250_000_000;
const MAX_ALLOC: u64 = 128 * 1024 * 1024;
/// Larger decoded images are scaled down to about this before detection.
const DETECT_PIXELS: u64 = 8_000_000;
/// Smaller than the smallest QR code: not decoded and not counted.
const MIN_SIDE: u32 = 21;
/// Codes read from one image or page.
const MAX_CODES: usize = 8;
/// The most a QR code can hold (alphanumeric mode, version 40).
const MAX_PAYLOAD: usize = 4296;
/// Per message.
pub const MAX_IMAGES: usize = 64;
pub const MAX_URLS: usize = 64;
pub const MAX_PIXELS: u64 = 200_000_000;
pub const MAX_TIME: Duration = Duration::from_secs(10);
/// PDF pages rendered, from the first.
pub const PDF_PAGES: u16 = 3;

/// Why an image or page was not read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Skipped {
    /// Dimensions past [`BOMB_PIXELS`]: a possible decode bomb.
    TooLarge,
    /// Over the per-image pixel or memory cap, or the message's QR budget
    /// (images, pixels, time or URLs) was used up.
    Budget,
}

/// QR work for one message.
#[derive(Debug, Default)]
pub struct Budget {
    images: usize,
    pixels: u64,
    started: Option<Instant>,
}

impl Budget {
    /// Payloads of the QR codes in an image. An image that cannot be
    /// decoded has none; one not read is [`Skipped`].
    pub fn image(&mut self, bytes: &[u8]) -> Result<Vec<String>, Skipped> {
        let Some((width, height)) = reader(bytes).and_then(|r| r.into_dimensions().ok()) else {
            return Ok(Vec::new());
        };
        if width < MIN_SIDE || height < MIN_SIDE {
            return Ok(Vec::new());
        }
        let pixels = u64::from(width) * u64::from(height);
        if pixels > BOMB_PIXELS {
            return Err(Skipped::TooLarge);
        }
        if pixels > MAX_DECODE_PIXELS {
            return Err(Skipped::Budget);
        }
        self.admit(pixels)?;
        let Some(reader) = reader(bytes) else {
            return Ok(Vec::new());
        };
        match reader.decode() {
            Ok(image) => Ok(decode_grey(&grey(image))),
            Err(ImageError::Limits(_)) => Err(Skipped::Budget),
            Err(_) => Ok(Vec::new()),
        }
    }

    /// Payloads of the QR codes on the first [`PDF_PAGES`] pages. Without
    /// the `pdfium` feature, or without the Pdfium library, there are none.
    pub fn pdf(&mut self, bytes: &[u8]) -> Result<Vec<String>, Skipped> {
        #[cfg(feature = "pdfium")]
        return pdf::decode(bytes, self);
        #[cfg(not(feature = "pdfium"))]
        {
            let _ = bytes;
            Ok(Vec::new())
        }
    }

    fn admit(&mut self, pixels: u64) -> Result<(), Skipped> {
        let started = *self.started.get_or_insert_with(Instant::now);
        if self.images >= MAX_IMAGES
            || self.pixels.saturating_add(pixels) > MAX_PIXELS
            || started.elapsed() > MAX_TIME
        {
            return Err(Skipped::Budget);
        }
        self.images += 1;
        self.pixels += pixels;
        Ok(())
    }
}

/// Bind Pdfium before the worker sandbox is applied. A no-op without the
/// `pdfium` feature.
pub fn init() {
    #[cfg(feature = "pdfium")]
    pdf::pdfium();
}

fn reader(bytes: &[u8]) -> Option<ImageReader<Cursor<&[u8]>>> {
    let mut reader = ImageReader::new(Cursor::new(bytes))
        .with_guessed_format()
        .ok()?;
    let mut limits = Limits::default();
    limits.max_alloc = Some(MAX_ALLOC);
    reader.limits(limits);
    Some(reader)
}

/// Grey on white: transparent pixels become white, so dark modules on a
/// transparent background still read. Large images are scaled down with
/// integer sums: `resize` would need 16 bytes a pixel on top.
fn grey(image: DynamicImage) -> GrayImage {
    let grey = if image.color().has_alpha() {
        let image = image.into_luma_alpha8();
        GrayImage::from_fn(image.width(), image.height(), |x, y| {
            let [luma, alpha] = image.get_pixel(x, y).0;
            let (luma, alpha) = (u32::from(luma), u32::from(alpha));
            Luma([((luma * alpha + 255 * (255 - alpha)) / 255) as u8])
        })
    } else {
        image.into_luma8()
    };
    let pixels = u64::from(grey.width()) * u64::from(grey.height());
    if pixels <= DETECT_PIXELS {
        return grey;
    }
    let scale = (DETECT_PIXELS as f64 / pixels as f64).sqrt();
    let width = ((f64::from(grey.width()) * scale) as u32).max(1);
    let height = ((f64::from(grey.height()) * scale) as u32).max(1);
    image::imageops::thumbnail(&grey, width, height)
}

/// Light-on-dark codes are read from the inverted image, which is always
/// tried: a benign code must not hide an inverted one beside it.
fn decode_grey(image: &GrayImage) -> Vec<String> {
    // The detector indexes into the image; a panic on a hostile grid must
    // not take down an in-process parse.
    std::panic::catch_unwind(|| {
        let mut codes = read(image, false);
        for code in read(image, true) {
            if !codes.contains(&code) {
                codes.push(code);
            }
        }
        codes.truncate(MAX_CODES);
        codes
    })
    .unwrap_or_default()
}

fn read(image: &GrayImage, invert: bool) -> Vec<String> {
    let (width, height) = image.dimensions();
    let mut prepared =
        rqrr::PreparedImage::prepare_from_greyscale(width as usize, height as usize, |x, y| {
            let luma = image.get_pixel(x as u32, y as u32).0[0];
            if invert {
                255 - luma
            } else {
                luma
            }
        });
    prepared
        .detect_grids()
        .into_iter()
        .take(MAX_CODES)
        .filter_map(|grid| grid.decode().ok().map(|(_, content)| content))
        .collect()
}

/// URLs in QR payloads: `http(s)://` and `www.` links (phones open both).
/// Codes often hold upper-case URLs (the compact alphanumeric mode has no
/// lower case), so the scheme and host are lower-cased; the path is kept.
pub fn urls(payloads: &[String]) -> Vec<String> {
    payloads
        .iter()
        .flat_map(|payload| payload.split_whitespace())
        .filter_map(url)
        .collect()
}

fn url(token: &str) -> Option<String> {
    if token.len() > MAX_PAYLOAD {
        return None;
    }
    let has = |prefix: &str| {
        token.len() > prefix.len()
            && token.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    };
    let (scheme, rest) = if let Some(scheme) = ["https://", "http://"].into_iter().find(|s| has(s))
    {
        (scheme, &token[scheme.len()..])
    } else if has("www.") {
        ("http://", token)
    } else {
        return None;
    };
    let host_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(format!(
        "{scheme}{}{}",
        rest[..host_end].to_ascii_lowercase(),
        &rest[host_end..]
    ))
}

#[cfg(feature = "pdfium")]
mod pdf {
    use super::{Budget, Skipped};
    use pdfium_render::prelude::*;
    use std::sync::OnceLock;

    /// About 150 dpi for A4: enough for a printed code.
    const WIDTH: i32 = 1240;
    const HEIGHT: i32 = 1754;

    /// Bound once per process, before the sandbox. A missing library is
    /// logged once and PDFs are then not checked for QR codes.
    pub(super) fn pdfium() -> Option<&'static Pdfium> {
        static PDFIUM: OnceLock<Option<Pdfium>> = OnceLock::new();
        PDFIUM
            .get_or_init(|| match Pdfium::bind_to_system_library() {
                Ok(bindings) => Some(Pdfium::new(bindings)),
                Err(err) => {
                    tracing::warn!(%err, "pdfium unavailable, PDFs are not checked for QR codes");
                    None
                }
            })
            .as_ref()
    }

    pub(super) fn decode(bytes: &[u8], budget: &mut Budget) -> Result<Vec<String>, Skipped> {
        let Some(pdfium) = pdfium() else {
            return Ok(Vec::new());
        };
        let Ok(document) = pdfium.load_pdf_from_byte_slice(bytes, None) else {
            return Ok(Vec::new());
        };
        let config = PdfRenderConfig::new()
            .set_target_width(WIDTH)
            .set_maximum_height(HEIGHT);
        let mut out = Vec::new();
        for page in document.pages().iter().take(usize::from(super::PDF_PAGES)) {
            budget.admit((WIDTH as u64) * (HEIGHT as u64))?;
            let image = page
                .render_with_config(&config)
                .and_then(|bitmap| bitmap.as_image());
            if let Ok(image) = image {
                out.extend(super::decode_grey(&super::grey(image)));
            }
        }
        Ok(out)
    }
}
