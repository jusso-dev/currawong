//! One module per identifier. Each has `find` over text and `validate` over
//! the bare digits. A `Match` holds offsets, never the identifier itself.
//!
//! Text is tokenised once: Unicode decimal digits are read as ASCII digits,
//! zero-width and other format characters are ignored, and up to three
//! separators (spaces, tabs, line breaks, `.`, `,`, `-`, `/` and their
//! Unicode look-alikes) may sit between digit groups. Every run of whole
//! groups from 8 to 19 digits is a candidate, so the work is linear in the
//! text and no candidate cap can be exhausted by padding.
pub mod abn;
pub mod acn;
pub mod card;
pub mod licence;
pub mod medicare;
pub mod tfn;

pub use currawong_core::DlpKind;
use std::ops::RangeInclusive;

/// Added when a context word is close by.
pub const CONTEXT_BOOST: u8 = 30;
/// Added when a context word appears anywhere in the text, for example a
/// spreadsheet column header.
pub const DOCUMENT_BOOST: u8 = 15;
/// Subtracted when the number is glued to letters, as in `INV123456782`.
pub const GLUED_PENALTY: u8 = 20;
const CONTEXT_BEFORE: usize = 60;
const CONTEXT_AFTER: usize = 30;
const MIN_DIGITS: usize = 8;
const MAX_DIGITS: usize = 19;
const MAX_SEPARATORS: usize = 3;

/// Byte offsets into the scanned text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Match {
    pub kind: DlpKind,
    pub start: usize,
    pub end: usize,
    /// 0 to 100.
    pub confidence: u8,
}

struct Group {
    /// Offset into `Tokens::digits`.
    digit_start: usize,
    byte_start: usize,
    byte_end: usize,
}

struct Run {
    groups: std::ops::Range<usize>,
    glued_before: bool,
    glued_after: bool,
}

/// Tokenised text shared by every detector in one scan.
pub struct Scan<'a> {
    text: &'a str,
    /// ASCII lowercase copy. Byte offsets match `text`.
    lower: String,
    digits: String,
    groups: Vec<Group>,
    runs: Vec<Run>,
}

impl<'a> Scan<'a> {
    pub fn new(text: &'a str) -> Self {
        let mut scan = Scan {
            text,
            lower: text.to_ascii_lowercase(),
            digits: String::new(),
            groups: Vec::new(),
            runs: Vec::new(),
        };
        scan.tokenise();
        scan
    }

    pub fn text(&self) -> &'a str {
        self.text
    }

    fn tokenise(&mut self) {
        let mut run_start: Option<usize> = None;
        let mut glued_before = false;
        let mut in_group = false;
        let mut separators = 0;
        let mut prev_alpha = false;
        for (at, ch) in self.text.char_indices() {
            if ignorable(ch) {
                continue;
            }
            if let Some(digit) = digit_value(ch) {
                if !in_group {
                    if run_start.is_none() {
                        run_start = Some(self.groups.len());
                        glued_before = prev_alpha;
                    }
                    self.groups.push(Group {
                        digit_start: self.digits.len(),
                        byte_start: at,
                        byte_end: at,
                    });
                    in_group = true;
                }
                self.digits.push(char::from(b'0' + digit));
                if let Some(group) = self.groups.last_mut() {
                    group.byte_end = at + ch.len_utf8();
                }
                separators = 0;
                prev_alpha = false;
                continue;
            }
            if run_start.is_some() && is_separator(ch) && separators < MAX_SEPARATORS {
                in_group = false;
                separators += 1;
                prev_alpha = false;
                continue;
            }
            let alpha = ch.is_alphabetic();
            if let Some(start) = run_start.take() {
                self.runs.push(Run {
                    groups: start..self.groups.len(),
                    glued_before,
                    glued_after: in_group && alpha,
                });
            }
            in_group = false;
            separators = 0;
            prev_alpha = alpha;
        }
        if let Some(start) = run_start {
            self.runs.push(Run {
                groups: start..self.groups.len(),
                glued_before,
                glued_after: false,
            });
        }
    }

    /// Calls `f(digits, byte_start, byte_end, glued)` for every candidate.
    fn candidates(&self, mut f: impl FnMut(&str, usize, usize, bool)) {
        for run in &self.runs {
            for from in run.groups.clone() {
                let digit_start = self.groups[from].digit_start;
                for to in from..run.groups.end {
                    let digit_end = self
                        .groups
                        .get(to + 1)
                        .map_or(self.digits.len(), |g| g.digit_start);
                    let len = digit_end - digit_start;
                    if len > MAX_DIGITS {
                        break;
                    }
                    if len >= MIN_DIGITS {
                        let glued = (from == run.groups.start && run.glued_before)
                            || (to + 1 == run.groups.end && run.glued_after);
                        f(
                            &self.digits[digit_start..digit_end],
                            self.groups[from].byte_start,
                            self.groups[to].byte_end,
                            glued,
                        );
                    }
                }
            }
        }
    }

    /// Where `words` appear as whole words, found once per scan.
    pub(crate) fn context(&self, words: &[&str]) -> Context {
        let mut spans: Vec<(usize, usize)> = words
            .iter()
            .flat_map(|word| {
                self.lower
                    .match_indices(word)
                    .filter(|(at, _)| word_boundary(self.lower.as_bytes(), *at, word.len()))
                    .map(|(at, _)| (at, at + word.len()))
            })
            .collect();
        spans.sort_unstable();
        Context { spans }
    }
}

pub(crate) struct Context {
    spans: Vec<(usize, usize)>,
}

impl Context {
    /// A context word lies wholly within the window around the span.
    pub(crate) fn near(&self, start: usize, end: usize) -> bool {
        let lo = start.saturating_sub(CONTEXT_BEFORE);
        let hi = end + CONTEXT_AFTER;
        let first = self.spans.partition_point(|(s, _)| *s < lo);
        self.spans[first..]
            .iter()
            .take_while(|(s, _)| *s < hi)
            .any(|(_, e)| *e <= hi)
    }

    pub(crate) fn anywhere(&self) -> bool {
        !self.spans.is_empty()
    }
}

/// A checksum detector: lengths it applies to, base confidence and the
/// words that raise it.
pub(crate) struct Rule {
    pub kind: DlpKind,
    pub lengths: RangeInclusive<usize>,
    pub base: u8,
    pub words: &'static [&'static str],
    pub validate: fn(&str) -> bool,
}

/// One pass over the candidates for several rules. Each match carries the
/// index of the rule that found it, which `find_all` uses as a tie-break.
pub(crate) fn find_rules(scan: &Scan, rules: &[&Rule]) -> Vec<(usize, Match)> {
    let context: Vec<Context> = rules.iter().map(|r| scan.context(r.words)).collect();
    let mut by_length: [Vec<usize>; MAX_DIGITS + 1] = Default::default();
    for (index, rule) in rules.iter().enumerate() {
        for len in rule.lengths.clone() {
            by_length[len].push(index);
        }
    }
    let mut out = Vec::new();
    scan.candidates(|digits, start, end, glued| {
        for &index in &by_length[digits.len()] {
            let rule = rules[index];
            if !(rule.validate)(digits) {
                continue;
            }
            let mut confidence = rule.base;
            if context[index].near(start, end) {
                confidence = confidence.saturating_add(CONTEXT_BOOST);
            } else if context[index].anywhere() {
                confidence = confidence.saturating_add(DOCUMENT_BOOST);
            }
            if glued {
                confidence = confidence.saturating_sub(GLUED_PENALTY);
            }
            out.push((
                index,
                Match {
                    kind: rule.kind,
                    start,
                    end,
                    confidence: confidence.min(100),
                },
            ));
        }
    });
    out
}

pub(crate) fn find_rule(scan: &Scan, rule: &Rule) -> Vec<Match> {
    find_rules(scan, &[rule])
        .into_iter()
        .map(|(_, m)| m)
        .collect()
}

/// Every checksum rule, in tie-break order.
pub(crate) fn checksum_rules() -> [&'static Rule; 6] {
    [
        &card::RULE,
        &abn::RULE,
        &medicare::RULE,
        &tfn::RULE_9,
        &tfn::RULE_8,
        &acn::RULE,
    ]
}

/// Letters may not touch the word; digits may (`TFN123456782`).
fn word_boundary(hay: &[u8], pos: usize, len: usize) -> bool {
    (pos == 0 || !hay[pos - 1].is_ascii_alphabetic())
        && hay.get(pos + len).is_none_or(|b| !b.is_ascii_alphabetic())
}

/// Weighted digit sum, or `None` unless `digits` is exactly `weights.len()`
/// ASCII digits.
pub(crate) fn weighted_sum(digits: &str, weights: &[u32]) -> Option<u32> {
    if digits.len() != weights.len() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(
        digits
            .bytes()
            .zip(weights)
            .map(|(b, w)| u32::from(b - b'0') * w)
            .sum(),
    )
}

fn is_separator(ch: char) -> bool {
    matches!(
        ch,
        ' ' | '\t'
            | '\r'
            | '\n'
            | '.'
            | ','
            | '-'
            | '/'
            | '_'
            | '\u{a0}'
            | '\u{2000}'..='\u{200a}'
            | '\u{2010}'..='\u{2015}'
            | '\u{2024}'
            | '\u{202f}'
            | '\u{205f}'
            | '\u{2212}'
            | '\u{3000}'
            | '\u{fe58}'
            | '\u{fe63}'
            | '\u{ff0c}'
            | '\u{ff0d}'
            | '\u{ff0e}'
            | '\u{ff0f}'
    )
}

/// Zero-width, bidi and other invisible format characters.
fn ignorable(ch: char) -> bool {
    matches!(
        ch,
        '\u{ad}'
            | '\u{34f}'
            | '\u{61c}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{e0000}'..='\u{e007f}'
    )
}

/// First code point of each Unicode decimal digit block in common use.
const DIGIT_BLOCKS: &[u32] = &[
    0x30, 0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66,
    0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
    0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0, 0xff10,
    0x104a0, 0x11066, 0x1d7ce, 0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1fbf0,
];

pub(crate) fn digit_value(ch: char) -> Option<u8> {
    let c = u32::from(ch);
    if ch.is_ascii() {
        return ch.to_digit(10).map(|d| d as u8);
    }
    DIGIT_BLOCKS
        .iter()
        .find(|start| (**start..*start + 10).contains(&c))
        .map(|start| (c - start) as u8)
}
