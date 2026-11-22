//! Text only: no JavaScript, subresource loading, or terminal control sequences.

use super::unsafe_char;
use html5gum::{DefaultEmitter, Token, Tokenizer};

pub(super) const MAX_OUTPUT: usize = 12 * 1024;
const TRUNCATED: &str = "\n… [truncated]";

pub(super) fn bounded(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max - TRUNCATED.len();
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str(TRUNCATED);
    }
    text
}

pub(super) fn plain(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c == '\n' {
                '\n'
            } else if unsafe_char(c) {
                ' '
            } else {
                c
            }
        })
        .collect()
}

fn block(name: &[u8]) -> bool {
    matches!(
        name,
        b"br"
            | b"p"
            | b"div"
            | b"section"
            | b"article"
            | b"li"
            | b"tr"
            | b"td"
            | b"pre"
            | b"h1"
            | b"h2"
            | b"h3"
            | b"h4"
            | b"h5"
            | b"h6"
            | b"title"
    )
}

pub(super) fn visible_tokens(input: &str) -> impl Iterator<Item = Token> + '_ {
    let mut emitter = DefaultEmitter::default();
    emitter.naively_switch_states(true); // e.g. '<' inside JavaScript is raw text
    let mut hidden = None;
    Tokenizer::new_with_emitter(input, emitter)
        .flatten()
        .filter(move |token| match token {
            Token::EndTag(tag) if hidden.as_ref() == Some(&tag.name) => {
                hidden = None;
                false
            }
            _ if hidden.is_some() => false,
            Token::StartTag(tag)
                if matches!(
                    tag.name.as_slice(),
                    b"script" | b"style" | b"noscript" | b"template"
                ) =>
            {
                hidden = Some(tag.name.clone());
                false
            }
            _ => true,
        })
}

pub(super) fn html(input: &str) -> String {
    let mut text = String::new();
    for token in visible_tokens(input) {
        match token {
            Token::String(s) => text.push_str(&String::from_utf8_lossy(&s)),
            Token::StartTag(tag) if block(&tag.name) => text.push('\n'),
            Token::EndTag(tag) if block(&tag.name) => text.push('\n'),
            _ => {}
        }
    }
    plain(&text)
        .lines()
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .filter(|l| !l.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_text_not_scripts_or_control_codes() {
        let page = "<h1>Rust &amp; Go</h1><script>if(a < b) x()</script><!--comment--><style>xxxx</style><p>Some <b>text</b>!\u{1b}\u{202e}</p>";
        assert_eq!(html(page), "Rust & Go\nSome text!");
        let clipped = bounded("界".repeat(MAX_OUTPUT), MAX_OUTPUT);
        assert!(clipped.len() <= MAX_OUTPUT && clipped.ends_with(TRUNCATED));
    }
}
