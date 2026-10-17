//! CRLF line reader over raw octets. SMTP lines are bytes, not UTF-8: an
//! 8BITMIME body may carry any octet except a bare CR or LF.
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

#[derive(Debug, PartialEq, Eq)]
pub enum Line {
    /// Line content, without its CRLF.
    Crlf(Vec<u8>),
    /// Content ended by a LF with no CR before it.
    BareLf(Vec<u8>),
    /// Longer than the limit. The rest of the line is left unread.
    TooLong,
    /// The peer closed the connection. A partial line is discarded.
    Eof,
}

/// Read one line. `max` counts the line ending, as RFC 5321 section 4.5.3.1
/// does, so `max = 1000` allows 998 octets of text.
pub async fn read_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Line> {
    let mut line = Vec::new();
    loop {
        let buf = reader.fill_buf().await?;
        if buf.is_empty() {
            return Ok(Line::Eof);
        }
        let (take, found) = match buf.iter().position(|b| *b == b'\n') {
            Some(pos) => (pos + 1, true),
            None => (buf.len(), false),
        };
        if line.len() + take > max {
            reader.consume(take);
            return Ok(Line::TooLong);
        }
        line.extend_from_slice(&buf[..take]);
        reader.consume(take);
        if found {
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
                return Ok(Line::Crlf(line));
            }
            return Ok(Line::BareLf(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lines(input: &[u8], max: usize) -> Vec<Line> {
        let mut reader = tokio::io::BufReader::with_capacity(7, input);
        let mut out = Vec::new();
        loop {
            let line = read_line(&mut reader, max).await.unwrap();
            let stop = matches!(line, Line::Eof | Line::TooLong);
            out.push(line);
            if stop {
                return out;
            }
        }
    }

    #[tokio::test]
    async fn splits_on_crlf_and_flags_bare_lf() {
        let got = lines(b"one\r\n\xe9\xff\r\nbare\nlast", 1000).await;
        assert_eq!(
            got,
            vec![
                Line::Crlf(b"one".to_vec()),
                Line::Crlf(b"\xe9\xff".to_vec()),
                Line::BareLf(b"bare".to_vec()),
                Line::Eof,
            ]
        );
    }

    #[tokio::test]
    async fn limit_includes_crlf() {
        let mut ok = vec![b'a'; 8];
        ok.extend_from_slice(b"\r\n");
        assert_eq!(lines(&ok, 10).await[0], Line::Crlf(vec![b'a'; 8]));
        let mut long = vec![b'a'; 9];
        long.extend_from_slice(b"\r\n");
        assert_eq!(lines(&long, 10).await[0], Line::TooLong);
        assert_eq!(lines(&[b'a'; 50], 10).await[0], Line::TooLong);
    }
}
