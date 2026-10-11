//! CONNECT-UDP URI templates.
//!
//! See [RFC 9298 §2](https://www.rfc-editor.org/rfc/rfc9298#section-2) for the template rules
//! and [RFC 6570](https://www.rfc-editor.org/rfc/rfc6570) (level 3) for expansion.

use std::{fmt, net::Ipv6Addr, str::FromStr};

use http::{Uri, uri::Authority};

use super::MasqueError;

/// A validated CONNECT-UDP URI template, such as
/// `https://proxy.example:443/.well-known/masque/udp/{target_host}/{target_port}/`.
///
/// Templates are checked against RFC 9298 §2 when parsed: absolute, variables only in the path
/// or query, both `target_host` and `target_port` present, and no level 4 or reserved
/// expansions. Variables other than those two expand as undefined.
#[derive(Clone)]
pub struct Template {
    raw: Box<str>,
    proxy: Uri,
    parts: Vec<Part>,
}

#[derive(Clone, Debug)]
enum Part {
    Literal(Box<str>),
    Expr(Op, Vec<Var>),
}

#[derive(Clone, Copy, Debug)]
enum Op {
    /// `{a,b}`
    Simple,
    /// `{?a,b}`
    Query,
    /// `{&a,b}`
    QueryContinuation,
}

#[derive(Clone, Debug)]
enum Var {
    Host,
    Port,
    /// Defined by the template but not by this client; expands as undefined.
    Other,
}

// ===== impl Template =====

impl Template {
    /// Parses and validates a template.
    pub fn new(template: &str) -> Result<Self, MasqueError> {
        let invalid = MasqueError::InvalidTemplate;
        if !template.bytes().all(|b| (0x21..=0x7E).contains(&b)) {
            return Err(invalid("characters outside 0x21-0x7E"));
        }
        let (scheme, rest) = template
            .split_once("://")
            .ok_or(invalid("not in absolute form"))?;
        let path_start = rest
            .find('/')
            .ok_or(invalid("path must start with a slash"))?;
        let authority = &rest[..path_start];
        if scheme.is_empty() || authority.is_empty() {
            return Err(invalid("empty scheme or authority"));
        }
        if scheme.contains(['{', '}']) || authority.contains(['{', '}', '?', '#']) {
            return Err(invalid("variables outside the path and query"));
        }
        let proxy = Uri::builder()
            .scheme(scheme)
            .authority(authority)
            .path_and_query("/")
            .build()
            .map_err(|_| invalid("invalid scheme or authority"))?;

        let parts = parse_parts(&rest[path_start..])?;
        let has = |want: fn(&Var) -> bool| {
            parts
                .iter()
                .any(|part| matches!(part, Part::Expr(_, vars) if vars.iter().any(want)))
        };
        if !has(|v| matches!(v, Var::Host)) || !has(|v| matches!(v, Var::Port)) {
            return Err(invalid("missing target_host or target_port"));
        }

        Ok(Template {
            raw: template.into(),
            proxy,
            parts,
        })
    }

    /// Returns the default template for a proxy (RFC 9298 §3):
    /// `https://{proxy}/.well-known/masque/udp/{target_host}/{target_port}/`.
    pub fn well_known(proxy: &Authority) -> Result<Self, MasqueError> {
        Template::new(&format!(
            "https://{proxy}/.well-known/masque/udp/{{target_host}}/{{target_port}}/"
        ))
    }

    /// Returns the proxy's scheme and authority as a URI, for connecting to it.
    pub fn proxy(&self) -> &Uri {
        &self.proxy
    }

    /// Expands the template for a target.
    ///
    /// `host` is a DNS name or an IP literal; IPv6 may be bracketed. The proxy resolves names.
    pub fn expand(&self, host: &str, port: u16) -> Result<Uri, MasqueError> {
        let host = target_host(host)?;
        if port == 0 {
            return Err(MasqueError::InvalidTarget);
        }
        let port = port.to_string();

        let mut uri = self.proxy.to_string();
        uri.pop(); // The trailing "/" from `proxy`; the template supplies the path.
        for part in &self.parts {
            match part {
                Part::Literal(literal) => uri.push_str(literal),
                Part::Expr(op, vars) => {
                    let defined = vars.iter().filter_map(|var| match var {
                        Var::Host => Some(("target_host", host)),
                        Var::Port => Some(("target_port", port.as_str())),
                        Var::Other => None,
                    });
                    for (i, (name, value)) in defined.enumerate() {
                        match (op, i) {
                            (Op::Simple, 0) => {}
                            (Op::Simple, _) => uri.push(','),
                            (Op::Query, 0) => uri.push('?'),
                            (Op::Query | Op::QueryContinuation, _) => uri.push('&'),
                        }
                        if !matches!(op, Op::Simple) {
                            uri.push_str(name);
                            uri.push('=');
                        }
                        percent_encode(value, &mut uri);
                    }
                }
            }
        }
        uri.parse().map_err(|_| MasqueError::InvalidTarget)
    }
}

impl FromStr for Template {
    type Err = MasqueError;

    fn from_str(template: &str) -> Result<Self, Self::Err> {
        Template::new(template)
    }
}

impl fmt::Display for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl fmt::Debug for Template {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Template").field(&self.raw).finish()
    }
}

/// Splits the path and query into literals and expressions.
fn parse_parts(mut rest: &str) -> Result<Vec<Part>, MasqueError> {
    let invalid = MasqueError::InvalidTemplate;
    let mut parts = Vec::new();
    while !rest.is_empty() {
        let Some(expr) = rest.strip_prefix('{') else {
            let end = rest.find('{').unwrap_or(rest.len());
            let literal = &rest[..end];
            validate_literal(literal)?;
            parts.push(Part::Literal(literal.into()));
            rest = &rest[end..];
            continue;
        };
        let (expr, after) = expr.split_once('}').ok_or(invalid("unclosed expression"))?;
        let (op, list) = match expr.as_bytes().first() {
            Some(b'?') => (Op::Query, &expr[1..]),
            Some(b'&') => (Op::QueryContinuation, &expr[1..]),
            Some(b'+' | b'#' | b'.' | b'/' | b';') => {
                return Err(invalid("reserved, fragment, label or path expansion"));
            }
            Some(b'=' | b',' | b'!' | b'@' | b'|') => return Err(invalid("reserved operator")),
            _ => (Op::Simple, expr),
        };
        let vars = list
            .split(',')
            .map(|name| match name {
                "target_host" => Ok(Var::Host),
                "target_port" => Ok(Var::Port),
                name if is_varname(name) => Ok(Var::Other),
                name if name.ends_with('*') || name.contains(':') => {
                    Err(invalid("level 4 modifiers"))
                }
                _ => Err(invalid("invalid variable name")),
            })
            .collect::<Result<Vec<_>, _>>()?;
        parts.push(Part::Expr(op, vars));
        rest = after;
    }
    Ok(parts)
}

/// RFC 6570 §2.1 literals, excluding a fragment.
fn validate_literal(literal: &str) -> Result<(), MasqueError> {
    let bytes = literal.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if !is_pct_encoded(&bytes[i..]) {
                    return Err(MasqueError::InvalidTemplate("bare '%' in a literal"));
                }
                i += 3;
                continue;
            }
            b'"' | b'\'' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'|' | b'}' | b'#' => {
                return Err(MasqueError::InvalidTemplate(
                    "character not allowed in a literal",
                ));
            }
            _ => {}
        }
        i += 1;
    }
    Ok(())
}

/// RFC 6570 §2.3: `varchar *( ["."] varchar )`, where varchar is ALPHA / DIGIT / "_" /
/// pct-encoded.
fn is_varname(name: &str) -> bool {
    let mut rest = name.as_bytes();
    // A varchar must start the name, end it, and follow each ".".
    let mut need_varchar = true;
    while let [byte, tail @ ..] = rest {
        rest = match byte {
            b'.' if !need_varchar => {
                need_varchar = true;
                tail
            }
            b'%' if is_pct_encoded(rest) => {
                need_varchar = false;
                &rest[3..]
            }
            b if b.is_ascii_alphanumeric() || *b == b'_' => {
                need_varchar = false;
                tail
            }
            _ => return false,
        };
    }
    !need_varchar
}

/// Whether `bytes` starts with `"%" HEXDIG HEXDIG` (RFC 6570 §1.5).
fn is_pct_encoded(bytes: &[u8]) -> bool {
    matches!(bytes, [b'%', hi, lo, ..] if hi.is_ascii_hexdigit() && lo.is_ascii_hexdigit())
}

/// Normalizes `target_host`: strips IPv6 brackets and rejects empty hosts and zone IDs.
fn target_host(host: &str) -> Result<&str, MasqueError> {
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    // RFC 9298 §3: IPv6 zone identifiers are not supported.
    if host.is_empty() || (host.contains(':') && host.parse::<Ipv6Addr>().is_err()) {
        return Err(MasqueError::InvalidTarget);
    }
    Ok(host)
}

/// Percent-encodes all but unreserved characters (RFC 6570 §3.2.1), so IPv6 colons become `%3A`.
fn percent_encode(value: &str, out: &mut String) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for b in value.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 0xF)]));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expansion() {
        let cases = [
            (
                "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
                "192.0.2.6",
                "https://proxy.example/.well-known/masque/udp/192.0.2.6/443/",
            ),
            (
                "https://proxy.example:4443/masque?h={target_host}&p={target_port}",
                "[2001:db8::42]",
                "https://proxy.example:4443/masque?h=2001%3Adb8%3A%3A42&p=443",
            ),
            // Undefined variables expand to nothing and take no separator.
            (
                "https://proxy.example/m/{x,target_host,y,target_port}",
                "a-b_c~d.example",
                "https://proxy.example/m/a-b_c~d.example,443",
            ),
            (
                "https://proxy.example/m{?x}{?y,target_host}{&z,target_port}",
                "example.com",
                "https://proxy.example/m?target_host=example.com&target_port=443",
            ),
        ];
        for (template, host, expected) in cases {
            let template = Template::new(template).expect(template);
            assert_eq!(template.proxy().path(), "/");
            assert_eq!(template.expand(host, 443).unwrap().to_string(), expected);
        }

        let well_known = Template::well_known(&"proxy.example:443".parse().unwrap()).unwrap();
        assert_eq!(
            well_known.expand("::1", 53).unwrap().to_string(),
            "https://proxy.example:443/.well-known/masque/udp/%3A%3A1/53/"
        );
        assert_eq!(
            well_known.to_string(),
            "https://proxy.example:443/.well-known/masque/udp/{target_host}/{target_port}/"
        );
    }

    #[test]
    fn rejects_invalid_templates_and_targets() {
        let missing = "missing target_host or target_port";
        let literal = "character not allowed in a literal";
        let varname = "invalid variable name";
        for (template, reason) in [
            (
                "/.well-known/masque/udp/{target_host}/{target_port}/",
                "not in absolute form",
            ),
            ("https://proxy.example", "path must start with a slash"),
            (
                "https://{target_host}/{target_port}",
                "variables outside the path and query",
            ),
            ("https://proxy.example/{target_host}", missing),
            ("https://proxy.example/{target_port}/", missing),
            (
                "https://proxy.example/{+target_host}/{target_port}",
                "reserved, fragment, label or path expansion",
            ),
            (
                "https://proxy.example/{target_host*}/{target_port}",
                "level 4 modifiers",
            ),
            (
                "https://proxy.example/{target_host}/{target_port}#frag",
                literal,
            ),
            (
                "https://proxy.example/{target_host}}/{target_port}",
                literal,
            ),
            (
                "https://proxy.example/%zz/{target_host}/{target_port}",
                "bare '%' in a literal",
            ),
            (
                "https://proxy.example/{target_host}/{target_port}/{x",
                "unclosed expression",
            ),
            (
                "https://proxy.example/{}/{target_host}/{target_port}",
                varname,
            ),
            (
                "https://proxy.example/{a-b}/{target_host}/{target_port}",
                varname,
            ),
            (
                "https://proxy.example/{x%}/{target_host}/{target_port}",
                varname,
            ),
            (
                "https://proxy.example/{x.}/{target_host}/{target_port}",
                varname,
            ),
            (
                "https://proxy.example/ {target_host}/{target_port}",
                "characters outside 0x21-0x7E",
            ),
        ] {
            assert!(
                matches!(Template::new(template), Err(MasqueError::InvalidTemplate(r)) if r == reason),
                "{template}"
            );
        }
        assert!(
            Template::new("https://proxy.example/{a.b%2F_c}/{target_host}/{target_port}").is_ok()
        );

        let template = Template::well_known(&"proxy.example".parse().unwrap()).unwrap();
        for (host, port) in [
            ("", 443),
            ("[]", 443),
            ("fe80::1%eth0", 443),
            ("1:2:3", 443),
            ("[2001:db8::1", 443),
            ("a.example", 0),
        ] {
            assert!(
                matches!(template.expand(host, port), Err(MasqueError::InvalidTarget)),
                "{host}:{port}"
            );
        }
    }
}
