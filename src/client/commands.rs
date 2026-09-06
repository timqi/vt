//! `vt create` / `read` / `auth` / `run` command entry points and the shared
//! multi-string decrypt used by `vt inject`.

use std::io::{self, IsTerminal, Write};

use super::{single_item_result, ItemResult, VTClient};
use crate::caller_meta::get_hostname;
use crate::core::{has_vt_url, iter_vt_urls, sanitize_for_display, EncryptItem, SecretType};
use anyhow::{ensure, Result};
use tracing::debug;

pub async fn create(vt_client: VTClient, type_arg: Option<&str>) -> Result<()> {
    // Non-interactive when stdin is not a terminal: the type comes from
    // `--type` (default raw) and stdin IS the plaintext. Interactively the two
    // prompts stay — the type on stdin, the value on /dev/tty without echo. A
    // piped run cannot answer the tty prompt at all, so a service rotating a
    // secret has no other way in, and the plaintext must never be an argv flag.
    let piped = !io::stdin().is_terminal();
    let secret_type = match type_arg {
        Some(t) => {
            let parsed = SecretType::from_str(&t.trim().to_lowercase());
            if parsed == SecretType::UNKNOWN {
                return Err(anyhow::anyhow!("Invalid secret type: {}", t));
            }
            parsed
        }
        None if piped => SecretType::RAW,
        None => {
            eprint!("Enter secret type (raw/totp) [default: raw]: ");
            io::stderr().flush()?;
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            if input.trim().is_empty() {
                input = "raw".to_string();
            }
            debug!("User input for secret type: '{}'", input);
            let parsed = SecretType::from_str(&input.trim().to_lowercase());
            if parsed == SecretType::UNKNOWN {
                // The invalid answer is echoed back, so it must be the type the
                // user typed and never a plaintext read off a pipe.
                return Err(anyhow::anyhow!("Invalid secret type: {}", input.trim()));
            }
            parsed
        }
    };

    let secret = if piped {
        crate::tty::read_secret_from_stdin()?
    } else {
        crate::tty::prompt_input_password("Enter secret: ", "Secret entered: ")?
    };
    // DO NOT log `secret` — plaintext the user just typed.

    let res = vt_client
        .encrypt(&[EncryptItem {
            plaintext: secret.to_string(),
            t: secret_type,
        }])
        .await?;
    println!("{}", single_item_result(res, "Failed to create secret")?);
    Ok(())
}

pub async fn auth(vt_client: VTClient, reason: &str) -> Result<()> {
    vt_client.auth(reason).await
}

pub async fn run(vt_client: VTClient, argv: Vec<String>, reason: Option<&str>) -> Result<()> {
    vt_client.run(argv, reason).await
}

pub async fn read(vt_client: VTClient, vt: String, reason: Option<&str>) -> Result<()> {
    let mut command = "op: read".to_string();
    if let Some(r) = reason {
        command.push_str("\nreason: ");
        command.push_str(&sanitize_for_display(r, 200));
    }
    let res = vt_client.decrypt(&get_hostname(), &command, &[vt]).await?;
    let value = single_item_result(res, "Error decrypting item")?;
    // Interactive terminal: end the line so the shell prompt doesn't overwrite
    // or obscure a plaintext with no trailing newline (redrawing prompts like
    // starship/p10k clobber partial lines). Piped/redirected: byte-exact
    // output — `$(vt read …)` strips trailing newlines anyway, and
    // `vt read … > file` must not gain a byte.
    use std::io::Write;
    let mut stdout = io::stdout().lock();
    stdout.write_all(value.as_bytes())?;
    if stdout.is_terminal() && !value.ends_with('\n') {
        stdout.write_all(b"\n")?;
    }
    stdout.flush()?;
    Ok(())
}

pub(super) async fn decrypt_from_multi_str(
    vt_client: VTClient,
    original_str_vec: Vec<String>,
    command: String,
) -> Result<Vec<String>> {
    let plan = SubstitutionPlan::new(original_str_vec);
    let res = vt_client
        .decrypt(&get_hostname(), &command, &plan.encrypted)
        .await?;
    plan.apply(res)
}

/// Only original URL spans can be substituted: plaintext containing another
/// record is a literal value, never a second request for substitution.
struct SubstitutionPlan {
    originals: Vec<String>,
    encrypted: Vec<String>,
    spans: Vec<Vec<(std::ops::Range<usize>, usize)>>,
}

impl SubstitutionPlan {
    fn new(originals: Vec<String>) -> Self {
        let mut encrypted = Vec::new();
        let mut indices = std::collections::HashMap::new();
        let mut spans = Vec::with_capacity(originals.len());
        for text in &originals {
            let mut matches = Vec::new();
            let mut cursor = 0;
            for url in iter_vt_urls(text) {
                let index = *indices.entry(url).or_insert_with(|| {
                    encrypted.push(url.to_string());
                    encrypted.len() - 1
                });
                // The scanner returns slices in encounter order. Searching
                // only the remaining suffix keeps total scanning linear.
                let start = cursor + text[cursor..].find(url).expect("URL came from this suffix");
                cursor = start + url.len();
                matches.push((start..cursor, index));
            }
            spans.push(matches);
        }
        Self {
            originals,
            encrypted,
            spans,
        }
    }

    fn apply(self, results: Vec<ItemResult>) -> Result<Vec<String>> {
        ensure!(
            results.len() == self.encrypted.len(),
            "Expected same number of items in response"
        );
        // Validate the WHOLE batch before returning any file/env/argv values.
        // A per-item wire error is never a replacement secret.
        let values = results
            .into_iter()
            .enumerate()
            .map(|(index, item)| {
                item.map_err(|e| anyhow::anyhow!("Failed to decrypt record {}: {}", index + 1, e))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(self
            .originals
            .into_iter()
            .zip(self.spans)
            .map(|(text, spans)| {
                if spans.is_empty() {
                    return text;
                }
                let mut out = String::with_capacity(text.len());
                let mut cursor = 0;
                for (range, index) in spans {
                    out.push_str(&text[cursor..range.start]);
                    out.push_str(&values[index]);
                    cursor = range.end;
                }
                out.push_str(&text[cursor..]);
                out
            })
            .collect())
    }
}

/// Whether an environment variable enters the decrypt pipeline: its value must
/// contain a `vt://` URL, and — when `--only-env` is given — its name must be in
/// that allow-list. This is the scoping that keeps `vt hook` from handing a
/// matched command every vt:// secret in the environment (confused-deputy guard).
pub(super) fn env_var_in_scope(key: &str, value: &str, only_env: Option<&[String]>) -> bool {
    has_vt_url(value) && only_env.is_none_or(|allow| allow.iter().any(|a| a == key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn success(value: &str) -> ItemResult {
        Ok(value.into())
    }

    #[test]
    fn substitution_deduplicates_records_in_encounter_order() {
        let plan = SubstitutionPlan::new(vec![
            "vt://0abc + vt://mac/1def + vt://0abc".into(),
            "prefix vt://0abcxyz suffix vt://0abc".into(),
        ]);
        assert_eq!(
            plan.encrypted,
            ["vt://0abc", "vt://mac/1def", "vt://0abcxyz"]
        );
        assert_eq!(
            plan.apply(vec![success("short"), success("code"), success("long")])
                .unwrap(),
            ["short + code + short", "prefix long suffix short"],
        );
    }

    #[test]
    fn substitution_never_rescans_inserted_plaintext() {
        let plan = SubstitutionPlan::new(vec!["前 vt://0abc / vt://0abcdef 后".into()]);
        assert_eq!(
            plan.apply(vec![success("literal vt://0abcdef"), success("value")])
                .unwrap(),
            ["前 literal vt://0abcdef / value 后"],
        );
    }

    #[test]
    fn substitution_rejects_entire_mixed_batch_without_plaintext_output() {
        let plan = SubstitutionPlan::new(vec!["vt://0abc vt://0def".into()]);
        let err = plan
            .apply(vec![
                success("decrypted-value"),
                Err(super::super::ItemError("authentication failed".into())),
            ])
            .unwrap_err();
        assert!(err.to_string().contains("record 2"));
        assert!(!err.to_string().contains("decrypted-value"));
        assert!(!err.to_string().contains("discarded-value"));
    }

    #[test]
    fn substitution_checks_response_count_and_preserves_plain_inputs() {
        assert!(SubstitutionPlan::new(vec!["vt://0abc".into()])
            .apply(vec![])
            .is_err());
        assert!(SubstitutionPlan::new(vec![])
            .apply(vec![success("unexpected")])
            .is_err());
        let originals = vec![String::new(), "no record, just vt://".into()];
        assert_eq!(
            SubstitutionPlan::new(originals.clone())
                .apply(vec![])
                .unwrap(),
            originals
        );
    }

    #[test]
    fn only_env_scopes_decryption() {
        let v = "vt://0abc"; // a vt:// ciphertext value
        let plain = "ghp_plaintext";
        // No --only-env: every vt:// var is in scope; non-vt values never are.
        assert!(env_var_in_scope("GH_TOKEN", v, None));
        assert!(env_var_in_scope("ANYTHING", v, None));
        assert!(!env_var_in_scope("GH_TOKEN", plain, None));
        // With --only-env: only named vt:// vars are in scope (confused-deputy guard).
        let allow = [String::from("GH_TOKEN")];
        assert!(env_var_in_scope("GH_TOKEN", v, Some(&allow)));
        assert!(!env_var_in_scope("ANTHROPIC_API_KEY", v, Some(&allow))); // vt:// but not named → excluded
        assert!(!env_var_in_scope("GH_TOKEN", plain, Some(&allow))); // named but not vt:// → excluded
                                                                     // Empty allow-list excludes everything.
        assert!(!env_var_in_scope("GH_TOKEN", v, Some(&[])));
    }
}
