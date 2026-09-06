//! Parse records once, preserving input positions across agent and Worker responses.

use super::{legacy_item_result, ItemError, ItemResult};
use crate::core::{client_decrypt_v2, DecryptInput, DecryptResItem, SecretType, VtUrl, SALT_LEN};
use anyhow::{ensure, Result};
use zeroize::{Zeroize, Zeroizing};

struct V2Record {
    t: SecretType,
    salt: [u8; SALT_LEN],
    inner_ct: Vec<u8>,
}

impl V2Record {
    fn decrypt(&self, dek: &[u8; 32]) -> ItemResult {
        client_decrypt_v2(self.t, dek, &self.salt, &self.inner_ct).map_err(ItemError::from)
    }
}

enum Record<'a> {
    V2(V2Record),
    Legacy(&'a str),
    Invalid { url: &'a str, error: ItemError },
}

pub(super) struct DecryptBatch<'a> {
    records: Vec<Record<'a>>,
}

impl<'a> DecryptBatch<'a> {
    pub(super) fn parse(urls: &'a [String]) -> Self {
        let records = urls
            .iter()
            .map(|url| match VtUrl::parse(url) {
                Ok(VtUrl::V2 { t, salt, inner_ct }) => Record::V2(V2Record { t, salt, inner_ct }),
                Ok(VtUrl::Legacy { .. }) => Record::Legacy(url),
                Err(error) => Record::Invalid {
                    url,
                    error: error.into(),
                },
            })
            .collect();
        Self { records }
    }

    pub(super) fn agent_items(&self) -> Vec<DecryptInput> {
        self.records
            .iter()
            .map(|record| match record {
                Record::V2(record) => DecryptInput::V2 {
                    t: record.t,
                    salt: record.salt,
                },
                // Invalid URLs must still take a wire slot and count as legacy:
                // any such member keeps the agent's whole batch Fresh.
                Record::Legacy(url) | Record::Invalid { url, .. } => DecryptInput::Legacy {
                    url: (*url).to_string(),
                },
            })
            .collect()
    }

    pub(super) fn salts(&self) -> Vec<[u8; SALT_LEN]> {
        self.records
            .iter()
            .filter_map(|record| match record {
                Record::V2(record) => Some(record.salt),
                _ => None,
            })
            .collect()
    }

    pub(super) fn finish_agent(self, mut results: Vec<DecryptResItem>) -> Result<Vec<ItemResult>> {
        let out = (|| {
            ensure!(
                results.len() == self.records.len(),
                "agent returned {} results for {} items",
                results.len(),
                self.records.len()
            );
            Ok(self
                .records
                .into_iter()
                .zip(results.iter_mut())
                .map(|(record, result)| match (record, result) {
                    (Record::Invalid { error, .. }, _) => Err(error),
                    (Record::V2(record), DecryptResItem::V2 { dek, err_message }) => {
                        let key = Zeroizing::new(*dek);
                        dek.zeroize();
                        if err_message.is_empty() {
                            record.decrypt(&key)
                        } else {
                            Err(ItemError(std::mem::take(err_message)))
                        }
                    }
                    (
                        Record::Legacy(_),
                        DecryptResItem::Legacy {
                            result,
                            err_message,
                        },
                    ) => legacy_item_result(std::mem::take(result), std::mem::take(err_message)),
                    _ => Err(ItemError(
                        "agent returned mismatched response variant".into(),
                    )),
                })
                .collect())
        })();
        // Also wipe material in rejected variants and wrong-length batches.
        for result in &mut results {
            match result {
                DecryptResItem::V2 { dek, .. } => dek.zeroize(),
                DecryptResItem::Legacy { result, .. } => result.zeroize(),
            }
        }
        out
    }

    pub(super) fn finish_cf(self, deks: &[Zeroizing<[u8; 32]>]) -> Result<Vec<ItemResult>> {
        let mut deks = deks.iter();
        let mut out = Vec::with_capacity(self.records.len());
        for record in self.records {
            out.push(match record {
                Record::Invalid { error, .. } => Err(error),
                Record::Legacy(_) => Err(ItemError(
                    "legacy vt:// URLs require macOS SSH agent".into(),
                )),
                Record::V2(record) => {
                    let dek = deks.next().ok_or_else(|| {
                        anyhow::anyhow!("internal: fewer DEKs returned than v2 records")
                    })?;
                    record.decrypt(dek)
                }
            });
        }
        ensure!(
            deks.next().is_none(),
            "internal: more DEKs returned than v2 records"
        );
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::client_encrypt_v2;

    fn v2(n: u8) -> String {
        client_encrypt_v2(SecretType::RAW, &[n; SALT_LEN], &[n; 32], &[b'a' + n]).unwrap()
    }

    fn agent_key(n: u8) -> DecryptResItem {
        DecryptResItem::V2 {
            dek: [n; 32],
            err_message: String::new(),
        }
    }

    fn legacy_result(value: &str, error: &str) -> DecryptResItem {
        DecryptResItem::Legacy {
            result: value.into(),
            err_message: error.into(),
        }
    }

    fn values(items: Vec<ItemResult>) -> Vec<Result<String, String>> {
        items
            .into_iter()
            .map(|item| item.map_err(|e| e.to_string()))
            .collect()
    }

    #[test]
    fn v2_duplicates_keep_wire_and_result_order_on_both_transports() {
        let urls = [v2(2), v2(1), v2(2)];
        let batch = DecryptBatch::parse(&urls);
        assert_eq!(batch.salts(), [[2; SALT_LEN], [1; SALT_LEN], [2; SALT_LEN]]);
        for (item, n) in batch.agent_items().iter().zip([2, 1, 2]) {
            assert!(
                matches!(item, DecryptInput::V2 { t: SecretType::RAW, salt } if *salt == [n; SALT_LEN])
            );
        }
        let agent = batch
            .finish_agent(vec![agent_key(2), agent_key(1), agent_key(2)])
            .unwrap();
        let keys = [
            Zeroizing::new([2; 32]),
            Zeroizing::new([1; 32]),
            Zeroizing::new([2; 32]),
        ];
        let cf = DecryptBatch::parse(&urls).finish_cf(&keys).unwrap();
        let expected = vec![Ok("c".into()), Ok("b".into()), Ok("c".into())];
        assert_eq!(values(agent), expected);
        assert_eq!(values(cf), expected);
    }

    #[test]
    fn mixed_batch_preserves_legacy_and_invalid_wire_slots() {
        let urls = [
            v2(1),
            "vt://mac/1YWJj".into(),
            "invalid".into(),
            v2(2),
            v2(1),
        ];
        let batch = DecryptBatch::parse(&urls);
        let wire = batch.agent_items();
        assert_eq!(wire.len(), urls.len());
        assert!(matches!(&wire[1], DecryptInput::Legacy { url } if url == &urls[1]));
        assert!(matches!(&wire[2], DecryptInput::Legacy { url } if url == &urls[2]));
        assert_eq!(batch.salts(), [[1; SALT_LEN], [2; SALT_LEN], [1; SALT_LEN]]);
        let results = batch
            .finish_agent(vec![
                agent_key(1),
                legacy_result("123456", ""),
                legacy_result("ignored", "remote parse error"),
                agent_key(2),
                agent_key(1),
            ])
            .unwrap();
        let results = values(results);
        assert_eq!(results[0], Ok("b".into()));
        assert_eq!(results[1], Ok("123456".into()));
        assert_eq!(
            results[2],
            Err(VtUrl::parse(&urls[2]).unwrap_err().to_string())
        );
        assert_eq!(results[3], Ok("c".into()));
        assert_eq!(results[4], Ok("b".into()));

        let keys = [
            Zeroizing::new([1; 32]),
            Zeroizing::new([2; 32]),
            Zeroizing::new([1; 32]),
        ];
        let cf = values(DecryptBatch::parse(&urls).finish_cf(&keys).unwrap());
        assert_eq!(
            cf[1],
            Err("legacy vt:// URLs require macOS SSH agent".into())
        );
        for index in [0, 2, 3, 4] {
            assert_eq!(cf[index], results[index]);
        }
    }

    #[test]
    fn response_count_and_variant_mismatches_are_rejected() {
        let urls = [v2(1), "vt://mac/0YWJj".into()];
        for count in [0, 1, 3] {
            let error = DecryptBatch::parse(&urls)
                .finish_agent((0..count).map(|_| agent_key(1)).collect())
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("agent returned {count} results for 2 items")
            );
        }
        let results = values(
            DecryptBatch::parse(&urls)
                .finish_agent(vec![legacy_result("discarded", ""), agent_key(1)])
                .unwrap(),
        );
        assert_eq!(
            results,
            vec![Err("agent returned mismatched response variant".into()); 2]
        );
        for count in [0, 2] {
            let keys = (0..count)
                .map(|_| Zeroizing::new([1; 32]))
                .collect::<Vec<_>>();
            assert!(DecryptBatch::parse(&urls).finish_cf(&keys).is_err());
        }
    }

    #[test]
    fn remote_item_errors_and_local_aead_errors_stay_per_item() {
        let urls = [v2(1), "vt://mac/0YWJj".into(), v2(2), v2(1)];
        let results = values(
            DecryptBatch::parse(&urls)
                .finish_agent(vec![
                    DecryptResItem::V2 {
                        dek: [1; 32],
                        err_message: "DEK denied".into(),
                    },
                    legacy_result("discarded", "legacy denied"),
                    agent_key(9),
                    agent_key(1),
                ])
                .unwrap(),
        );
        assert_eq!(results[0], Err("DEK denied".into()));
        assert_eq!(results[1], Err("legacy denied".into()));
        assert!(results[2].is_err());
        assert_eq!(results[3], Ok("b".into()));
        let cf = values(
            DecryptBatch::parse(&urls)
                .finish_cf(&[
                    Zeroizing::new([1; 32]),
                    Zeroizing::new([9; 32]),
                    Zeroizing::new([1; 32]),
                ])
                .unwrap(),
        );
        assert_eq!(cf[0], Ok("b".into()));
        assert!(cf[1].is_err());
        assert_eq!(cf[2], results[2]);
        assert_eq!(cf[3], results[3]);
    }

    #[test]
    fn empty_and_non_v2_batches_do_not_consume_deks() {
        let empty = DecryptBatch::parse(&[]);
        assert!(empty.agent_items().is_empty());
        assert!(empty.salts().is_empty());
        assert!(empty.finish_agent(vec![]).unwrap().is_empty());
        assert!(DecryptBatch::parse(&[]).finish_cf(&[]).unwrap().is_empty());
        let urls = ["vt://mac/0YWJj".into(), "bad".into()];
        let batch = DecryptBatch::parse(&urls);
        assert!(batch.salts().is_empty());
        assert!(batch
            .agent_items()
            .iter()
            .all(|item| matches!(item, DecryptInput::Legacy { .. })));
        assert!(batch.finish_cf(&[]).unwrap().iter().all(Result::is_err));
    }
}
