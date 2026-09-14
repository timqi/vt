//! Parse records once, preserving input positions across agent and Worker responses.

use super::{ItemError, ItemResult};
use crate::core::{client_decrypt_v2, DecryptInput, DecryptResItem, SecretType, VtUrl, SALT_LEN};
use anyhow::{ensure, Result};
use zeroize::{Zeroize, Zeroizing};

struct V2Record {
    t: SecretType,
    salt: [u8; SALT_LEN],
    inner_ct: Vec<u8>,
    /// Where the caller read this record from (env var name, file basename);
    /// `""` when unknown. Display suggestion for the Worker only.
    name: String,
}

impl V2Record {
    fn decrypt(&self, dek: &[u8; 32]) -> ItemResult {
        client_decrypt_v2(self.t, dek, &self.salt, &self.inner_ct).map_err(ItemError::from)
    }
}

/// Invalid records never reach a transport: they fail in place and the
/// transports see only the v2 records, in order.
enum Record {
    V2(V2Record),
    Invalid(ItemError),
}

pub(super) struct DecryptBatch {
    records: Vec<Record>,
}

impl DecryptBatch {
    /// `names[i]` labels `urls[i]`; a shorter or empty `names` means unknown.
    pub(super) fn parse(urls: &[String], names: &[String]) -> Self {
        let records = urls
            .iter()
            .enumerate()
            .map(|(i, url)| match VtUrl::parse(url) {
                Ok(VtUrl::V2 { t, salt, inner_ct }) => Record::V2(V2Record {
                    t,
                    salt,
                    inner_ct,
                    name: names.get(i).cloned().unwrap_or_default(),
                }),
                Err(error) => Record::Invalid(error.into()),
            })
            .collect();
        Self { records }
    }

    fn v2_records(&self) -> impl Iterator<Item = &V2Record> {
        self.records.iter().filter_map(|record| match record {
            Record::V2(record) => Some(record),
            Record::Invalid(_) => None,
        })
    }

    pub(super) fn agent_items(&self) -> Vec<DecryptInput> {
        self.v2_records()
            .map(|record| DecryptInput::V2 {
                t: record.t,
                salt: record.salt,
            })
            .collect()
    }

    pub(super) fn salts(&self) -> Vec<[u8; SALT_LEN]> {
        self.v2_records().map(|record| record.salt).collect()
    }

    /// Aligned with `salts()`: one suggestion per v2 record, `""` when unknown.
    pub(super) fn names(&self) -> Vec<String> {
        self.v2_records()
            .map(|record| record.name.clone())
            .collect()
    }

    /// Pair each v2 record with the next of `count` transport results.
    fn finish(
        self,
        source: &str,
        count: usize,
        mut decrypt: impl FnMut(&V2Record) -> ItemResult,
    ) -> Result<Vec<ItemResult>> {
        ensure!(
            count == self.v2_records().count(),
            "{source} returned {count} results for {} records",
            self.v2_records().count()
        );
        Ok(self
            .records
            .into_iter()
            .map(|record| match record {
                Record::Invalid(error) => Err(error),
                Record::V2(record) => decrypt(&record),
            })
            .collect())
    }

    pub(super) fn finish_agent(self, mut results: Vec<DecryptResItem>) -> Result<Vec<ItemResult>> {
        let count = results.len();
        let mut items = results.iter_mut();
        let out = self.finish("agent", count, |record| {
            let DecryptResItem::V2 { dek, err_message } = items.next().expect("count checked");
            let key = Zeroizing::new(*dek);
            dek.zeroize();
            if err_message.is_empty() {
                record.decrypt(&key)
            } else {
                Err(ItemError(std::mem::take(err_message)))
            }
        });
        // Also wipe material in wrong-length batches.
        for DecryptResItem::V2 { dek, .. } in &mut results {
            dek.zeroize();
        }
        out
    }

    pub(super) fn finish_cf(self, deks: &[Zeroizing<[u8; 32]>]) -> Result<Vec<ItemResult>> {
        let mut deks = deks.iter();
        self.finish("worker", deks.len(), |record| {
            record.decrypt(deks.next().expect("count checked"))
        })
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

    fn values(items: Vec<ItemResult>) -> Vec<Result<String, String>> {
        items
            .into_iter()
            .map(|item| item.map_err(|e| e.to_string()))
            .collect()
    }

    #[test]
    fn v2_duplicates_keep_wire_and_result_order_on_both_transports() {
        let urls = [v2(2), v2(1), v2(2)];
        let batch = DecryptBatch::parse(&urls, &[]);
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
        let cf = DecryptBatch::parse(&urls, &[]).finish_cf(&keys).unwrap();
        let expected = vec![Ok("c".into()), Ok("b".into()), Ok("c".into())];
        assert_eq!(values(agent), expected);
        assert_eq!(values(cf), expected);
    }

    #[test]
    fn invalid_and_legacy_records_fail_in_place_without_a_wire_slot() {
        // Retired `vt://mac/` records are rejected like any malformed URL:
        // the transports see only the v2 records and results keep positions.
        let urls = [
            v2(1),
            "vt://mac/1YWJj".into(),
            "invalid".into(),
            v2(2),
            v2(1),
        ];
        let batch = DecryptBatch::parse(&urls, &[]);
        let wire = batch.agent_items();
        assert_eq!(wire.len(), 3);
        assert_eq!(batch.salts(), [[1; SALT_LEN], [2; SALT_LEN], [1; SALT_LEN]]);
        let results = values(
            batch
                .finish_agent(vec![agent_key(1), agent_key(2), agent_key(1)])
                .unwrap(),
        );
        assert_eq!(results[0], Ok("b".into()));
        assert_eq!(
            results[1],
            Err(VtUrl::parse(&urls[1]).unwrap_err().to_string())
        );
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
        let cf = values(DecryptBatch::parse(&urls, &[]).finish_cf(&keys).unwrap());
        assert_eq!(cf, results);
    }

    #[test]
    fn names_align_with_v2_records_and_default_to_unknown() {
        let urls = [v2(1), "bad".into(), v2(2), v2(3)];
        let names = ["A_TOKEN".to_string(), "skipped".into(), ".env".into()];
        let batch = DecryptBatch::parse(&urls, &names);
        assert_eq!(batch.salts().len(), 3);
        assert_eq!(batch.names(), ["A_TOKEN", ".env", ""]);
        assert_eq!(DecryptBatch::parse(&urls, &[]).names(), ["", "", ""]);
    }

    #[test]
    fn response_count_mismatches_are_rejected() {
        let urls = [v2(1), "vt://mac/0YWJj".into()];
        for count in [0, 2, 3] {
            let error = DecryptBatch::parse(&urls, &[])
                .finish_agent((0..count).map(|_| agent_key(1)).collect())
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("agent returned {count} results for 1 records")
            );
            let keys = (0..count)
                .map(|_| Zeroizing::new([1; 32]))
                .collect::<Vec<_>>();
            let error = DecryptBatch::parse(&urls, &[])
                .finish_cf(&keys)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("worker returned {count} results for 1 records")
            );
        }
    }

    #[test]
    fn remote_item_errors_and_local_aead_errors_stay_per_item() {
        let urls = [v2(1), "bad".into(), v2(2), v2(1)];
        let results = values(
            DecryptBatch::parse(&urls, &[])
                .finish_agent(vec![
                    DecryptResItem::V2 {
                        dek: [1; 32],
                        err_message: "DEK denied".into(),
                    },
                    agent_key(9),
                    agent_key(1),
                ])
                .unwrap(),
        );
        assert_eq!(results[0], Err("DEK denied".into()));
        assert!(results[1].is_err());
        assert!(results[2].is_err());
        assert_eq!(results[3], Ok("b".into()));
        let cf = values(
            DecryptBatch::parse(&urls, &[])
                .finish_cf(&[
                    Zeroizing::new([1; 32]),
                    Zeroizing::new([9; 32]),
                    Zeroizing::new([1; 32]),
                ])
                .unwrap(),
        );
        assert_eq!(cf[0], Ok("b".into()));
        assert_eq!(cf[1], results[1]);
        assert_eq!(cf[2], results[2]);
        assert_eq!(cf[3], results[3]);
    }

    #[test]
    fn empty_and_all_invalid_batches_send_nothing_and_consume_nothing() {
        let empty = DecryptBatch::parse(&[], &[]);
        assert!(empty.agent_items().is_empty());
        assert!(empty.salts().is_empty());
        assert!(empty.finish_agent(vec![]).unwrap().is_empty());
        assert!(DecryptBatch::parse(&[], &[])
            .finish_cf(&[])
            .unwrap()
            .is_empty());
        let urls = ["vt://mac/0YWJj".into(), "bad".into()];
        let batch = DecryptBatch::parse(&urls, &[]);
        assert!(batch.salts().is_empty());
        assert!(batch.agent_items().is_empty());
        let results = batch.finish_agent(vec![]).unwrap();
        assert_eq!(results.len(), 2);
        assert!(results.iter().all(Result::is_err));
        assert!(DecryptBatch::parse(&urls, &[])
            .finish_cf(&[])
            .unwrap()
            .iter()
            .all(Result::is_err));
    }
}
