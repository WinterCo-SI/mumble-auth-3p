use std::collections::BTreeMap;

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
pub struct WhitelistConfig {
    #[serde(default)]
    pub whitelist: TierList,
    #[serde(default)]
    pub groups: BTreeMap<String, TierList>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TierList {
    #[serde(default)]
    pub alliance_ids: Vec<u64>,
    #[serde(default)]
    pub corporation_ids: Vec<u64>,
    #[serde(default)]
    pub character_ids: Vec<u64>,
}

impl TierList {
    fn matches(&self, char_id: u64, corp_id: u64, alliance_id: Option<u64>) -> bool {
        self.character_ids.contains(&char_id)
            || self.corporation_ids.contains(&corp_id)
            || alliance_id.is_some_and(|a| self.alliance_ids.contains(&a))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub admitted: bool,
    pub groups: Vec<String>,
}

pub fn decide(
    char_id: u64,
    corp_id: u64,
    alliance_id: Option<u64>,
    cfg: &WhitelistConfig,
) -> Decision {
    if !cfg.whitelist.matches(char_id, corp_id, alliance_id) {
        return Decision { admitted: false, groups: Vec::new() };
    }
    let mut groups = vec![format!("char_{char_id}"), format!("corp_{corp_id}")];
    if let Some(a) = alliance_id {
        groups.push(format!("alliance_{a}"));
    }
    for (name, rule) in &cfg.groups {
        if rule.matches(char_id, corp_id, alliance_id) {
            groups.push(name.clone());
        }
    }
    Decision { admitted: true, groups }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(whitelist: TierList, groups: &[(&str, TierList)]) -> WhitelistConfig {
        WhitelistConfig {
            whitelist,
            groups: groups.iter().map(|(k, v)| ((*k).to_string(), v.clone())).collect(),
        }
    }

    fn tier(alliances: &[u64], corps: &[u64], chars: &[u64]) -> TierList {
        TierList {
            alliance_ids: alliances.to_vec(),
            corporation_ids: corps.to_vec(),
            character_ids: chars.to_vec(),
        }
    }

    #[test]
    fn empty_whitelist_denies() {
        let c = cfg(TierList::default(), &[]);
        assert!(!decide(1, 2, Some(3), &c).admitted);
    }

    #[test]
    fn alliance_admits_with_full_auto_groups() {
        let c = cfg(tier(&[3], &[], &[]), &[]);
        let d = decide(1, 2, Some(3), &c);
        assert!(d.admitted);
        assert!(d.groups.contains(&"char_1".into()));
        assert!(d.groups.contains(&"corp_2".into()));
        assert!(d.groups.contains(&"alliance_3".into()));
    }

    #[test]
    fn corp_admits() {
        let c = cfg(tier(&[], &[2], &[]), &[]);
        assert!(decide(1, 2, Some(3), &c).admitted);
    }

    #[test]
    fn character_admits_even_when_corp_and_alliance_unknown() {
        let c = cfg(tier(&[], &[], &[1]), &[]);
        assert!(decide(1, 2, None, &c).admitted);
    }

    #[test]
    fn no_alliance_skips_alliance_group() {
        let c = cfg(tier(&[], &[2], &[]), &[]);
        let d = decide(1, 2, None, &c);
        assert!(d.admitted);
        assert!(!d.groups.iter().any(|g| g.starts_with("alliance_")));
    }

    #[test]
    fn unrelated_alliance_denies() {
        let c = cfg(tier(&[999], &[], &[]), &[]);
        assert!(!decide(1, 2, Some(3), &c).admitted);
    }

    #[test]
    fn named_group_matches_via_each_tier() {
        let c = cfg(
            tier(&[3], &[], &[]),
            &[
                ("officers", tier(&[], &[], &[1])),
                ("brave",    tier(&[3], &[], &[])),
                ("hq_corp",  tier(&[], &[2], &[])),
            ],
        );
        let d = decide(1, 2, Some(3), &c);
        assert!(d.groups.contains(&"officers".into()));
        assert!(d.groups.contains(&"brave".into()));
        assert!(d.groups.contains(&"hq_corp".into()));
    }

    #[test]
    fn named_group_excluded_when_overall_decision_is_deny() {
        let c = cfg(
            TierList::default(),
            &[("officers", tier(&[], &[], &[1]))],
        );
        let d = decide(1, 2, Some(3), &c);
        assert!(!d.admitted);
        assert!(d.groups.is_empty());
    }
}
