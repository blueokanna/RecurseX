// The f7a387c refresh scoring path, retained only for comparison tools.
// It deliberately scans and scores under the caller's cache lock.
use recurse_x::cache::{RefreshInputs, SemanticCache, Tier, UNVERIFIED_OBSERVATION_TRUST};
use recurse_x::planner::PrefetchPolicy;
use recurse_x::time::Ts;
use recurse_x::{cache::CacheKey, Name};

pub fn schedule(
    cache: &SemanticCache,
    policy: &PrefetchPolicy,
    budget: usize,
    now: Ts,
    inputs: impl Fn(&Name, u32) -> RefreshInputs,
) -> Vec<CacheKey> {
    let scheduling = cache.config().refresh_scheduling;
    let mut entries: Vec<_> = cache
        .iter_entries()
        .filter(|entry| {
            matches!(entry.tier, Tier::Hot | Tier::Warm)
                && entry.rrset().is_some()
                && !entry.refreshing
        })
        .collect();
    entries.sort_by(|a, b| a.key.cmp(&b.key));
    let candidates = entries
        .into_iter()
        .filter_map(|entry| {
            let supplied = inputs(&entry.key.name.apex(), policy.horizon_secs);
            if !policy.wants_refresh(&entry.stability, supplied.query_probability) {
                return None;
            }
            let config = recurse_x::voi::VoiConfig {
                horizon_secs: policy.horizon_secs as f64,
                ttl_secs: entry.ttl_secs(),
                tail_probability: entry.stability.hazard().config().tail_probability(),
                observation_weight: if entry.validated {
                    1.0
                } else {
                    UNVERIFIED_OBSERVATION_TRUST
                },
                min_value: scheduling.min_value,
                reservation_per_class: scheduling.reservation_per_class,
            };
            Some(recurse_x::voi::Candidate {
                payload: entry.key.clone(),
                class: entry.behavior_class(),
                tie_break: 0,
                value: recurse_x::voi::observation_value(
                    &entry.stability,
                    entry.answer_consequence(),
                    entry.trust_level(),
                    supplied.value_ms,
                    now,
                    &config,
                ),
            })
        })
        .collect();
    recurse_x::voi::schedule(
        candidates,
        budget,
        &recurse_x::voi::VoiConfig {
            horizon_secs: policy.horizon_secs as f64,
            min_value: scheduling.min_value,
            reservation_per_class: scheduling.reservation_per_class,
            ..recurse_x::voi::VoiConfig::default()
        },
    )
}
