use crate::{
    error::RbacError,
    rbac::{MatchingFn, RoleManager},
    Result,
};
use std::collections::{HashMap, HashSet, VecDeque};

#[cfg(feature = "cached")]
use crate::cache::{Cache, DefaultCache};

const DEFAULT_DOMAIN: &str = "DEFAULT";

pub struct DefaultRoleManager {
    /// Explicit role links keyed by the domain they were declared in. This is
    /// the single source of truth: links are never copied between domains.
    explicit_links: HashMap<String, HashSet<(String, String)>>,
    /// Role names ever declared in each domain. Kept so domain/role
    /// membership queries keep their original semantics.
    domain_roles: HashMap<String, HashSet<String>>,
    #[cfg(feature = "cached")]
    cache: DefaultCache<(String, String, String), bool>,
    max_hierarchy_level: usize,
    role_matching_fn: Option<MatchingFn>,
    domain_matching_fn: Option<MatchingFn>,
}

impl DefaultRoleManager {
    pub fn new(max_hierarchy_level: usize) -> Self {
        DefaultRoleManager {
            explicit_links: HashMap::new(),
            domain_roles: HashMap::new(),
            #[cfg(feature = "cached")]
            cache: DefaultCache::new(50),
            max_hierarchy_level,
            role_matching_fn: None,
            domain_matching_fn: None,
        }
    }

    /// Domains whose declarations contribute to the view of `domain`.
    ///
    /// A stored domain `d` participates in the view of `domain` when:
    /// - it is the domain itself, or
    /// - the configured matcher explicitly approves the relation from the
    ///   queried domain's point of view.
    ///
    /// The matcher is treated as the administrator-approved relation: a
    /// concrete tenant name only matches pattern domains (e.g. "*"), never
    /// another concrete tenant, so a link declared in one tenant cannot be
    /// seen by an adjacent tenant through this path.
    fn visible_domains(&self, domain: &str) -> Vec<String> {
        match self.domain_matching_fn {
            Some(matcher) => self
                .explicit_links
                .keys()
                .chain(self.domain_roles.keys())
                .filter(|d| **d == domain || matcher(domain, d))
                .cloned()
                .collect::<HashSet<String>>()
                .into_iter()
                .collect(),
            None => {
                // Without a matcher every known domain is its own view; an
                // unknown domain simply has an empty view instead of erroring.
                let mut domains: Vec<String> = self
                    .explicit_links
                    .keys()
                    .chain(self.domain_roles.keys())
                    .filter(|d| **d == domain)
                    .cloned()
                    .collect();
                domains.sort_unstable();
                domains.dedup();
                domains
            }
        }
    }

    /// Outgoing link targets of `name` inside the tenant view of `domain`.
    ///
    /// Reproduces the historical `matching_bfs` expansion on top of the
    /// explicit link set:
    /// - direct links whose source is `name`;
    /// - links whose source is a pattern matching `name`;
    /// - pattern targets matching any directly reachable role;
    /// - links of concrete roles that `name` itself matches as a pattern.
    fn successors(&self, name: &str, domain: &str) -> Vec<String> {
        let mut targets = HashSet::new();
        let links: Vec<(String, String)> = self
            .visible_domains(domain)
            .into_iter()
            .filter_map(|visible| self.explicit_links.get(&visible))
            .flatten()
            .cloned()
            .collect();

        let matcher = match self.role_matching_fn {
            Some(matcher) => matcher,
            // Without pattern matching only direct links are followed.
            None => {
                for (source, target) in &links {
                    if source == name {
                        targets.insert(target.clone());
                    }
                }
                return targets.into_iter().collect();
            }
        };

        // Every role name participating in the view, used to evaluate the
        // virtual `Match` edges that the old graph built on node creation.
        let mut nodes: HashSet<String> = HashSet::new();
        for (source, target) in &links {
            nodes.insert(source.clone());
            nodes.insert(target.clone());
        }

        // Direct link targets of `name` (old outgoing LINK edges).
        let mut direct_targets = HashSet::new();
        for (source, target) in &links {
            if source == name {
                direct_targets.insert(target.clone());
                targets.insert(target.clone());
            }
        }

        // Virtual Match edge: `node` -> `pattern` when matcher(pattern, node).
        let is_match = |node: &str, pattern: &str| matcher(pattern, node);

        // Old branch 2: pattern targets matching a directly reached role.
        for role in &direct_targets {
            for pattern in &nodes {
                if is_match(role, pattern) {
                    targets.insert(pattern.clone());
                }
            }
        }

        // Old branch 3: concrete nodes with a Match edge into `name`
        // contribute their own direct link targets.
        for concrete in &nodes {
            if is_match(concrete, name) {
                for (source, target) in &links {
                    if source == concrete {
                        targets.insert(target.clone());
                    }
                }
            }
        }
        targets.into_iter().collect()
    }

    /// Names that directly point at `name` inside the tenant view of
    /// `domain`.
    fn predecessors(&self, name: &str, domain: &str) -> Vec<String> {
        let mut sources = HashSet::new();
        let links: Vec<(String, String)> = self
            .visible_domains(domain)
            .into_iter()
            .filter_map(|visible| self.explicit_links.get(&visible))
            .flatten()
            .cloned()
            .collect();

        for (source, target) in &links {
            // Exact target, or `name` acts as a pattern matching the
            // concrete target role (the historical node lookup rule).
            if target == name
                || self.role_matching_fn.is_some_and(|f| f(name, target))
            {
                sources.insert(source.clone());
            }
        }
        sources.into_iter().collect()
    }

    fn domain_has_role(&self, name: &str, domain: Option<&str>) -> bool {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);
        self.visible_domains(domain).iter().any(|visible| {
            self.domain_roles.get(visible).is_some_and(|roles| {
                roles.contains(name)
                    || self
                        .role_matching_fn
                        .is_some_and(|f| roles.iter().any(|role| f(name, role)))
            })
        })
    }

    fn remember_role(&mut self, name: &str, domain: &str) {
        self.domain_roles
            .entry(domain.to_owned())
            .or_default()
            .insert(name.to_owned());
    }
}

impl RoleManager for DefaultRoleManager {
    fn clear(&mut self) {
        self.explicit_links.clear();
        self.domain_roles.clear();
        #[cfg(feature = "cached")]
        self.cache.clear();
    }

    fn add_link(&mut self, name1: &str, name2: &str, domain: Option<&str>) {
        if name1 == name2 {
            return;
        }

        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        self.remember_role(name1, domain);
        self.remember_role(name2, domain);

        let inserted = self
            .explicit_links
            .entry(domain.to_owned())
            .or_default()
            .insert((name1.to_owned(), name2.to_owned()));

        if inserted {
            #[cfg(feature = "cached")]
            self.cache.clear();
        }
    }

    fn matching_fn(
        &mut self,
        role_matching_fn: Option<MatchingFn>,
        domain_matching_fn: Option<MatchingFn>,
    ) {
        self.domain_matching_fn = domain_matching_fn;
        self.role_matching_fn = role_matching_fn;
        #[cfg(feature = "cached")]
        self.cache.clear();
    }

    fn delete_link(
        &mut self,
        name1: &str,
        name2: &str,
        domain: Option<&str>,
    ) -> Result<()> {
        if name1 == name2 {
            return Ok(());
        }

        if !self.domain_has_role(name1, domain)
            || !self.domain_has_role(name2, domain)
        {
            return Err(
                RbacError::NotFound(format!("{} OR {}", name1, name2)).into()
            );
        }

        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        let removed =
            self.explicit_links.get_mut(domain).is_some_and(|links| {
                links.remove(&(name1.to_owned(), name2.to_owned()))
            });

        if removed {
            #[cfg(feature = "cached")]
            self.cache.clear();
        }

        Ok(())
    }

    fn has_link(&self, name1: &str, name2: &str, domain: Option<&str>) -> bool {
        if name1 == name2 {
            return true;
        }

        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        #[cfg(feature = "cached")]
        let cache_key = (name1.to_owned(), name2.to_owned(), domain.to_owned());

        #[cfg(feature = "cached")]
        if let Some(result) = self.cache.get(&cache_key) {
            return result;
        }

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(name1.to_owned());
        visited.insert(name1.to_owned());

        let mut result = false;
        for _depth in 0..self.max_hierarchy_level {
            for _ in 0..queue.len() {
                let current = queue
                    .pop_front()
                    .expect("queue length is bounded by the loop bound");
                for next in self.successors(&current, domain) {
                    let reaches = next == name2
                        || self
                            .role_matching_fn
                            .is_some_and(|f| f(&next, name2));
                    if reaches {
                        result = true;
                        break;
                    }
                    if visited.insert(next.clone()) {
                        queue.push_back(next);
                    }
                }
                if result {
                    break;
                }
            }
            if result {
                break;
            }
        }

        #[cfg(feature = "cached")]
        self.cache.set(cache_key, result);

        result
    }

    fn get_roles(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        // The historical implementation expanded the BFS iterator once on
        // the start node: direct roles plus the local pattern/sibling
        // expansions, but without recursive transitive accumulation.
        self.successors(name, domain)
    }

    fn get_users(&self, name: &str, domain: Option<&str>) -> Vec<String> {
        let domain = domain.unwrap_or(DEFAULT_DOMAIN);

        // Direct incoming links only, matching the historical graph query.
        self.predecessors(name, domain)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    fn sort_unstable<T: Ord>(mut v: Vec<T>) -> Vec<T> {
        v.sort_unstable();
        v
    }

    #[test]
    fn test_has_link_cache_hash_collision() {
        let authorized = "u85b1cd3ad675c9e1";
        let unauthorized = "ua03255daeb17d9fb";

        let mut rm = DefaultRoleManager::new(10);
        rm.add_link(authorized, "admin", None);
        assert!(rm.has_link(authorized, "admin", None));
        assert!(!rm.has_link(unauthorized, "admin", None));
    }

    #[test]
    fn test_role() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", None);
        rm.add_link("u2", "g1", None);
        rm.add_link("u3", "g2", None);
        rm.add_link("u4", "g2", None);
        rm.add_link("u4", "g3", None);
        rm.add_link("g1", "g3", None);

        assert_eq!(true, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(true, rm.has_link("u1", "g3", None));
        assert_eq!(true, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(true, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(true, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(true, rm.has_link("u4", "g2", None));
        assert_eq!(true, rm.has_link("u4", "g3", None));

        // test get_roles
        assert_eq!(vec!["g1"], rm.get_roles("u1", None));
        assert_eq!(vec!["g1"], rm.get_roles("u2", None));
        assert_eq!(vec!["g2"], rm.get_roles("u3", None));
        assert_eq!(vec!["g2", "g3"], sort_unstable(rm.get_roles("u4", None)));
        assert_eq!(vec!["g3"], rm.get_roles("g1", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g2", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g3", None));

        // test delete_link
        rm.delete_link("g1", "g3", None).unwrap();
        rm.delete_link("u4", "g2", None).unwrap();
        assert_eq!(true, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(false, rm.has_link("u1", "g3", None));
        assert_eq!(true, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(false, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(true, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(false, rm.has_link("u4", "g2", None));
        assert_eq!(true, rm.has_link("u4", "g3", None));
        assert_eq!(vec!["g1"], rm.get_roles("u1", None));
        assert_eq!(vec!["g1"], rm.get_roles("u2", None));
        assert_eq!(vec!["g2"], rm.get_roles("u3", None));
        assert_eq!(vec!["g3"], rm.get_roles("u4", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g1", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g2", None));
        assert_eq!(vec![String::new(); 0], rm.get_roles("g3", None));
    }

    #[test]
    fn test_clear() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", None);
        rm.add_link("u2", "g1", None);
        rm.add_link("u3", "g2", None);
        rm.add_link("u4", "g2", None);
        rm.add_link("u4", "g3", None);
        rm.add_link("g1", "g3", None);

        rm.clear();
        assert_eq!(false, rm.has_link("u1", "g1", None));
        assert_eq!(false, rm.has_link("u1", "g2", None));
        assert_eq!(false, rm.has_link("u1", "g3", None));
        assert_eq!(false, rm.has_link("u2", "g1", None));
        assert_eq!(false, rm.has_link("u2", "g2", None));
        assert_eq!(false, rm.has_link("u2", "g3", None));
        assert_eq!(false, rm.has_link("u3", "g1", None));
        assert_eq!(false, rm.has_link("u3", "g2", None));
        assert_eq!(false, rm.has_link("u3", "g3", None));
        assert_eq!(false, rm.has_link("u4", "g1", None));
        assert_eq!(false, rm.has_link("u4", "g2", None));
        assert_eq!(false, rm.has_link("u4", "g3", None));
    }

    #[test]
    fn test_domain_role() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", Some("domain1"));
        rm.add_link("u2", "g1", Some("domain1"));
        rm.add_link("u3", "admin", Some("domain2"));
        rm.add_link("u4", "admin", Some("domain2"));
        rm.add_link("u4", "admin", Some("domain1"));
        rm.add_link("g1", "admin", Some("domain1"));

        assert_eq!(true, rm.has_link("u1", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u1", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain2")));

        assert_eq!(true, rm.has_link("u2", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u2", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u3", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u3", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u3", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u3", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u4", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain2")));

        rm.delete_link("g1", "admin", Some("domain1")).unwrap();

        rm.delete_link("u4", "admin", Some("domain2")).unwrap();

        assert_eq!(true, rm.has_link("u1", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u1", "admin", Some("domain2")));

        assert_eq!(true, rm.has_link("u2", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u2", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u3", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u3", "g1", Some("domain2")));
        assert_eq!(false, rm.has_link("u3", "admin", Some("domain1")));
        assert_eq!(true, rm.has_link("u3", "admin", Some("domain2")));

        assert_eq!(false, rm.has_link("u4", "g1", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "g1", Some("domain2")));
        assert_eq!(true, rm.has_link("u4", "admin", Some("domain1")));
        assert_eq!(false, rm.has_link("u4", "admin", Some("domain2")));
    }

    #[test]
    fn test_users() {
        let mut rm = DefaultRoleManager::new(3);
        rm.add_link("u1", "g1", Some("domain1"));
        rm.add_link("u2", "g1", Some("domain1"));

        rm.add_link("u3", "g2", Some("domain2"));
        rm.add_link("u4", "g2", Some("domain2"));

        rm.add_link("u5", "g3", None);

        assert_eq!(
            vec!["u1", "u2"],
            sort_unstable(rm.get_users("g1", Some("domain1")))
        );
        assert_eq!(
            vec!["u3", "u4"],
            sort_unstable(rm.get_users("g2", Some("domain2")))
        );
        assert_eq!(vec!["u5"], rm.get_users("g3", None));
    }

    #[test]
    fn test_pattern_domain() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(3);
        rm.matching_fn(None, Some(key_match));
        rm.add_link("u1", "g1", Some("*"));

        assert!(rm.domain_has_role("u1", Some("domain2")));
    }

    #[test]
    fn test_basic_role_matching() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(Some(key_match), None);
        rm.add_link("bob", "book_group", None);
        rm.add_link("*", "book_group", None);
        rm.add_link("*", "pen_group", None);
        rm.add_link("eve", "pen_group", None);

        assert!(rm.has_link("alice", "book_group", None));
        assert!(rm.has_link("eve", "book_group", None));
        assert!(rm.has_link("bob", "book_group", None));

        assert_eq!(
            vec!["book_group", "pen_group"],
            sort_unstable(rm.get_roles("alice", None))
        );
    }

    #[test]
    fn test_basic_role_matching2() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(Some(key_match), None);
        rm.add_link("alice", "book_group", None);
        rm.add_link("alice", "*", None);
        rm.add_link("bob", "pen_group", None);

        assert!(rm.has_link("alice", "book_group", None));
        assert!(rm.has_link("alice", "pen_group", None));
        assert!(rm.has_link("bob", "pen_group", None));
        assert!(!rm.has_link("bob", "book_group", None));

        assert_eq!(
            vec!["*", "alice", "bob", "book_group", "pen_group"],
            sort_unstable(rm.get_roles("alice", None))
        );

        assert_eq!(vec!["alice"], sort_unstable(rm.get_users("*", None)));
    }

    #[test]
    fn test_cross_domain_role_inheritance_complex() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        rm.add_link("editor", "admin", Some("*"));
        rm.add_link("viewer", "editor", Some("*"));

        rm.add_link("alice", "editor", Some("domain1"));
        rm.add_link("bob", "viewer", Some("domain2"));

        assert!(rm.has_link("alice", "admin", Some("domain1")));
        assert!(rm.has_link("bob", "editor", Some("domain2")));
        assert!(rm.has_link("bob", "admin", Some("domain2")));

        rm.add_link("charlie", "viewer", Some("domain3"));
        assert!(rm.has_link("charlie", "editor", Some("domain3")));
        assert!(rm.has_link("charlie", "admin", Some("domain3")));

        rm.add_link("super_admin", "admin", Some("domain1"));
        assert!(rm.has_link("super_admin", "admin", Some("domain1")));
    }

    #[test]
    fn test_delete_pattern_domain_link() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        rm.add_link("alice", "admin", Some("*"));
        rm.add_link("bob", "admin", Some("domain2"));
        rm.add_link("admin", "super_admin", Some("domain2"));
        assert!(rm.has_link("alice", "admin", Some("domain2")));
        assert!(rm.has_link("alice", "super_admin", Some("domain2")));

        rm.delete_link("alice", "admin", Some("*")).unwrap();
        assert!(!rm.has_link("alice", "admin", Some("*")));
        assert!(!rm.has_link("alice", "admin", Some("domain2")));
        assert!(!rm.has_link("alice", "super_admin", Some("domain2")));
        assert!(rm.has_link("bob", "super_admin", Some("domain2")));

        rm.add_link("carol", "admin", Some("*"));
        rm.add_link("carol", "admin", Some("domain2"));
        rm.delete_link("carol", "admin", Some("*")).unwrap();
        assert!(rm.has_link("carol", "admin", Some("domain2")));
        assert!(!rm.has_link("carol", "admin", Some("domain3")));

        rm.add_link("dave", "admin", Some("*"));
        rm.add_link("dave", "admin", Some("domain2"));
        rm.delete_link("dave", "admin", Some("domain2")).unwrap();
        assert!(rm.has_link("dave", "super_admin", Some("domain2")));
    }

    #[test]
    fn test_concrete_tenants_are_isolated_under_wildcard() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        // Two concrete tenants plus a shared wildcard policy layer.
        rm.add_link("root", "platform", Some("*"));
        rm.add_link("eve", "admin", Some("tenantA"));
        rm.add_link("bob", "viewer", Some("tenantB"));

        // The private tenant-A grant must never appear in tenant B,
        // regardless of query ordering.
        assert!(rm.has_link("eve", "admin", Some("tenantA")));
        assert!(!rm.has_link("eve", "admin", Some("tenantB")));
        assert!(!rm
            .get_roles("eve", Some("tenantB"))
            .contains(&"admin".to_owned()));
        assert!(!rm
            .get_users("admin", Some("tenantB"))
            .contains(&"eve".to_owned()));

        // Adding the same grant on the wildcard domain must not retroactively
        // materialize it inside the concrete tenant graphs.
        rm.add_link("eve", "admin", Some("*"));
        assert!(rm.has_link("eve", "admin", Some("tenantB")));
        rm.delete_link("eve", "admin", Some("*")).unwrap();
        assert!(!rm.has_link("eve", "admin", Some("tenantB")));
        assert!(rm.has_link("eve", "admin", Some("tenantA")));

        // A tenant created after the wildcard grant was revoked sees the same
        // view as existing tenants: no stale edge survives anywhere.
        rm.add_link("carol", "viewer", Some("tenantC"));
        assert!(!rm.has_link("eve", "admin", Some("tenantC")));
    }

    #[test]
    fn test_wildcard_grant_removal_keeps_private_tenant_grant() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        rm.add_link("mallory", "admin", Some("*"));
        rm.add_link("mallory", "admin", Some("tenantA"));

        assert!(rm.has_link("mallory", "admin", Some("tenantB")));

        // Revoking only the shared grant leaves the private tenant-A grant
        // untouched and removes the inherited view in tenant B.
        rm.delete_link("mallory", "admin", Some("*")).unwrap();
        assert!(rm.has_link("mallory", "admin", Some("tenantA")));
        assert!(!rm.has_link("mallory", "admin", Some("tenantB")));
        assert!(!rm
            .get_roles("mallory", Some("tenantB"))
            .contains(&"admin".to_owned()));
    }

    #[test]
    fn test_wildcard_hierarchy_is_shared_but_tenant_edges_are_not() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        // Shared baseline hierarchy declared on the wildcard domain.
        rm.add_link("editor", "admin", Some("*"));
        rm.add_link("viewer", "editor", Some("*"));

        rm.add_link("alice", "editor", Some("domain1"));
        rm.add_link("bob", "viewer", Some("domain2"));

        // Both tenants inherit the approved shared hierarchy.
        assert!(rm.has_link("alice", "admin", Some("domain1")));
        assert!(rm.has_link("bob", "editor", Some("domain2")));
        assert!(rm.has_link("bob", "admin", Some("domain2")));

        // A private elevation in domain1 cannot be reached from domain2.
        rm.add_link("alice", "super_admin", Some("domain1"));
        assert!(rm.has_link("alice", "super_admin", Some("domain1")));
        assert!(!rm.has_link("alice", "super_admin", Some("domain2")));

        // Removing a shared hierarchy link is reflected everywhere at once.
        rm.delete_link("viewer", "editor", Some("*")).unwrap();
        assert!(!rm.has_link("bob", "editor", Some("domain2")));
        assert!(!rm.has_link("bob", "admin", Some("domain2")));
        assert!(rm.has_link("alice", "admin", Some("domain1")));
    }

    #[cfg(feature = "cached")]
    #[test]
    fn test_cached_views_stay_consistent_across_mutations() {
        use crate::model::key_match;
        let mut rm = DefaultRoleManager::new(10);
        rm.matching_fn(None, Some(key_match));

        rm.add_link("eve", "admin", Some("*"));
        assert!(rm.has_link("eve", "admin", Some("tenantB")));

        // The cached positive answer must be invalidated by the revocation;
        // reads and mutations share one tenant view.
        rm.delete_link("eve", "admin", Some("*")).unwrap();
        assert!(!rm.has_link("eve", "admin", Some("tenantB")));
        assert!(!rm.has_link("eve", "admin", Some("tenantA")));

        rm.add_link("eve", "admin", Some("tenantA"));
        assert!(rm.has_link("eve", "admin", Some("tenantA")));
        assert!(!rm.has_link("eve", "admin", Some("tenantB")));
    }
}
