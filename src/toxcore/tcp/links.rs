/*! The implementation of links used by server and clients
*/

use crate::toxcore::crypto_core::*;

use std::collections::HashMap;

/// This constant is defined by c-toxcore
pub const MAX_LINKS_N: u8 = 240;

/// The status of the Link
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum LinkStatus {
    /// The link is registered on one side only.
    ///
    /// We received `RouteResponse` packet with connection id but can't use it
    /// until we get `ConnectNotification` packet.
    Registered,
    /// The link is registered on both sides: both clients are linked.
    /// It means that both clients sent RouteRequest and received ConnectNotification
    Online,
}

#[derive(Debug, Clone, Copy)]
pub struct Link {
    /// The link is linked with the given PK
    pub pk: PublicKey,
    /// The status of the link
    pub status: LinkStatus,
}

impl Link {
    /// Create a new link with the given PK and with status = Registered
    fn new(pk: PublicKey) -> Link {
        Link {
            pk,
            status: LinkStatus::Registered,
        }
    }
    /// Change status to Registered
    fn downgrade(&mut self) {
        self.status = LinkStatus::Registered;
    }
    /// Change status to Online
    fn upgrade(&mut self) {
        self.status = LinkStatus::Online;
    }
}

/// The structure contains `MAX_LINKS_N` of links
pub struct Links {
    /** An array of Link with `MAX_LINKS_N` item
    None means there is a hole and you can allocate the `Link`
    and respond the id with RouteResponse. Packets like `Data`
    use connection_id as an index for links.
    */
    links: [Option<Link>; MAX_LINKS_N as usize],
    /// Map PK -> id to index links with O(1)
    pk_to_id: HashMap<PublicKey, u8>,
}

impl Default for Links {
    fn default() -> Self {
        Links::new()
    }
}

impl Links {
    /// Create empty `Links`
    pub fn new() -> Links {
        Links {
            links: [None; 240],
            pk_to_id: HashMap::new()
        }
    }
    /** Try to find a hole inside `links` and insert a new `Link` to the given PK
    Return `Some(id)` if there was a `Link` or if there is a room for a new `Link`
    Return `None` if there is no room for a new `Link`
    */
    pub fn insert(&mut self, pk: &PublicKey) -> Option<u8> {
        let possible_index = { self.pk_to_id.get(pk).cloned() };
        match possible_index {
            Some(index) => Some(index), // already inserted
            None => {
                if let Some(index) = self.links.iter().position(|link| link.is_none()) {
                    let link = Link::new(*pk);
                    self.links[index] = Some(link);
                    self.pk_to_id.insert(*pk, index as u8);
                    Some(index as u8)
                } else {
                    // no enough room for a link
                    None
                }
            }
        }
    }
    /** Try to insert a new `Link` to the given PK at links[id]
    Return true if succeeded to insert a new `Link`
    Return false if there is a `Link` with such PK or there is no hole at links[id]
    */
    pub fn insert_by_id(&mut self, pk: &PublicKey, index: u8) -> bool {
        assert!(index < MAX_LINKS_N, "The index {} must be lower than {}", index, MAX_LINKS_N);
        if !self.pk_to_id.contains_key(pk) && self.links[index as usize].is_none() {
            let link = Link::new(*pk);
            self.links[index as usize] = Some(link);
            self.pk_to_id.insert(*pk, index);
            true
        } else {
            false
        }
    }
    /// Get `Link` by id
    pub fn by_id(&self, index: u8) -> Option<&Link> {
        if index < MAX_LINKS_N {
            self.links[index as usize].as_ref()
        } else {
            None
        }
    }
    /// Get index of the link by PK
    pub fn id_by_pk(&self, pk: &PublicKey) -> Option<u8> {
        self.pk_to_id.get(pk).cloned()
    }
    /// Takes the link out of the links, leaving a None in its place
    pub fn take(&mut self, index: u8) -> Option<Link> {
        if index < MAX_LINKS_N {
            if let Some(link) = self.links[index as usize].take() {
                self.pk_to_id.remove(&link.pk);
                Some(link)
            } else {
                None
            }
        } else {
            None
        }
    }
    /// Call Links::downgrade on the `Link` by id
    /// Return false of links[id] is None
    pub fn downgrade(&mut self, index: u8) -> bool {
        assert!(index < MAX_LINKS_N, "The index {} must be lower than {}", index, MAX_LINKS_N);
        if let Some(ref mut link) = self.links[index as usize] {
            link.downgrade();
            true
        } else {
            false
        }
    }
    /// Call Links::upgrade on the `Link` by id
    /// Return false of links[id] is None
    pub fn upgrade(&mut self, index: u8) -> bool {
        assert!(index < MAX_LINKS_N, "The index {} must be lower than {}", index, MAX_LINKS_N);
        if let Some(ref mut link) = self.links[index as usize] {
            link.upgrade();
            true
        } else {
            false
        }
    }
    /// Iter over each non-empty link in self.links
    pub fn iter_links(&self) -> impl Iterator<Item = Link> + '_ {
        self.links.iter().filter_map(|&link| link)
    }
    /// Clear links
    pub fn clear(&mut self) {
        self.links = [None; 240];
        self.pk_to_id.clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::toxcore::crypto_core::*;
    use crate::toxcore::tcp::links::*;

    #[test]
    fn link_new() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let link = Link::new(pk);
        assert_eq!(LinkStatus::Registered, link.status);
        assert_eq!(pk, link.pk);
    }

    #[test]
    fn link_upgrade() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut link = Link::new(pk);
        link.upgrade();
        assert_eq!(LinkStatus::Online, link.status);
    }

    #[test]
    fn link_downgrade() {
        crypto_init().unwrap();
        let (pk, _) = gen_keypair();
        let mut link = Link::new(pk);
        link.upgrade();
        link.downgrade();
        assert_eq!(LinkStatus::Registered, link.status);
    }

    #[test]
    fn links_new() {
        let links = Links::new();
        assert!(links.links.iter().all(|link| link.is_none()));
        assert!(links.pk_to_id.is_empty());
    }

    #[test]
    fn links_default() {
        let links = Links::default();
        assert!(links.links.iter().all(|link| link.is_none()));
        assert!(links.pk_to_id.is_empty());
    }

    #[test]
    fn links_insert_240() {
        crypto_init().unwrap();
        let mut links = Links::new();
        for _ in 0..240 {
            // The first 240 must be inserted successfully
            let (pk, _) = gen_keypair();
            let id = links.insert(&pk);
            assert!(id.is_some());
        }
        let (pk, _) = gen_keypair();
        let id = links.insert(&pk);
        assert!(id.is_none());
    }

    #[test]
    fn links_insert_same_pk() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk, _) = gen_keypair();
        let id1 = links.insert(&pk);
        let id2 = links.insert(&pk);

        assert!(id1.is_some());
        assert_eq!(id1, id2);
    }

    #[test]
    fn links_insert_alloc_order() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk1, _) = gen_keypair();
        let id1 = links.insert(&pk1).unwrap();

        let (pk2, _) = gen_keypair();
        let id2 = links.insert(&pk2).unwrap();

        // Two links inserted, the id of the 1st is 0, the id of the 2nd is 1
        assert_eq!(id1, 0);
        assert_eq!(id2, 1);

        // Remove link[0]
        links.take(0);

        // Insert a third link
        let (pk3, _) = gen_keypair();
        let id3 = links.insert(&pk3).unwrap();

        // The id of the link must be 0
        assert_eq!(id3, 0);
    }

    #[test]
    fn links_insert_by_id() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk1, _) = gen_keypair();
        let (pk2, _) = gen_keypair();

        let id1 = links.insert(&pk1).unwrap();

        assert_eq!(links.insert_by_id(&pk1, id1+1), false);
        assert_eq!(links.insert_by_id(&pk2, id1), false);
        assert_eq!(links.insert_by_id(&pk2, id1+1), true);

        assert_eq!(links.by_id(id1+1).unwrap().pk, pk2);
    }


    #[test]
    fn links_by_id() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk, _) = gen_keypair();
        let id = links.insert(&pk).unwrap();

        assert_eq!(pk, links.by_id(id).unwrap().pk);
    }

    #[test]
    fn links_by_id_nonexistent() {
        crypto_init().unwrap();
        let links = Links::new();

        assert!(links.by_id(MAX_LINKS_N as u8 + 1).is_none());
    }

    #[test]
    fn links_by_pk() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk, _) = gen_keypair();
        let id = links.insert(&pk);

        assert_eq!(id, links.id_by_pk(&pk));
    }

    #[test]
    fn links_upgrade() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk, _) = gen_keypair();
        let id = links.insert(&pk).unwrap();

        assert_eq!(LinkStatus::Registered, links.by_id(id).unwrap().status);

        assert_eq!(links.upgrade(id), true); // try to upgrade an existent link

        assert_eq!(LinkStatus::Online, links.by_id(id).unwrap().status);

        assert_eq!(links.upgrade(id+1), false); // try to upgrade an nonexistent link
    }

    #[test]
    fn links_downgrade() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk, _) = gen_keypair();
        let id = links.insert(&pk).unwrap();

        assert_eq!(LinkStatus::Registered, links.by_id(id).unwrap().status);

        links.upgrade(id);
        assert_eq!(links.downgrade(id), true); // try to downgrade an existent link

        assert_eq!(LinkStatus::Registered, links.by_id(id).unwrap().status);

        assert_eq!(links.downgrade(id+1), false); // try to downgrade an nonexistent link
    }

    #[test]
    fn links_take() {
        crypto_init().unwrap();
        let mut links = Links::new();

        let (pk, _) = gen_keypair();
        let id = links.insert(&pk).unwrap();

        assert!(links.by_id(id).is_some());

        let link = links.take(id);
        assert_eq!(pk, link.unwrap().pk);

        assert!(links.by_id(id).is_none());
    }

    #[test]
    fn links_take_nonexistent() {
        crypto_init().unwrap();
        let mut links = Links::new();

        assert!(links.take(MAX_LINKS_N as u8 + 1).is_none());
    }

    #[test]
    fn links_clear() {
        crypto_init().unwrap();
        let mut links = Links::new();
        for _ in 0..240 {
            // The first 240 must be inserted successfully
            let (pk, _) = gen_keypair();
            let id = links.insert(&pk);
            assert!(id.is_some());
        }

        // check links are non empty
        for i in 0..240 {
            assert!(links.by_id(i).is_some());
        }

        links.clear();

        // check links are empty
        for i in 0..240 {
            assert!(links.by_id(i).is_none());
        }
    }
}
