/*! The implementation of packets buffer
*/

use std::iter;

use crate::toxcore::net_crypto::errors::*;

/// Maximum size of receiving and sending packet buffers.
///
/// Must be a power of 2. The reason of this requirement is that `buffer_start`
/// and `buffer_end` indexes are unsigned 32 integers and might be overflowed.
/// When overflow happens the buffer should be used from the beginning but it's
/// possible only if `u32::MAX` is divided by buffer size, i.e. buffer size is a
/// power of 2.
pub const CRYPTO_PACKET_BUFFER_SIZE: u32 = 32768;

/// Calculate real index in the buffer by the packet index
fn real_index(index: u32) -> usize {
    (index % CRYPTO_PACKET_BUFFER_SIZE) as usize
}

/// Deque-like struct for packets queue that allows random writings by the
/// packet index
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PacketsArray<T> {
    /// Packets buffer of `CRYPTO_PACKET_BUFFER_SIZE` length
    pub buffer: Vec<Option<Box<T>>>,
    /// Start packet index.
    ///
    /// Can be any `u32` value regardless of the buffer size. Real index is
    /// calculated via `real_index` function.
    pub buffer_start: u32,
    /// End packet index.
    ///
    /// Can be any `u32` value regardless of the buffer size. Real index is
    /// calculated via `real_index` function.
    pub buffer_end: u32,
}

impl<T: Clone> Default for PacketsArray<T> {
    fn default() -> Self {
        PacketsArray::new()
    }
}

impl<T: Clone> PacketsArray<T> {
    /// Create new `PacketsArray`
    pub fn new() -> PacketsArray<T> {
        PacketsArray {
            buffer: iter::repeat(None).take(CRYPTO_PACKET_BUFFER_SIZE as usize).collect(),
            buffer_start: 0,
            buffer_end: 0,
        }
    }
}

impl<T> PacketsArray<T> {
    /// Get difference between end and start indices of stored packets in this
    /// array.
    ///
    /// This value is equal to known gap between sent by one side and received
    /// by other side packets. Also note that this value is not necessary equal
    /// to count of packets that are stored in this array because packets are
    /// not necessary stored sequentially.
    pub fn len(&self) -> u32 {
        self.buffer_end.overflowing_sub(self.buffer_start).0
    }

    /// Insert packet to the array by its index
    ///
    /// Returns an error when index is too far and buffer can't hold it or when
    /// packet with this index already exists
    pub fn insert(&mut self, index: u32, packet: T) -> Result<(), PacketsArrayError> {
        if index.overflowing_sub(self.buffer_start).0 >= CRYPTO_PACKET_BUFFER_SIZE {
            return Err(PacketsArrayError::too_big(index))
        }

        let i = real_index(index);

        if self.buffer[i].is_some() {
            return Err(PacketsArrayError::already_exist(index))
        }

        self.buffer[i] = Some(Box::new(packet));
        if index.overflowing_sub(self.buffer_start).0 >= self.len() {
            self.buffer_end = index.overflowing_add(1).0;
        }

        Ok(())
    }

    /// Write packet at the end index and increment this index
    ///
    /// Returns an error when the buffer is full
    pub fn push_back(&mut self, packet: T) -> Result<(), PacketsArrayError> {
        if self.len() == CRYPTO_PACKET_BUFFER_SIZE {
            return Err(PacketsArrayError::from(PacketsArrayErrorKind::ArrayFull))
        }

        self.buffer[real_index(self.buffer_end)] = Some(Box::new(packet));
        self.buffer_end = self.buffer_end.overflowing_add(1).0;

        Ok(())
    }

    /// Get packet at the start index and increment index if the packet exists
    pub fn pop_front(&mut self) -> Option<T> {
        if self.buffer_start == self.buffer_end {
            return None
        }

        let i = real_index(self.buffer_start);
        let result = self.buffer[i].take();
        if result.is_some() {
            self.buffer_start = self.buffer_start.overflowing_add(1).0;
        };
        result.map(|packet| *packet)
    }

    /// Check if packet the index exists
    pub fn contains(&self, index: u32) -> bool {
        let len = self.len();

        if self.buffer_end.overflowing_sub(index).0 > len || index.overflowing_sub(self.buffer_start).0 >= len {
            return false
        }

        self.buffer[real_index(index)].is_some()
    }

    /// Get reference to the packet by its index
    pub fn get(&self, index: u32) -> Option<&T> {
        let len = self.len();

        if self.buffer_end.overflowing_sub(index).0 > len || index.overflowing_sub(self.buffer_start).0 >= len {
            return None
        }

        self.buffer[real_index(index)].as_ref().map(|packet| &**packet)
    }

    /// Get mutable reference to the packet by its index
    pub fn get_mut(&mut self, index: u32) -> Option<&mut T> {
        let len = self.len();

        if self.buffer_end.overflowing_sub(index).0 > len || index.overflowing_sub(self.buffer_start).0 >= len {
            return None
        }

        self.buffer[real_index(index)].as_mut().map(|packet| &mut **packet)
    }

    /// Remove packet by its index and return it if it was previously in the
    /// array
    pub fn remove(&mut self, index: u32) -> Option<T> {
        let len = self.len();

        if self.buffer_end.overflowing_sub(index).0 > len || index.overflowing_sub(self.buffer_start).0 >= len {
            return None
        }

        self.buffer[real_index(index)].take().map(|packet| *packet)
    }

    /// Set end index when it gets known
    ///
    /// Returns an error when index is too far and buffer can't hold it or when
    /// index is lower then end index
    pub fn set_buffer_end(&mut self, index: u32) -> Result<(), PacketsArrayError> {
        if index.overflowing_sub(self.buffer_start).0 > CRYPTO_PACKET_BUFFER_SIZE {
            return Err(PacketsArrayError::too_big(index))
        }

        if index.overflowing_sub(self.buffer_end).0 > CRYPTO_PACKET_BUFFER_SIZE {
            return Err(PacketsArrayError::lower_index(index))
        }

        self.buffer_end = index;

        Ok(())
    }

    /// Set start index removing all packet before this index
    ///
    /// Returns an error when index is outside of buffer bounds
    pub fn set_buffer_start(&mut self, index: u32) -> Result<(), PacketsArrayError> {
        let len = self.len();

        if self.buffer_end.overflowing_sub(index).0 > len || index.overflowing_sub(self.buffer_start).0 > len {
            return Err(PacketsArrayError::outside_index(index))
        }

        for packet in &mut self.buffer[real_index(self.buffer_start) .. real_index(index)] {
            *packet = None;
        }

        self.buffer_start = index;

        Ok(())
    }

    /// Get mutable iterator over all stored packets with their index.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u32, &mut T)> {
        let buffer_start = self.buffer_start;
        let start = real_index(buffer_start);
        let end = real_index(self.buffer_end);
        let iter = if start > end {
            let (first, second) = self.buffer.split_at_mut(start);
            second.iter_mut().chain(first.iter_mut().take(end))
        } else {
            [].iter_mut().chain(self.buffer[start ..].iter_mut().take(end - start))
        };
        iter.enumerate().flat_map(move |(i, packet)|
            packet.iter_mut().map(move |packet|
                (buffer_start.overflowing_add(i as u32).0, &mut **packet)
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len() {
        let mut array = PacketsArray::<()>::new();
        assert_eq!(array.len(), 0);
        array.buffer_end = 1;
        assert_eq!(array.len(), 1);
        array.buffer_start = u32::max_value();
        assert_eq!(array.len(), 2);
    }

    #[test]
    fn insert() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.insert(0, ()).is_ok());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 1);
        assert!(array.get(0).is_some());
        assert!(array.get(1).is_none());
        assert!(array.insert(7, ()).is_ok());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 8);
        assert!(array.get(7).is_some());
        assert!(array.get(6).is_none());
        assert!(array.get(8).is_none());
    }

    #[test]
    fn insert_exists() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.insert(7, ()).is_ok());
        let res = array.insert(7, ());
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::AlreadyExist { index: 7 });
        assert!(array.insert(6, ()).is_ok());
        assert!(array.insert(8, ()).is_ok());
    }

    #[test]
    fn insert_too_big_index() {
        let mut array = PacketsArray::<()>::new();
        let res = array.insert(CRYPTO_PACKET_BUFFER_SIZE, ());
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::TooBig { index: CRYPTO_PACKET_BUFFER_SIZE });
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 0);
        array.buffer_start = u32::max_value();
        let res = array.insert(CRYPTO_PACKET_BUFFER_SIZE - 1, ());
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::TooBig { index: CRYPTO_PACKET_BUFFER_SIZE - 1 });
        assert_eq!(array.buffer_start, u32::max_value());
        assert_eq!(array.buffer_end, 0);
    }

    #[test]
    fn push_back() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.push_back(()).is_ok());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 1);
        assert!(array.get(0).is_some());
    }

    #[test]
    fn push_back_overflow() {
        let mut array = PacketsArray::<()>::new();
        array.buffer_start = u32::max_value();
        array.buffer_end = u32::max_value();
        assert!(array.push_back(()).is_ok());
        assert_eq!(array.buffer_start, u32::max_value());
        assert_eq!(array.buffer_end, 0);
        assert!(array.get(u32::max_value()).is_some());
    }

    #[test]
    fn push_back_full() {
        let mut array = PacketsArray::<()>::new();
        array.buffer_end = CRYPTO_PACKET_BUFFER_SIZE;
        let res = array.push_back(());
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::ArrayFull);
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, CRYPTO_PACKET_BUFFER_SIZE);
    }

    #[test]
    fn pop_front_some() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.push_back(()).is_ok());
        assert!(array.pop_front().is_some());
        assert_eq!(array.buffer_start, 1);
        assert_eq!(array.buffer_end, 1);
        assert!(array.get(0).is_none());
    }

    #[test]
    fn pop_front_none() {
        let mut array = PacketsArray::<()>::new();
        array.buffer_end = 1;
        assert!(array.pop_front().is_none());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 1);
    }

    #[test]
    fn pop_front_empty() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.pop_front().is_none());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 0);
    }

    #[test]
    fn contains() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.push_back(()).is_ok());
        assert!(array.contains(0));
        assert!(!array.contains(1));
        assert!(!array.contains(2));
    }

    #[test]
    fn get() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.push_back(()).is_ok());
        assert!(array.get(0).is_some());
        assert!(array.get(1).is_none());
        assert!(array.get(2).is_none());
    }

    #[test]
    fn get_mut() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.push_back(()).is_ok());
        assert!(array.get_mut(0).is_some());
        assert!(array.get_mut(1).is_none());
        assert!(array.get_mut(2).is_none());
    }

    #[test]
    fn remove() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.push_back(()).is_ok());
        assert!(array.remove(0).is_some());
        assert!(array.remove(0).is_none());
        assert!(array.remove(1).is_none());
        assert!(array.remove(2).is_none());
        assert!(array.get(0).is_none());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 1);
    }

    #[test]
    fn set_buffer_end() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.set_buffer_end(7).is_ok());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 7);
        assert!(array.set_buffer_end(CRYPTO_PACKET_BUFFER_SIZE).is_ok());
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, CRYPTO_PACKET_BUFFER_SIZE);
    }

    #[test]
    fn set_buffer_end_too_big_index() {
        let mut array = PacketsArray::<()>::new();
        let res = array.set_buffer_end(CRYPTO_PACKET_BUFFER_SIZE + 1);
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::TooBig { index: CRYPTO_PACKET_BUFFER_SIZE + 1 });
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 0);
    }

    #[test]
    fn set_buffer_end_lower_than_end_index() {
        let mut array = PacketsArray::<()>::new();
        array.buffer_end = 7;
        let res = array.set_buffer_end(6);
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::LowerIndex { index: 6 });
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 7);
    }

    #[test]
    fn set_buffer_start() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.push_back(()).is_ok());
        assert!(array.push_back(()).is_ok());
        assert!(array.set_buffer_start(1).is_ok());
        assert!(array.set_buffer_start(1).is_ok());
        assert!(array.get(0).is_none());
        assert!(array.get(1).is_some());
        assert_eq!(array.buffer_start, 1);
        assert_eq!(array.buffer_end, 2);
        assert!(array.set_buffer_start(2).is_ok());
        assert!(array.set_buffer_start(2).is_ok());
        assert!(array.get(0).is_none());
        assert!(array.get(1).is_none());
        assert_eq!(array.buffer_start, 2);
        assert_eq!(array.buffer_end, 2);
    }

    #[test]
    fn set_buffer_start_too_big_index() {
        let mut array = PacketsArray::<()>::new();
        let res = array.set_buffer_start(1);
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::OutsideIndex { index: 1 });
        assert_eq!(array.buffer_start, 0);
        assert_eq!(array.buffer_end, 0);
    }

    #[test]
    fn set_buffer_start_lower_than_start_index() {
        let mut array = PacketsArray::<()>::new();
        array.buffer_start = 7;
        array.buffer_end = 7;
        let res = array.set_buffer_start(1);
        assert!(res.is_err());
        assert_eq!(*res.err().unwrap().kind(), PacketsArrayErrorKind::OutsideIndex { index: 1 });
        assert_eq!(array.buffer_start, 7);
        assert_eq!(array.buffer_end, 7);
    }

    #[test]
    fn iter_mut_empty() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.iter_mut().next().is_none());
    }

    #[test]
    fn iter_mut_single_part() {
        let mut array = PacketsArray::<()>::new();
        assert!(array.insert(0, ()).is_ok());
        assert!(array.insert(2, ()).is_ok());
        assert!(array.insert(5, ()).is_ok());
        assert_eq!(
            array.iter_mut().map(|(i, _)| i).collect::<Vec<_>>(),
            vec![0, 2, 5]
        );
    }

    #[test]
    fn iter_mut_two_parts() {
        let mut array = PacketsArray::<()>::new();
        array.buffer_start = CRYPTO_PACKET_BUFFER_SIZE - 1;
        array.buffer_end = CRYPTO_PACKET_BUFFER_SIZE + 3;
        assert!(array.insert(CRYPTO_PACKET_BUFFER_SIZE - 1, ()).is_ok());
        assert!(array.insert(CRYPTO_PACKET_BUFFER_SIZE, ()).is_ok());
        assert!(array.insert(CRYPTO_PACKET_BUFFER_SIZE + 2, ()).is_ok());
        assert_eq!(
            array.iter_mut().map(|(i, _)| i).collect::<Vec<_>>(),
            vec![
                CRYPTO_PACKET_BUFFER_SIZE - 1,
                CRYPTO_PACKET_BUFFER_SIZE,
                CRYPTO_PACKET_BUFFER_SIZE + 2,
            ]
        );
    }
}
