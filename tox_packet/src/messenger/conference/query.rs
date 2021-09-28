/*! Peer query message struct.
*/

use super::*;

use nom::number::complete::be_u16;
use nom::bytes::complete::tag;

/** Query is a struct that holds info to query a peer in a conference.

Serialized form:

Length    | Content
--------- | ------
`1`       | `0x62`
`2`       | `conference id`
`1`       | `0x08`

*/
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Query(pub u16);

impl FromBytes for Query {
    fn from_bytes(input: &[u8]) -> IResult<&[u8], Self> {
        let (input, _) = tag("\x62")(input)?;
        let (input, conference_id) = be_u16(input)?;
        let (input, _) = tag("\x08")(input)?;
        Ok((input, Query(conference_id)))
    }
}

impl ToBytes for Query {
    fn to_bytes<'a>(&self, buf: (&'a mut [u8], usize)) -> Result<(&'a mut [u8], usize), GenError> {
        do_gen!(buf,
            gen_be_u8!(0x62) >>
            gen_be_u16!(self.0) >>
            gen_be_u8!(0x08)
        )
    }
}

impl Query {
    /// Create new Query object.
    pub fn new(conference_id: u16) -> Self {
        Query(conference_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    encode_decode_test!(
        peer_query_encode_decode,
        Query::new(1)
    );
}
