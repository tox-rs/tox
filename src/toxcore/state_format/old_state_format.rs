/*
    Copyright © 2016 Zetok Zalbavar <zexavexxe@gmail.com>

    This file is part of Tox.

    Tox is libre software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Tox is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Tox.  If not, see <http://www.gnu.org/licenses/>.
*/

//! Old state format. *Will be deprecated when something better will be
//! implemented.*

// TODO: improve docs

/** Sections of the old state format.

https://zetok.github.io/tox-spec/#sections
*/
pub enum SectionKind {
    /// Section for [`NoSpam`](../../toxid/struct.NoSpam.html), public and
    /// secret keys.
    NospamKeys =    0x01,
    /// Section for DHT-related data.
    DHT =           0x02,
    /// Section for friends data.
    Friends =       0x03,
    /// Section for own name.
    Name =          0x04,
    /// Section for own status message.
    StatusMessage = 0x05,
    /// Section for own status.
    Status =        0x06,
    /// Section for a list of TCP relays.
    TcpRelays =     0x0a,
    /// Section for a list of path nodes for onion routing.
    PathNodes =     0x0b,
    /// End of file.
    Eof =           0xff,
}
