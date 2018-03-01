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

/*! State format – for saving / loading data across restarts.

*Currently there's only supported old, custom binary format used by toxcore. At
some point it will be deprecated in favour of something better.*

*After deprecation of the old format there will be a period where it still will
be supported. After deprecation period code for handling old format will be
moved out of toxcore into a separate library and maintained there.*

https://zetok.github.io/tox-spec/#state-format
*/


// FIXME: use new dht code instead of old
// pub mod old;
