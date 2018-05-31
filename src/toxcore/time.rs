/*
    Copyright (C) 2013 Tox project All Rights Reserved.
    Copyright © 2018 Evgeny Kurnevsky <kurnevsky@gmail.com>

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

//! Functions to work with time

use std::time::{SystemTime, UNIX_EPOCH};

/// Return number of seconds that have elapsed since Unix epoch.
pub fn unix_time(time: SystemTime) -> u64 {
    let since_the_epoch = time.duration_since(UNIX_EPOCH)
        .expect("Current time is earlier than Unix epoch");
    since_the_epoch.as_secs()
}
