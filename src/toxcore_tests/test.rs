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

//! File with testing helpers. **Use only in tests!**

/// Assert that function with given data fails with given error.
macro_rules! contains_err {
    ($func: path, $data: expr, $error: expr) => (
        { // ← ensure that expanded macro won't interfere with other code
            let e = format!("{:?}", $func($data).unwrap_err());
            assert!(e.contains($error),
                    format!("e: {}", e));
        }
    )
}
