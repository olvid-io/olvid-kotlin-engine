/*
 *  Olvid Kotlin Engine
 *  Copyright © 2019-2026 Olvid SAS
 *
 *  This file is part of the Olvid Kotlin Engine.
 *
 *  The Olvid Kotlin Engine is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Affero General Public License, version 3,
 *  as published by the Free Software Foundation.
 *
 *  The Olvid Kotlin Engine is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Affero General Public License for more details.
 *
 *  You should have received a copy of the GNU Affero General Public License
 *  along with the Olvid Kotlin Engine.  If not, see <https://www.gnu.org/licenses/>.
 */
package io.olvid.engine.engine.types


class ObvContactDeviceCount(deviceCount: Int, establishedChannelCount: Int, preKeyCount: Int) {
    @JvmField val deviceCount: Int
    @JvmField val establishedChannelCount: Int
    @JvmField val preKeyCount: Int // this only counts device with a preKey that do not have an established channel

    init {
        this.deviceCount = deviceCount
        this.establishedChannelCount = establishedChannelCount
        this.preKeyCount = preKeyCount
    }
}
