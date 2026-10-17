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
package io.olvid.engine.datatypes.containers

import io.olvid.engine.datatypes.KeyId
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey


class AuthEncKeyAndChannelInfo(
    @JvmField val authEncKey: AuthEncKey?,
    @JvmField val receptionChannelInfo: ReceptionChannelInfo?,
    // only set for messages received through a pre-key channel: used to prevent the replay of these messages
    @JvmField val preKeyId: KeyId? = null,
    @JvmField val preKeySignature: ByteArray? = null,
) {
    fun getAuthEncKey(): AuthEncKey? = authEncKey
    fun getReceptionChannelInfo(): ReceptionChannelInfo? = receptionChannelInfo
}
