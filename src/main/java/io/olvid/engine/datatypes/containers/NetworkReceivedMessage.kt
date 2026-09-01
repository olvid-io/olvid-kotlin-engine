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

import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID


class NetworkReceivedMessage(
    @JvmField val messageUid: UID?,
    @JvmField val serverTimestamp: Long,
    @JvmField val encryptedContent: EncryptedBytes?,
    @JvmField val header: Header,
    private val hasExtendedPayload: Boolean
) {
    val ownedIdentity: Identity?
        get() = header.ownedIdentity

    fun hasExtendedPayload(): Boolean {
        return hasExtendedPayload
    }

    class Header(@JvmField val ownedIdentity: Identity?, @JvmField val wrappedKey: EncryptedBytes?) {
    fun getOwnedIdentity(): Identity? = ownedIdentity
    fun getWrappedKey(): EncryptedBytes? = wrappedKey
}
    fun getMessageUid(): UID? = messageUid
    fun getServerTimestamp(): Long = serverTimestamp
    fun getEncryptedContent(): EncryptedBytes? = encryptedContent
    fun getHeader(): Header = header
}
