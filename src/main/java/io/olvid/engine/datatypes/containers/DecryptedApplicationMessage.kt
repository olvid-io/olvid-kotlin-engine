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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID

class DecryptedApplicationMessage(
    @JvmField val messageUid: UID?,
    @JvmField val messagePayload: ByteArray?,
    @JvmField val fromIdentity: Identity?,
    @JvmField val fromDeviceUid: UID?,
    @JvmField val toIdentity: Identity?,
    @JvmField val serverTimestamp: Long,
    @JvmField val downloadTimestamp: Long,
    @JvmField val localDownloadTimestamp: Long
) {
    fun getMessageUid(): UID? = messageUid
    fun getMessagePayload(): ByteArray? = messagePayload
    fun getFromIdentity(): Identity? = fromIdentity
    fun getFromDeviceUid(): UID? = fromDeviceUid
    fun getToIdentity(): Identity? = toIdentity
    fun getServerTimestamp(): Long = serverTimestamp
    fun getDownloadTimestamp(): Long = downloadTimestamp
    fun getLocalDownloadTimestamp(): Long = localDownloadTimestamp
}
