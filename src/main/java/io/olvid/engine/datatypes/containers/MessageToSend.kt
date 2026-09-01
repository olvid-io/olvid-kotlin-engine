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
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey


class MessageToSend(
    @JvmField val ownedIdentity: Identity?,
    @JvmField val uid: UID?,
    @JvmField val server: String?,
    @JvmField val encryptedContent: EncryptedBytes?,
    @JvmField val encryptedExtendedContent: EncryptedBytes?,
    @JvmField val headers: Array<Header?>?,
    @JvmField val attachments: Array<Attachment?>?,
    @JvmField val isApplicationMessage: Boolean,
    @JvmField val isVoipMessage: Boolean
) {
    constructor(
        ownedIdentity: Identity?,
        uid: UID?,
        server: String?,
        encryptedContent: EncryptedBytes?,
        headers: Array<Header?>?,
        hasUserContent: Boolean
    ) : this(
        ownedIdentity,
        uid,
        server,
        encryptedContent,
        null,
        headers,
        arrayOfNulls<Attachment>(0),
        hasUserContent,
        false
    )

    class Header(
        @JvmField val deviceUid: UID?,
        @JvmField val toIdentity: Identity?,
        @JvmField val wrappedMessageKey: EncryptedBytes?
    ) {
    fun getDeviceUid(): UID? = deviceUid
    fun getToIdentity(): Identity? = toIdentity
}

    class Attachment(
        @JvmField val url: String?,
        @JvmField val isDeleteAfterSend: Boolean,
        @JvmField val attachmentLength: Long,
        @JvmField val key: AuthEncKey?
    ) {
    fun getUrl(): String? = url
    fun isDeleteAfterSend(): Boolean = isDeleteAfterSend
    fun getAttachmentLength(): Long = attachmentLength
}
    fun getOwnedIdentity(): Identity? = ownedIdentity
    fun getUid(): UID? = uid
    fun getServer(): String? = server
    fun getEncryptedContent(): EncryptedBytes? = encryptedContent
    fun getEncryptedExtendedContent(): EncryptedBytes? = encryptedExtendedContent
    fun getHeaders(): Array<Header?>? = headers
    fun getAttachments(): Array<Attachment?>? = attachments
    fun isApplicationMessage(): Boolean = isApplicationMessage
    fun isVoipMessage(): Boolean = isVoipMessage
}
