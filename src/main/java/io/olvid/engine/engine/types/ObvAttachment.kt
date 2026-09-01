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

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.metamanager.NetworkFetchDelegate

class ObvAttachment internal constructor(
    metadata: ByteArray?,
    url: String?,
    uploadCancelledByTheSender: Boolean,
    downloadRequested: Boolean,
    ownedIdentity: Identity,
    messageUid: UID,
    messageServerTimestamp: Long,
    number: Int,
    expectedLength: Long,
    receivedLength: Long
) {
    @JvmField val metadata: ByteArray?
    @JvmField val url: String? // should always be the getNoBackupFilesDir() relative path to the file
    @JvmField val uploadCancelledByTheSender: Boolean
    @JvmField val downloadRequested: Boolean
    @JvmField val ownedIdentity: Identity
    @JvmField val messageUid: UID
    @JvmField val messageServerTimestamp: Long
    @JvmField val number: Int
    @JvmField val expectedLength: Long
    @JvmField val receivedLength: Long

    fun getMetadata(): ByteArray? {
        return metadata
    }

    fun getUrl(): String? {
        return url
    }

    val isUploadCancelledByTheSender: Boolean
        get() = uploadCancelledByTheSender

    fun isDownloadRequested(): Boolean {
        return downloadRequested
    }

    fun getMessageServerTimestamp(): Long {
        return messageServerTimestamp
    }

    fun getBytesOwnedIdentity(): ByteArray? {
        return ownedIdentity.getBytes()
    }

    fun getOwnedIdentity(): Identity {
        return ownedIdentity
    }

    fun getMessageUid(): UID {
        return messageUid
    }

    val messageIdentifier: ByteArray? get() = messageUid.bytes

    fun getNumber(): Int {
        return number
    }

    fun getExpectedLength(): Long {
        return expectedLength
    }

    fun getReceivedLength(): Long {
        return receivedLength
    }


    init {
        this.metadata = metadata
        this.url = url
        this.uploadCancelledByTheSender = uploadCancelledByTheSender
        this.downloadRequested = downloadRequested
        this.ownedIdentity = ownedIdentity
        this.messageUid = messageUid
        this.messageServerTimestamp = messageServerTimestamp
        this.number = number
        this.expectedLength = expectedLength
        this.receivedLength = receivedLength
    }

    companion object {
        fun create(
            networkFetchDelegate: NetworkFetchDelegate,
            ownedIdentity: Identity?,
            messageUid: UID?,
            attachmentNumber: Int
        ): ObvAttachment? {
            val receivedAttachment =
                networkFetchDelegate.getAttachment(ownedIdentity, messageUid, attachmentNumber)
                    ?: return null
            val receivedMessage =
                networkFetchDelegate.getMessage(ownedIdentity, receivedAttachment.getMessageUid())
                    ?: return null

            return ObvAttachment(
                receivedAttachment.getMetadata(),
                receivedAttachment.getUrl(),
                receivedAttachment.isUploadCancelledByTheSender(),
                receivedAttachment.isDownloadRequested(),
                receivedAttachment.getOwnedIdentity()!!,
                receivedAttachment.getMessageUid()!!,
                receivedMessage.getServerTimestamp(),
                receivedAttachment.getAttachmentNumber(),
                receivedAttachment.getExpectedLength(),
                receivedAttachment.getReceivedLength()
            )
        }
    }
}
