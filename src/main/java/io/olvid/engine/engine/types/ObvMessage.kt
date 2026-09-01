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

import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.DecryptedApplicationMessage
import io.olvid.engine.datatypes.containers.ReceivedAttachment

class ObvMessage(
    receivedMessage: DecryptedApplicationMessage,
    receivedAttachments: Array<ReceivedAttachment>
) {
    @JvmField val messageUid: UID?
    @JvmField val serverTimestamp: Long
    @JvmField val downloadTimestamp: Long
    @JvmField val localDownloadTimestamp: Long
    @JvmField val messagePayload: ByteArray?
    @JvmField val bytesFromIdentity: ByteArray?
    @JvmField val bytesFromDeviceUid: ByteArray?
    @JvmField val bytesToIdentity: ByteArray?
    @JvmField val attachments: Array<ObvAttachment?>


    val identifier: ByteArray? get() = messageUid?.bytes

    fun getServerTimestamp(): Long {
        return serverTimestamp
    }

    fun getDownloadTimestamp(): Long {
        return downloadTimestamp
    }

    fun getLocalDownloadTimestamp(): Long {
        return localDownloadTimestamp
    }

    fun getMessagePayload(): ByteArray? {
        return messagePayload
    }

    fun getBytesFromIdentity(): ByteArray? {
        return bytesFromIdentity
    }

    fun getBytesFromDeviceUid(): ByteArray? {
        return bytesFromDeviceUid
    }

    fun getBytesToIdentity(): ByteArray? {
        return bytesToIdentity
    }

    fun getAttachments(): Array<ObvAttachment?> {
        return attachments
    }

    init {
        this.messageUid = receivedMessage.getMessageUid()
        this.messagePayload = receivedMessage.getMessagePayload()
        this.serverTimestamp = receivedMessage.getServerTimestamp()
        this.downloadTimestamp = receivedMessage.getDownloadTimestamp()
        this.localDownloadTimestamp = receivedMessage.getLocalDownloadTimestamp()
        this.bytesFromIdentity =
            if (receivedMessage.getFromIdentity() != null) receivedMessage.getFromIdentity()!!
                .getBytes() else null
        this.bytesFromDeviceUid =
            if (receivedMessage.getFromDeviceUid() != null) receivedMessage.getFromDeviceUid()!!.bytes else null
        this.bytesToIdentity =
            if (receivedMessage.getToIdentity() != null) receivedMessage.getToIdentity()!!
                .getBytes() else null

        this.attachments = arrayOfNulls<ObvAttachment>(receivedAttachments.size)
        for (i in this.attachments.indices) {
            val receivedAttachment = receivedAttachments[i]
            this.attachments[i] = ObvAttachment(
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
