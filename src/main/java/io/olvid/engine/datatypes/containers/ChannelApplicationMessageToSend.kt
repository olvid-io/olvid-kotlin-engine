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

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID


class ChannelApplicationMessageToSend : ChannelMessageToSend {
    override val sendChannelInfo: SendChannelInfo?
    @JvmField val attachments: Array<Attachment?>?
    @JvmField val messagePayload: ByteArray?
    @JvmField val extendedMessagePayload: ByteArray?
    private val hasUserContent: Boolean
    @JvmField val isVoipMessage: Boolean

    override val messageType: Int
        get() = MessageType.APPLICATION_MESSAGE_TYPE

    constructor(
        toIdentities: Array<Identity>?,
        fromIdentity: Identity?,
        messagePayload: ByteArray?,
        extendedMessagePayload: ByteArray?,
        attachments: Array<Attachment?>?,
        hasUserContent: Boolean,
        isVoipMessage: Boolean
    ) {
        val sendChannelInfos: Array<SendChannelInfo?>? =
            SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                toIdentities!!,
                fromIdentity
            )
        if (sendChannelInfos == null || sendChannelInfos.size != 1) {
            Logger.e("Error: trying to create a ChannelApplicationMessageToSend for identities on different servers")
            throw Exception()
        }
        this.sendChannelInfo = sendChannelInfos[0]
        this.messagePayload = messagePayload
        this.extendedMessagePayload = extendedMessagePayload
        this.attachments = attachments
        this.hasUserContent = hasUserContent
        this.isVoipMessage = isVoipMessage
    }

    // some toDeviceUids may be null: send to all devices for this contact in that case
    constructor(
        toIdentities: Array<Identity>?,
        toDeviceUids: Array<UID?>?,
        fromIdentity: Identity?,
        messagePayload: ByteArray?,
        extendedMessagePayload: ByteArray?,
        attachments: Array<Attachment?>?,
        hasUserContent: Boolean,
        isVoipMessage: Boolean
    ) {
        val sendChannelInfos: Array<SendChannelInfo?>? =
            SendChannelInfo.createAllConfirmedObliviousChannelsOrPreKeysInfoForMultipleIdentities(
                toIdentities,
                toDeviceUids!!,
                fromIdentity
            )
        if (sendChannelInfos == null || sendChannelInfos.size != 1) {
            Logger.e("Error: trying to create a ChannelApplicationMessageToSend for identities on different servers")
            throw Exception()
        }
        this.sendChannelInfo = sendChannelInfos[0]
        this.messagePayload = messagePayload
        this.extendedMessagePayload = extendedMessagePayload
        this.attachments = attachments
        this.hasUserContent = hasUserContent
        this.isVoipMessage = isVoipMessage
    }

    fun hasUserContent(): Boolean {
        return hasUserContent
    }

    class Attachment(
        @JvmField val url: String?,
        @JvmField val isDeleteAfterSend: Boolean,
        @JvmField val attachmentLength: Long,
        @JvmField val metadata: ByteArray?
    ) {
    fun getUrl(): String? = url
    fun isDeleteAfterSend(): Boolean = isDeleteAfterSend
    fun getAttachmentLength(): Long = attachmentLength
}
    fun getAttachments(): Array<Attachment?>? = attachments
    fun getMessagePayload(): ByteArray? = messagePayload
    fun getExtendedMessagePayload(): ByteArray? = extendedMessagePayload
    fun isVoipMessage(): Boolean = isVoipMessage
}
