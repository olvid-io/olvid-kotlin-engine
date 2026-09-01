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
package io.olvid.engine.protocol.datatypes

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.datatypes.containers.SendChannelInfo
import io.olvid.engine.protocol.databases.ReceivedMessage


class CoreProtocolMessage {
    @JvmField val sendChannelInfo: SendChannelInfo?
    @JvmField val receptionChannelInfo: ReceptionChannelInfo?
    @JvmField val toIdentity: Identity?
    @JvmField val protocolId: Int
    @JvmField val protocolInstanceUid: UID?
    internal val hasUserContent: Boolean
    @JvmField val serverTimestamp: Long

    constructor(message: ReceivedMessage) {
        this.sendChannelInfo = null
        this.receptionChannelInfo = message.receptionChannelInfo
        this.toIdentity = message.toIdentity
        this.protocolId = message.protocolId
        this.protocolInstanceUid = message.protocolInstanceUid
        this.hasUserContent = false
        this.serverTimestamp = message.serverTimestamp
    }

    constructor(sendChannelInfo: SendChannelInfo?, protocolId: Int, protocolInstanceUid: UID?) {
        this.sendChannelInfo = sendChannelInfo
        this.receptionChannelInfo = null
        this.toIdentity = null
        this.protocolId = protocolId
        this.protocolInstanceUid = protocolInstanceUid
        this.hasUserContent = false
        this.serverTimestamp = System.currentTimeMillis()
    }

    constructor(
        sendChannelInfo: SendChannelInfo?,
        protocolId: Int,
        protocolInstanceUid: UID?,
        hasUserContent: Boolean
    ) {
        this.sendChannelInfo = sendChannelInfo
        this.receptionChannelInfo = null
        this.toIdentity = null
        this.protocolId = protocolId
        this.protocolInstanceUid = protocolInstanceUid
        this.hasUserContent = hasUserContent
        this.serverTimestamp = System.currentTimeMillis()
    }

    fun hasUserContent(): Boolean {
        return hasUserContent
    }
}
