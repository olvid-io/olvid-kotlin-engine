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
package io.olvid.engine.protocol.protocol_engine

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelDialogMessageToSend
import io.olvid.engine.datatypes.containers.ChannelProtocolMessageToSend
import io.olvid.engine.datatypes.containers.ChannelServerQueryMessageToSend
import io.olvid.engine.datatypes.containers.ReceptionChannelInfo
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.GenericProtocolMessageToSend


abstract class ConcreteProtocolMessage protected constructor(internal val coreProtocolMessage: CoreProtocolMessage) {
    abstract val protocolMessageId: Int
    abstract val inputs: Array<Encoded>

    val protocolId: Int
        get() = coreProtocolMessage.protocolId

    val receptionChannelInfo: ReceptionChannelInfo?
        get() = coreProtocolMessage.receptionChannelInfo

    val toIdentity: Identity?
        get() = coreProtocolMessage.toIdentity

    val serverTimestamp: Long
        get() = coreProtocolMessage.serverTimestamp

    val protocolInstanceUid: UID?
        get() = coreProtocolMessage.protocolInstanceUid

    fun generateGenericProtocolMessageToSend(): GenericProtocolMessageToSend? {
        if (coreProtocolMessage.sendChannelInfo == null) {
            return null
        }
        return GenericProtocolMessageToSend(
            coreProtocolMessage.sendChannelInfo,
            coreProtocolMessage.protocolId,
            coreProtocolMessage.protocolInstanceUid!!,
            this.protocolMessageId,
            this.inputs,
            coreProtocolMessage.hasUserContent()
        )
    }

    fun generateChannelProtocolMessageToSend(): ChannelProtocolMessageToSend? {
        return generateGenericProtocolMessageToSend()?.generateChannelProtocolMessageToSend()
    }

    fun generateChannelDialogMessageToSend(): ChannelDialogMessageToSend? {
        return generateGenericProtocolMessageToSend()?.generateChannelDialogMessageToSend()
    }

    fun generateChannelServerQueryMessageToSend(): ChannelServerQueryMessageToSend? {
        return generateGenericProtocolMessageToSend()?.generateChannelServerQueryMessageToSend()
    }
}
