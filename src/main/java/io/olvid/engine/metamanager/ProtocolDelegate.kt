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
package io.olvid.engine.metamanager

import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ProtocolReceivedDialogResponse
import io.olvid.engine.datatypes.containers.ProtocolReceivedMessage
import io.olvid.engine.datatypes.containers.ProtocolReceivedServerResponse


interface ProtocolDelegate {
    @Throws(Exception::class)
    fun abortProtocol(session: Session, protocolInstanceUid: UID?, ownedIdentity: Identity?)

    @Throws(Exception::class)
    fun process(session: Session, message: ProtocolReceivedMessage?)

    @Throws(Exception::class)
    fun process(session: Session, message: ProtocolReceivedDialogResponse?)

    @Throws(Exception::class)
    fun process(session: Session, message: ProtocolReceivedServerResponse?)

    @Throws(Exception::class)
    fun isChannelCreationInProgress(
        session: Session,
        ownedIdentity: Identity?,
        contactIdentity: Identity?,
        contactDeviceUid: UID?
    ): Boolean
}
