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
import io.olvid.engine.datatypes.containers.MessageToSend
import java.sql.SQLException


interface NetworkSendDelegate {
    fun post(session: Session, messageToSend: MessageToSend?)

    @Throws(SQLException::class)
    fun cancelAttachmentUpload(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    )

    @Throws(SQLException::class)
    fun isOutboxAttachmentSent(
        session: Session,
        ownedIdentity: Identity?,
        messageUid: UID?,
        attachmentNumber: Int
    ): Boolean

    @Throws(SQLException::class)
    fun isOutboxMessageSent(session: Session, ownedIdentity: Identity?, messageUid: UID?): Boolean

    @Throws(SQLException::class)
    fun cancelMessageSending(session: Session, ownedIdentity: Identity?, messageUid: UID?)

    fun retryScheduledNetworkTasks()
}

