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
package io.olvid.engine.networksend.operations

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.networksend.databases.OutboxMessage
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.sql.SQLException

class TryToDeleteMessageAndAttachmentsOperation(
    sendManagerSessionFactory: SendManagerSessionFactory,
    ownedIdentity: Identity,
    messageUid: UID
) : Operation(
    IdentityAndUid.computeUniqueUid(ownedIdentity, messageUid), null, null
) {
    private val ownedIdentity: Identity
    private val messageUid: UID
    private val sendManagerSessionFactory: SendManagerSessionFactory

    init {
        this.ownedIdentity = ownedIdentity
        this.sendManagerSessionFactory = sendManagerSessionFactory
        this.messageUid = messageUid
    }

    // possible reasons for cancel
    // None!
    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        val outboxMessage: OutboxMessage?
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                try {
                    try {
                        outboxMessage = OutboxMessage.get(
                            sendManagerSession,
                            ownedIdentity,
                            messageUid
                        )
                    } catch (_: SQLException) {
                        return
                    }

                    if (outboxMessage == null) {
                        finished = true
                        return
                    }
                    if (outboxMessage.uidFromServer == null) {
                        finished = true
                        return
                    }

                    val outboxAttachments = outboxMessage.attachments
                    for (outboxAttachment in outboxAttachments ?: emptyArray()) {
                        if (outboxAttachment != null && !outboxAttachment.isAcknowledged) {
                            finished = true
                            return
                        }
                    }

                    // everything has been acknowledged OR cancelled, we can proceed to delete everything
                    for (outboxAttachment in outboxAttachments ?: emptyArray()) {
                        if (outboxAttachment?.shouldBeDeletedAfterSend() == true) {
                            val attachmentFile = sendManagerSession.fileIo.file(
                                sendManagerSession.engineBaseDirectory,
                                outboxAttachment.url!!
                            )
                            if (attachmentFile.isFile()) {
                                if (!attachmentFile.delete()) {
                                    // We were unable to delete the file
                                    //    -> abort to avoid loose files
                                    cancel(null)
                                    return
                                }
                            }
                        }
                    }

                    sendManagerSession.session.startTransaction()
                    outboxMessage.delete()
                    finished = true
                } catch (e: Exception) {
                    Logger.x(e)
                    sendManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        sendManagerSession.session.commit()
                        setFinished()
                    } else {
                        cancel(null)
                        processCancel()
                    }
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            cancel(null)
            processCancel()
        }
    }
}
