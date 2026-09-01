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
package io.olvid.engine.networkfetch.operations

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.PriorityOperation
import io.olvid.engine.datatypes.UID
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException


class ProcessPreKeyMessagesForNewContactOperation(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    ownedIdentity: Identity,
    contactIdentity: Identity,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : PriorityOperation(
    computeUniqueUid(ownedIdentity, contactIdentity), onFinishCallback, onCancelCallback
) {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    @JvmField val ownedIdentity: Identity
    @JvmField val contactIdentity: Identity

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.ownedIdentity = ownedIdentity
        this.contactIdentity = contactIdentity
    }

    override fun getPriority(): Long {
        return 1
    }

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    val inboxMessages: MutableList<InboxMessage> =
                        InboxMessage.getPendingPreKeyMessages(
                            fetchManagerSession,
                            ownedIdentity,
                            contactIdentity
                        )
                    Logger.i("Found " + inboxMessages.size + " pending PreKey inbox messages to process following a contact addition.")
                    for (inboxMessage in inboxMessages) {
                        fetchManagerSession.inboxMessageListener?.messageWasDownloaded(inboxMessage.networkReceivedMessage)
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    setFinished()
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
            cancel(null)
            processCancel()
        }
    }

    companion object {
        private fun computeUniqueUid(ownedIdentity: Identity, contactIdentity: Identity): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            val input = ByteArray(ownedIdentity.getBytes().size + contactIdentity.getBytes().size)
            System.arraycopy(ownedIdentity.getBytes(), 0, input, 0, ownedIdentity.getBytes().size)
            System.arraycopy(
                contactIdentity.getBytes(),
                0,
                input,
                ownedIdentity.getBytes().size,
                contactIdentity.getBytes().size
            )
            return UID(sha256.digest(input))
        }
    }
}
