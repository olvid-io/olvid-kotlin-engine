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
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.sql.SQLException


class ProcessWebsocketReceivedMessageOperation(
    fetchManagerSessionFactory: FetchManagerSessionFactory,
    ownedIdentity: Identity,
    deviceUid: UID?,
    messagePayload: ByteArray,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : PriorityOperation(
    computeUniqueUid(ownedIdentity, messagePayload), onFinishCallback, onCancelCallback
) {
    private val fetchManagerSessionFactory: FetchManagerSessionFactory
    @JvmField val ownedIdentity: Identity
    @JvmField val deviceUid: UID?
    private val messagePayload: ByteArray

    init {
        this.fetchManagerSessionFactory = fetchManagerSessionFactory
        this.ownedIdentity = ownedIdentity
        this.deviceUid = deviceUid
        this.messagePayload = messagePayload
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
                var finished = false
                try {
                    val parts: Array<Encoded> = Encoded(messagePayload).decodeList()
                    if (parts.size != 4) {
                        return
                    }

                    val messageUid = parts[0].decodeUid()
                    val serverTimestamp = parts[1].decodeLong()
                    val wrappedKey = parts[2].decodeEncryptedData()
                    val messageContent = parts[3].decodeEncryptedData()

                    fetchManagerSession.session.startTransaction()

                    val message: InboxMessage? =
                        InboxMessage.get(fetchManagerSession, ownedIdentity, messageUid)
                    if (message == null) {
                        InboxMessage.create(
                            fetchManagerSession,
                            ownedIdentity,
                            messageUid,
                            messageContent,
                            wrappedKey,
                            serverTimestamp,
                            serverTimestamp,  // we assume that downloadTimestamp is equal to serverTimestamp as websocket received messages are received almost immediately
                            System.currentTimeMillis(),
                            false
                        )
                    }
                    finished = true
                } catch (e: Exception) {
                    Logger.x(e)
                    fetchManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        fetchManagerSession.session.commit()
                        setFinished()
                    } else {
                        if (hasNoReasonForCancel()) {
                            cancel(null)
                        }
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

    companion object {
        private fun computeUniqueUid(ownedIdentity: Identity, messagePayload: ByteArray): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            val input = ByteArray(ownedIdentity.getBytes().size + messagePayload.size)
            System.arraycopy(ownedIdentity.getBytes(), 0, input, 0, ownedIdentity.getBytes().size)
            System.arraycopy(
                messagePayload,
                0,
                input,
                ownedIdentity.getBytes().size,
                messagePayload.size
            )
            return UID(sha256.digest(input))
        }
    }
}
