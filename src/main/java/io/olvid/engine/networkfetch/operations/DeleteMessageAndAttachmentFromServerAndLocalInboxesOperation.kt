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
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.InboxMessage
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.DeleteOrMarkAsListed
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.networkfetch.datatypes.MessageBatchProvider
import io.olvid.engine.networkfetch.datatypes.UidAndDeletedOrMarkAsListed
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class DeleteMessageAndAttachmentFromServerAndLocalInboxesOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    private val messageBatchProvider: MessageBatchProvider,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(ownedIdentity.computeUniqueUid(), onFinishCallback, onCancelCallback) {
    var messageUidsAndMarkAsListed: Array<UidAndDeletedOrMarkAsListed> = emptyArray()
        private set


    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    this.messageUidsAndMarkAsListed =
                        messageBatchProvider.getBatchOFMessageUids(ownedIdentity) ?: emptyArray()

                    val messageAndPendingDeletes: MutableList<MessageAndMarkAsListed> = ArrayList()
                    for (messageUidAndMarkAsListed in messageUidsAndMarkAsListed) {
                        // message may be null in case of re-list of an already deleted message
                        val message: InboxMessage? = InboxMessage.get(
                            fetchManagerSession,
                            ownedIdentity,
                            messageUidAndMarkAsListed.uid
                        )

                        when (messageUidAndMarkAsListed.deleteOrMarkAsListed) {
                            DeleteOrMarkAsListed.MARK_AS_LISTED -> if (message == null) continue
                            DeleteOrMarkAsListed.DELETE_EVERYWHERE -> if (message != null && !message.canBeDeleted()) continue
                            DeleteOrMarkAsListed.DELETE_FROM_SERVER_BUT_NOT_LOCALLY -> {} // always send
                        }

                        messageAndPendingDeletes.add(
                            MessageAndMarkAsListed(
                                message,
                                messageUidAndMarkAsListed
                            )
                        )
                    }

                    if (messageAndPendingDeletes.isEmpty()) {
                        // nothing to actually do!
                        finished = true
                        return
                    }

                    if (messageUidsAndMarkAsListed.size != messageAndPendingDeletes.size) {
                        // some messages were skipped, update the messageUidsAndMarkAsListed to avoid unnecessary re-queues in case of failure
                        messageUidsAndMarkAsListed = Array(messageAndPendingDeletes.size) { i ->
                            messageAndPendingDeletes[i].messageUidAndMarkAsListed
                        }
                    }

                    val serverSessionToken: ByteArray? =
                        ServerSession.getToken(fetchManagerSession, ownedIdentity)
                    if (serverSessionToken == null) {
                        cancel(RFC_INVALID_SERVER_SESSION)
                        return
                    }
                    if (cancelWasRequested()) {
                        return
                    }

                    val currentDeviceUid =
                        fetchManagerSession.identityDelegate?.getCurrentDeviceUidOfOwnedIdentity(
                            fetchManagerSession.session,
                            ownedIdentity
                        ) ?: return

                    val serverMethod = DeleteMessageAndAttachmentServerMethod(
                        ownedIdentity,
                        serverSessionToken,
                        currentDeviceUid,
                        messageUidsAndMarkAsListed
                    )
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(
                        fetchManagerSession.identityDelegate.isActiveOwnedIdentity(
                            fetchManagerSession.session,
                            ownedIdentity
                        )
                    )

                    fetchManagerSession.session.startTransaction()
                    when (returnStatus) {
                        ServerMethod.OK -> {
                            for (messageAndMarkAsListed in messageAndPendingDeletes) {
                                if (messageAndMarkAsListed.messageUidAndMarkAsListed.deleteOrMarkAsListed == DeleteOrMarkAsListed.DELETE_EVERYWHERE
                                    && messageAndMarkAsListed.message != null) {
                                    messageAndMarkAsListed.message.delete()
                                }
                            }
                            finished = true
                            return
                        }

                        ServerMethod.INVALID_SESSION -> {
                            ServerSession.deleteCurrentTokenIfEqualTo(
                                fetchManagerSession,
                                serverSessionToken,
                                ownedIdentity
                            )
                            fetchManagerSession.session.commit()
                            cancel(RFC_INVALID_SERVER_SESSION)
                            return
                        }

                        else -> {
                            cancel(RFC_NETWORK_ERROR)
                            return
                        }
                    }
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
        // possible reasons for cancel
        const val RFC_NETWORK_ERROR: Int = 1
        const val RFC_INVALID_SERVER_SESSION: Int = 2
    }
}

internal class DeleteMessageAndAttachmentServerMethod(
    private val identity: Identity,
    private val token: ByteArray,
    private val currentDeviceUid: UID,
    private val messageUidsAndMarkAsListed: Array<UidAndDeletedOrMarkAsListed>
) : ServerMethod() {
    private val server: String = identity.server

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        val encodedMessageUidsAndMarkAsListed =
            arrayOfNulls<Encoded>(2 * messageUidsAndMarkAsListed.size)
        for (i in messageUidsAndMarkAsListed.indices) {
            val item = messageUidsAndMarkAsListed[i]
            encodedMessageUidsAndMarkAsListed[2 * i] = Encoded.of(item.uid)
            encodedMessageUidsAndMarkAsListed[2 * i + 1] = Encoded.of(item.isMarkAsListed())
        }

        @Suppress("UNCHECKED_CAST")
        return Encoded.of(
            arrayOf(
                Encoded.of(identity),
                Encoded.of(token),
                Encoded.of(currentDeviceUid),
                Encoded.of(encodedMessageUidsAndMarkAsListed as Array<Encoded>),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        // Nothing to parse here
    }

    override fun isActiveIdentityRequired(): Boolean {
        return false
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/deleteMessageAndAttachments"
    }
}

internal class MessageAndMarkAsListed(
    @JvmField val message: InboxMessage?,
    @JvmField val messageUidAndMarkAsListed: UidAndDeletedOrMarkAsListed
)