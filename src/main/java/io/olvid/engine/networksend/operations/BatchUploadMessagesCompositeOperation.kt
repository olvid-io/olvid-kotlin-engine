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
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndUid
import io.olvid.engine.datatypes.containers.StringAndBoolean
import io.olvid.engine.networksend.coordinators.SendMessageCoordinator
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.nio.charset.StandardCharsets
import javax.net.ssl.SSLSocketFactory

class BatchUploadMessagesCompositeOperation(
    private val sendManagerSessionFactory: SendManagerSessionFactory?,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val server: String,
    userContentMessages: Boolean,
    private val messageBatchProvider: SendMessageCoordinator.MessageBatchProvider,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    StringAndBoolean.computeUniqueUid(
        server, userContentMessages
    ), onFinishCallback, onCancelCallback
) {
    var messageIdentitiesAndUids: Array<IdentityAndUid?>? =
        null
        private set
    private var suboperations: Array<Operation?> = emptyArray()

    val identityInactiveMessageUids: MutableList<IdentityAndUid?>?
        get() {
            if (suboperations.isNotEmpty()) {
                return (suboperations[0] as? BatchUploadMessagesOperation)?.identityInactiveMessageUids
            }
            return mutableListOf<IdentityAndUid?>()
        }

    val tooManyHeadersUnsentMessageUids: MutableList<IdentityAndUid?>?
        get() {
            if (suboperations.isNotEmpty()) {
                return (suboperations[0] as? BatchUploadMessagesOperation)?.tooManyHeadersUnsentMessageUids
            }
            return mutableListOf<IdentityAndUid?>()
        }

    override fun doCancel() {
        for (op in suboperations) {
            op?.cancel(null)
        }
    }

    override fun doExecute() {
        var finished = false
        try {
            // first get some messageUids from the provider
            this.messageIdentitiesAndUids = messageBatchProvider.batchOFMessageUids
            if (messageIdentitiesAndUids!!.isEmpty()) {
                suboperations = arrayOfNulls<Operation>(0)
            } else {
                suboperations = arrayOfNulls<Operation>(messageIdentitiesAndUids!!.size + 1)

                suboperations[0] = BatchUploadMessagesOperation(
                    sendManagerSessionFactory!!,
                    sslSocketFactory,
                    userAgentOverride,
                    server,
                    messageIdentitiesAndUids!!.filterNotNull().toTypedArray()
                )
                for (i in messageIdentitiesAndUids!!.indices) {
                    suboperations[i + 1] = TryToDeleteMessageAndAttachmentsOperation(
                        sendManagerSessionFactory,
                        messageIdentitiesAndUids!![i]!!.identity,
                        messageIdentitiesAndUids!![i]!!.uid
                    )
                    suboperations[i + 1]!!.addDependency(suboperations[0]!!)
                }
            }

            // now run the suboperations
            if (suboperations.isNotEmpty()) {
                val queue = OperationQueue()
                for (op in suboperations) {
                    if (op != null) queue.queue(op)
                }
                queue.execute(1, "BatchUploadMessagesCompositeOperation")
                queue.join()

                if (cancelWasRequested()) {
                    return
                }

                for (op in suboperations) {
                    if (op != null && op.isCancelled) {
                        cancel(op.reasonForCancel)
                        return
                    }
                }
            }
            finished = true
        } catch (e: Exception) {
            Logger.x(e)
        } finally {
            if (finished) {
                setFinished()
            } else {
                cancel(null)
                processCancel()
            }
        }
    }

    companion object {
        // possible reasons for cancel
        const val RFC_BATCH_TOO_LARGE: Int = 2
        const val RFC_NETWORK_ERROR: Int = 3

        fun computeUniqueUid(server: String): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            return UID(sha256.digest(server.toByteArray(StandardCharsets.UTF_8)))
        }
    }
}
