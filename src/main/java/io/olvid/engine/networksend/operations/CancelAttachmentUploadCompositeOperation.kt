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
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.UID
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import javax.net.ssl.SSLSocketFactory


class CancelAttachmentUploadCompositeOperation(
    sendManagerSessionFactory: SendManagerSessionFactory?,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?, //    public static final int RFC_MESSAGE_NOT_UPLOADED_YET = 4;
    @JvmField val ownedIdentity: Identity,
    messageUid: UID,
    attachmentNumber: Int,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    OutboxAttachment.computeUniqueUid(
        ownedIdentity, messageUid, attachmentNumber
    ), onFinishCallback, onCancelCallback
) {
    @JvmField val messageUid: UID = messageUid
    @JvmField val attachmentNumber: Int = attachmentNumber
    private val suboperations: Array<Operation?> = arrayOfNulls(2)

    init {
        suboperations[0] = CancelAttachmentUploadOperation(
            sendManagerSessionFactory!!, sslSocketFactory, userAgentOverride,
            ownedIdentity, messageUid, attachmentNumber
        )
        suboperations[1] = TryToDeleteMessageAndAttachmentsOperation(
            sendManagerSessionFactory,
            ownedIdentity, messageUid
        )

        for (i in 0..<suboperations.size - 1) {
            suboperations[i + 1]!!.addDependency(suboperations[i]!!)
        }
    }


    override fun doCancel() {
        for (op in suboperations) {
            op?.cancel(null)
        }
    }

    override fun doExecute() {
        var finished = false
        try {
            val queue = OperationQueue()
            for (op in suboperations) {
                if (op != null) queue.queue(op)
            }
            queue.execute(1, "Engine-CancelAttachmentUploadCompositeOperation")
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
        const val RFC_ATTACHMENT_NOT_FOUND_IN_DATABASE: Int = 1
        const val RFC_NETWORK_ERROR: Int = 2
        const val RFC_IDENTITY_IS_INACTIVE: Int = 3
    }
}
