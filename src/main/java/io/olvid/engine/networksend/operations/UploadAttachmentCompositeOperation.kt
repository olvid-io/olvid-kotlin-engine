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
import io.olvid.engine.datatypes.PriorityOperation
import io.olvid.engine.datatypes.UID
import io.olvid.engine.networksend.coordinators.SendAttachmentCoordinator
import io.olvid.engine.networksend.databases.OutboxAttachment
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import javax.net.ssl.SSLSocketFactory


class UploadAttachmentCompositeOperation(
    sendManagerSessionFactory: SendManagerSessionFactory?,
    sslSocketFactory: SSLSocketFactory?,
    userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    @JvmField val messageUid: UID,
    @JvmField val attachmentNumber: Int,
    initialPriority: Long,
    coordinator: SendAttachmentCoordinator?,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : PriorityOperation(
    OutboxAttachment.computeUniqueUid(
        ownedIdentity,
        messageUid,
        attachmentNumber
    ), onFinishCallback, onCancelCallback
) {
    private val suboperations: Array<Operation?>

    private val uploadAttachmentOperation: UploadAttachmentOperation

    init {
        this.suboperations = arrayOfNulls<Operation>(2)

        uploadAttachmentOperation = UploadAttachmentOperation(
            sendManagerSessionFactory!!, sslSocketFactory, userAgentOverride,
            ownedIdentity,
            messageUid,
            attachmentNumber, initialPriority, coordinator
        )
        suboperations[0] = uploadAttachmentOperation
        suboperations[1] = TryToDeleteMessageAndAttachmentsOperation(
            sendManagerSessionFactory,
            ownedIdentity,
            messageUid
        )

        for (i in 0..<suboperations.size - 1) {
            suboperations[i + 1]!!.addDependency(suboperations[i]!!)
        }
    }


    override fun getPriority(): Long {
        return uploadAttachmentOperation.getPriority()
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
            queue.execute(1, "Engine-UploadAttachmentCompositeOperation")
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
        const val RFC_NETWORK_ERROR: Int = 3
        const val RFC_MESSAGE_HAS_NO_UID_FROM_SERVER: Int = 4
        const val RFC_ATTACHMENT_FILE_NOT_READABLE: Int = 6
        const val RFC_DOES_NOT_HAVE_THE_HIGHEST_PRIORITY: Int = 7
        const val RFC_INVALID_SIGNED_URL: Int = 8
        const val RFC_IDENTITY_IS_INACTIVE: Int = 9
    }
}
