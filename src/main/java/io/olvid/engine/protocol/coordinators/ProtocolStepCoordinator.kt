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
package io.olvid.engine.protocol.coordinators

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.NoDuplicatePriorityOperationQueue
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.Operation.OnCancelCallback
import io.olvid.engine.datatypes.Operation.OnFinishCallback
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ChannelMessageToSend
import io.olvid.engine.datatypes.containers.DialogType.Companion.createDeleteDialog
import io.olvid.engine.datatypes.containers.SendChannelInfo.Companion.createUserInterfaceChannelInfo
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.CoreProtocolMessage
import io.olvid.engine.protocol.datatypes.ProtocolManagerSessionFactory
import io.olvid.engine.protocol.datatypes.ProtocolReceivedMessageProcessorDelegate
import io.olvid.engine.protocol.protocol_engine.OneWayDialogProtocolMessage
import io.olvid.engine.protocol.protocol_engine.ProtocolOperation
import java.sql.SQLException


class ProtocolStepCoordinator(
    private val protocolManagerSessionFactory: ProtocolManagerSessionFactory,
    private val prng: PRNGService,
    private val jsonObjectMapper: ObjectMapper
) : ProtocolReceivedMessageProcessorDelegate, OnFinishCallback, OnCancelCallback {
    private val protocolOperationQueue: NoDuplicatePriorityOperationQueue = NoDuplicatePriorityOperationQueue()
    private val stepFailedAttemptCount: HashMap<UID?, Int?> = HashMap()

    fun startProcessing() {
        protocolOperationQueue.execute(1, "Engine-ProtocolStepCoordinator")
    }

    private fun queueNewProtocolOperation(
        receivedMessageUid: UID?,
        protocolId: Int,
        failedAttemptsCount: Int
    ) {
        val op = ProtocolOperation(
            protocolManagerSessionFactory,
            receivedMessageUid,
            protocolId,
            failedAttemptsCount,
            prng,
            jsonObjectMapper,
            this,
            this
        )
        protocolOperationQueue.queue(op)
    }

    fun initialQueueing() {
        try {
            protocolManagerSessionFactory.session.use { protocolManagerSession ->
                // To improve: also cleanup protocol instances: implement a clean abort in each protocol, and call it when the protocol is stalled
                ReceivedMessage.deleteExpiredMessagesWithNoProtocol(protocolManagerSession)
                ReceivedMessage.deleteAllTransfer(protocolManagerSession)

                val receivedMessages: Array<ReceivedMessage?> =
                    ReceivedMessage.getAll(protocolManagerSession)
                if (receivedMessages.size > 0) {
                    Logger.i("Found " + receivedMessages.size + " ReceivedMessage to (attempt to) process.")
                    for (receivedMessage in receivedMessages) {
                        if (receivedMessage == null) continue
                        queueNewProtocolOperation(
                            receivedMessage.uid,
                            receivedMessage.protocolId,
                            0
                        )
                    }
                }
                protocolManagerSession.session.commit()
            }
        } catch (e: Exception) {
            Logger.x(e)
        }
    }

    override fun processReceivedMessage(messageUid: UID?, protocolId: Int) {
        queueNewProtocolOperation(messageUid, protocolId, 0)
    }

    override fun onFinishCallback(operation: Operation) {
        Logger.d("Running onFinishCallback for " + operation.javaClass)
        val protocolOperation = operation as ProtocolOperation
        val protocolInstanceUid = protocolOperation.protocolInstanceUid
        val protocolOwnedIdentity = protocolOperation.protocolOwnedIdentity
        if ((protocolInstanceUid == null) || (protocolOwnedIdentity == null)) {
            Logger.w("The ProtocolOperation finished, but either the protocolInstanceUid or the protocolOwnedIdentity is not properly set.")
            return
        }
        try {
            protocolManagerSessionFactory.session.use { protocolManagerSession ->
                for (receivedMessage in ReceivedMessage.getAll(
                    protocolManagerSession,
                    protocolInstanceUid,
                    protocolOwnedIdentity
                )) {
                    if (receivedMessage == null) continue
                    protocolManagerSession.protocolReceivedMessageProcessorDelegate!!.processReceivedMessage(
                        receivedMessage.uid,
                        receivedMessage.protocolId
                    )
                }
            }
        } catch (e: SQLException) {
            Logger.x(e)
        }
    }

    override fun onCancelCallback(operation: Operation) {
        Logger.d("Running onCancelCallback for " + operation.javaClass)
        if (operation.hasNoReasonForCancel()) {
            return
        }
        Logger.d("ProtocolOperation cancelled for RFC " + operation.reasonForCancel)
        when (operation.reasonForCancel) {
            ProtocolOperation.RFC_DELEGATE_NOT_SET, ProtocolOperation.RFC_MESSAGE_NOT_FOUND, ProtocolOperation.RFC_UNABLE_TO_FIND_STEP_TO_EXECUTE -> {}
            ProtocolOperation.RFC_THE_STEP_TO_EXECUTE_FAILED -> {
                // check how many times this step has failed before
                val messageUid = (operation as ProtocolOperation).receivedMessageUid
                val protocolId = operation.protocolId
                var failedAttempts = stepFailedAttemptCount.get(messageUid)
                if (failedAttempts == null) {
                    failedAttempts = 0
                }
                failedAttempts++
                if (failedAttempts >= 5) {
                    // the step failed 5 times --> we can delete it
                    try {
                        protocolManagerSessionFactory.session.use { protocolManagerSession ->
                            val message: ReceivedMessage? = ReceivedMessage.get(
                                protocolManagerSession,
                                operation.receivedMessageUid
                            )
                            if (message != null) {
                                message.delete()
                                protocolManagerSession.session.commit()
                            }
                        }
                    } catch (e: SQLException) {
                        Logger.x(e)
                    }
                } else {
                    // retry to execute the step
                    stepFailedAttemptCount.put(messageUid, failedAttempts)
                    queueNewProtocolOperation(messageUid, protocolId, failedAttempts)
                }
            }

            ProtocolOperation.RFC_UNABLE_TO_RECONSTRUCT_MESSAGE, ProtocolOperation.RFC_UNABLE_TO_RECONSTRUCT_PROTOCOL -> {
                // Delete the protocol message
                try {
                    protocolManagerSessionFactory.session.use { protocolManagerSession ->
                        val message: ReceivedMessage? = ReceivedMessage.get(
                            protocolManagerSession,
                            (operation as ProtocolOperation).receivedMessageUid
                        )
                        if (message != null) {
                            message.delete()
                            protocolManagerSession.session.commit()
                        }
                    }
                } catch (e: SQLException) {
                    Logger.x(e)
                }
            }

            ProtocolOperation.RFC_DIALOG_RESPONSE_CANNOT_BE_PROCESSED -> {
                // Delete the protocol message and the UI dialog
                try {
                    protocolManagerSessionFactory.session.use { protocolManagerSession ->
                        val message: ReceivedMessage? = ReceivedMessage.get(
                            protocolManagerSession,
                            (operation as ProtocolOperation).receivedMessageUid
                        )
                        if (message == null) return@use
                        message.delete()

                        val coreProtocolMessage = CoreProtocolMessage(
                            createUserInterfaceChannelInfo(
                                message.toIdentity,
                                // carry the answered dialog's version so the listener only deletes
                                // the dialog if it has not been replaced in the meantime
                                createDeleteDialog(message.userDialogVersion),
                                message.userDialogUuid
                            ), message.protocolId, message.protocolInstanceUid
                        )
                        val messageToSend: ChannelMessageToSend? =
                            OneWayDialogProtocolMessage(coreProtocolMessage).generateChannelDialogMessageToSend()
                        protocolManagerSession.channelDelegate!!.post(
                            protocolManagerSession.session,
                            messageToSend,
                            prng
                        )
                        protocolManagerSession.session.commit()
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                }
            }

            else -> Logger.w("Unknown RFC for ProtocolOperation: " + operation.reasonForCancel)
        }
    }
}
