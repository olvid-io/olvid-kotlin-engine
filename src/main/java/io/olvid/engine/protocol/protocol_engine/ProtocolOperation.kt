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
package io.olvid.engine.protocol.protocol_engine

import com.fasterxml.jackson.databind.ObjectMapper
import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.OperationQueue
import io.olvid.engine.datatypes.PriorityOperation
import io.olvid.engine.datatypes.UID
import io.olvid.engine.protocol.databases.LinkBetweenProtocolInstances
import io.olvid.engine.protocol.databases.ProtocolInstance
import io.olvid.engine.protocol.databases.ReceivedMessage
import io.olvid.engine.protocol.datatypes.GenericProtocolMessageToSend
import io.olvid.engine.protocol.datatypes.ProtocolManagerSessionFactory
import java.sql.SQLException


class ProtocolOperation(
    internal val protocolManagerSessionFactory: ProtocolManagerSessionFactory,
    @JvmField val receivedMessageUid: UID?,
    @JvmField val protocolId: Int,
    internal val failedAttempts: Int,
    internal val prng: PRNGService,
    internal val jsonObjectMapper: ObjectMapper,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : PriorityOperation(
    receivedMessageUid, onFinishCallback, onCancelCallback
) {
    internal val creationTime: Long

    // The following 2 variables are set during operation execution to be used in the onFinishCallback of the coordinator
    var protocolInstanceUid: UID? = null
        private set
    var protocolOwnedIdentity: Identity? = null
        private set

    init {
        this.creationTime = System.currentTimeMillis()
    }

    override fun getPriority(): Long {
        // failed ProtocolOperation go to the back of the queue,
        // we add the creationTimestamp to preserve some kind of FIFO for same priority protocols
        return (failedAttempts.toLong()) shl (60 +  // max failedAttempts is 5, so it fits on 3 bits
                ConcreteProtocol.getProtocolPriority(protocolId)).toInt() shl (50 +  // priority fits on 10 bits
                creationTime).toInt() // currentTimeMillis() should fit on 50 bits for quite some time
    }

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        try {
            protocolManagerSessionFactory.session.use { protocolManagerSession ->
                var finished = false
                try {
                    val message: ReceivedMessage? =
                        ReceivedMessage.get(protocolManagerSession, receivedMessageUid)
                    if (message == null) {
                        cancel(RFC_MESSAGE_NOT_FOUND)
                        return
                    }

                    // Set this for use in the onFinishCallback
                    this.protocolInstanceUid = message.protocolInstanceUid
                    this.protocolOwnedIdentity = message.toIdentity

                    protocolManagerSession.session.startTransaction()

                    var protocolInstance: ProtocolInstance? = null
                    var protocolInstanceNeedsToBeInserted = false
                    var protocol: ConcreteProtocol? = null
                    try {
                        protocolInstance = ProtocolInstance.get(
                            protocolManagerSession,
                            protocolInstanceUid,
                            protocolOwnedIdentity
                        )
                        if (protocolInstance == null) {
                            protocolInstance = ProtocolInstance.createNotInDb(
                                protocolManagerSession,
                                protocolInstanceUid,
                                protocolOwnedIdentity,
                                protocolId,
                                InitialProtocolState()
                            )
                            protocolInstanceNeedsToBeInserted = true
                            if (protocolInstance != null) {
                                protocol =
                                    ConcreteProtocol.getConcreteProtocolInInitialState(
                                        protocolManagerSession,
                                        protocolId,
                                        protocolInstanceUid,
                                        protocolOwnedIdentity!!,
                                        prng,
                                        jsonObjectMapper
                                    )
                            }
                        } else {
                            protocol = ConcreteProtocol.getConcreteProtocol(
                                protocolInstance,
                                prng,
                                jsonObjectMapper
                            )
                            if (protocol == null) {
                                // we have a protocolInstance in db but cannot reconstruct it --> delete it!
                                protocolInstance.delete()
                                protocolManagerSession.session.commit()
                            }
                        }
                    } catch (e: Exception) {
                        Logger.x(e)
                    }
                    if (protocol == null) {
                        cancel(RFC_UNABLE_TO_RECONSTRUCT_PROTOCOL)
                        return
                    }


                    val concreteProtocolMessage = protocol.getConcreteProtocolMessage(message)
                    if (concreteProtocolMessage == null) {
                        cancel(RFC_UNABLE_TO_RECONSTRUCT_MESSAGE)
                        return
                    }

                    val stepToExecute = protocol.getStepToExecute(concreteProtocolMessage)
                    if (stepToExecute == null) {
                        // special case if the received message is a protocol dialog response: we delete the dialog
                        if (message.userDialogUuid != null) {
                            cancel(RFC_DIALOG_RESPONSE_CANNOT_BE_PROCESSED)
                        } else {
                            cancel(RFC_UNABLE_TO_FIND_STEP_TO_EXECUTE)
                        }
                        return
                    }

                    if (protocol.requiresProtocolInstanceToBeInsertedBeforeInitialStep && protocolInstanceNeedsToBeInserted) {
                        try {
                            protocolInstance!!.insert()
                            protocolInstanceNeedsToBeInserted = false
                        } catch (e: SQLException) {
                            Logger.x(e)
                            cancel(RFC_UNABLE_TO_RECONSTRUCT_PROTOCOL)
                            return
                        }
                    }


                    // run the step
                    Logger.d("Executing step " + stepToExecute.javaClass.getName() + "\n  - state: " + protocol.currentState.javaClass.getName() + "\n  - message: " + concreteProtocolMessage.javaClass.getName())
                    val queue = OperationQueue()
                    queue.queue(stepToExecute)
                    queue.execute(1, "Engine-ProtocolOperation")
                    queue.join()


                    if (stepToExecute.isCancelled || (stepToExecute.endState == null)) {
                        Logger.i("Step " + stepToExecute.javaClass + " failed")
                        cancel(RFC_THE_STEP_TO_EXECUTE_FAILED)
                        return
                    }
                    Logger.d("Finished step " + stepToExecute.javaClass.getName() + ". It reached state " + stepToExecute.endState!!.javaClass.getName())

                    val endState = stepToExecute.endState!!
                    protocol.updateCurrentState(endState)

                    // Notify linked parent protocol
                    if (protocol.mayBeRunAsLinkedChildProtocol) {
                        val parentNotificationMessage: GenericProtocolMessageToSend? =
                            LinkBetweenProtocolInstances.getGenericProtocolMessageToSendWhenChildProtocolInstanceReachesAState(
                                protocolManagerSession,
                                protocol.protocolInstanceUid,
                                protocol.ownedIdentity,
                                protocol.currentState
                            )
                        if (parentNotificationMessage != null) {
                            if (protocolManagerSession.channelDelegate == null) {
                                Logger.w("Unable to run notify parent protocol as the ChannelDelegate is not set yet.")
                                throw Exception()
                            }
                            protocolManagerSession.channelDelegate.post(
                                protocolManagerSession.session,
                                parentNotificationMessage.generateChannelProtocolMessageToSend(),
                                prng
                            )
                        }
                    }

                    if (protocol.hasReachedFinalState()) {
                        // Delete the associated ProtocolInstance (unless it was not yet inserted)
                        if (!protocolInstanceNeedsToBeInserted) {
                            protocolInstance!!.delete()
                        }

                        // Delete all remaining ReceivedMessage for this protocol
                        if (protocol.eraseReceivedMessagesAfterReachingAFinalState) {
                            for (receivedMessage in ReceivedMessage.getAll(
                                protocolManagerSession,
                                protocol.protocolInstanceUid!!,
                                protocol.ownedIdentity!!
                            )) {
                                receivedMessage?.delete()
                            }
                        }
                    } else {
                        protocolInstance!!.updateCurrentState(
                            endState,
                            protocolInstanceNeedsToBeInserted
                        )
                    }

                    message.delete()

                    finished = true
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    if (finished) {
                        protocolManagerSession.session.commit()
                        setFinished()
                    } else {
                        protocolManagerSession.session.rollback()
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
        const val RFC_DELEGATE_NOT_SET: Int = 1
        const val RFC_MESSAGE_NOT_FOUND: Int = 2
        const val RFC_UNABLE_TO_RECONSTRUCT_PROTOCOL: Int = 3
        const val RFC_UNABLE_TO_RECONSTRUCT_MESSAGE: Int = 4
        const val RFC_UNABLE_TO_FIND_STEP_TO_EXECUTE: Int = 5
        const val RFC_THE_STEP_TO_EXECUTE_FAILED: Int = 6
        const val RFC_DIALOG_RESPONSE_CANNOT_BE_PROCESSED: Int = 7
    }
}
