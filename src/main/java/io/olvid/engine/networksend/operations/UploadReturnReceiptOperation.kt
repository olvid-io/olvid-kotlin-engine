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
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.IdentityAndLong
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.metamanager.IdentityDelegate
import io.olvid.engine.networksend.coordinators.SendReturnReceiptCoordinator.ReturnReceiptBatchProvider
import io.olvid.engine.networksend.databases.ReturnReceipt
import io.olvid.engine.networksend.datatypes.SendManagerSessionFactory
import java.nio.charset.StandardCharsets
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class UploadReturnReceiptOperation(
    private val sendManagerSessionFactory: SendManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val server: String,
    private val returnReceiptBatchProvider: ReturnReceiptBatchProvider,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    computeUniqueUid(
        server
    ), onFinishCallback, onCancelCallback
) {
    @JvmField val identityInactiveReturnReceiptIds: MutableList<IdentityAndLong?> = ArrayList()
    var returnReceiptOwnedIdentitiesAndIds: Array<IdentityAndLong?> = emptyArray()
        private set

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        try {
            sendManagerSessionFactory.session.use { sendManagerSession ->
                try {
                    returnReceiptOwnedIdentitiesAndIds =
                        returnReceiptBatchProvider.batchOFReturnReceiptIds ?: emptyArray()
                    val returnReceiptAndEncryptedPayloads: MutableList<ReturnReceiptAndEncryptedPayload> =
                        ArrayList<ReturnReceiptAndEncryptedPayload>()

                    Logger.d("UploadReturnReceiptOperation uploading a batch of " + returnReceiptOwnedIdentitiesAndIds.size)

                    val returnReceiptIdsByIdentity = HashMap<Identity?, MutableList<Long?>?>()
                    for (identityAndUid in returnReceiptOwnedIdentitiesAndIds) {
                        if (identityAndUid == null) continue
                        var list = returnReceiptIdsByIdentity.get(identityAndUid.identity)
                        if (list == null) {
                            list = ArrayList<Long?>()
                            returnReceiptIdsByIdentity.put(identityAndUid.identity, list)
                        }
                        list.add(identityAndUid.lng)
                    }

                    for (entry in returnReceiptIdsByIdentity.entries) {
                        val ownedIdentity: Identity = entry.key!!
                        val returnReceiptIds: MutableList<Long?> = entry.value ?: ArrayList()
                        // we need to block sending return receipts for any inactive ownedIdentity
                        if (!sendManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                                sendManagerSession.session,
                                ownedIdentity
                            )
                        ) {
                            for (returnReceiptId in returnReceiptIds) {
                                identityInactiveReturnReceiptIds.add(
                                    IdentityAndLong(
                                        ownedIdentity,
                                        returnReceiptId ?: continue
                                    )
                                )
                            }
                        } else {
                            val returnReceipts: Array<ReturnReceipt?>? =
                                ReturnReceipt.getMany(
                                    sendManagerSession,
                                    returnReceiptIds.toTypedArray<Long?>()
                                )
                            for (returnReceipt in returnReceipts ?: emptyArray()) {
                                if (returnReceipt == null) continue
                                // compute the encryptedPayload
                                val payload: Encoded
                                val attachmentNumber = returnReceipt.attachmentNumber
                                if (attachmentNumber == null) {
                                    payload = Encoded.of(
                                        arrayOf<Encoded>(
                                            Encoded.of(returnReceipt.getOwnedIdentity()),
                                            Encoded.of(returnReceipt.status.toLong()),
                                        )
                                    )
                                } else {
                                    payload = Encoded.of(
                                        arrayOf<Encoded>(
                                            Encoded.of(returnReceipt.getOwnedIdentity()),
                                            Encoded.of(returnReceipt.status.toLong()),
                                            Encoded.of(attachmentNumber.toLong()),
                                        )
                                    )
                                }

                                val prngSeed =
                                    sendManagerSession.identityDelegate.getDeterministicSeedForOwnedIdentity(
                                        ownedIdentity,
                                        returnReceipt.nonce,
                                        IdentityDelegate.DeterministicSeedContext.ENCRYPT_RETURN_RECEIPT
                                    )
                                val prng = Suite.getPRNG(PRNG.PRNG_HMAC_SHA256, prngSeed!!)

                                val authEnc = Suite.getAuthEnc(returnReceipt.key)!!
                                val encryptedPayload =
                                    authEnc.encrypt(returnReceipt.key, payload.bytes, prng)

                                returnReceiptAndEncryptedPayloads.add(
                                    ReturnReceiptAndEncryptedPayload(
                                        returnReceipt,
                                        encryptedPayload
                                    )
                                )
                            }
                        }
                    }

                    if (cancelWasRequested()) {
                        return
                    }


                    val serverMethod =
                        UploadReturnReceiptServerMethod(server, returnReceiptAndEncryptedPayloads)
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(true)

                    sendManagerSession.session.startTransaction()
                    when (returnStatus) {
                        ServerMethod.OK -> {
                            for (returnReceiptAndEncryptedPayload in returnReceiptAndEncryptedPayloads) {
                                returnReceiptAndEncryptedPayload.returnReceipt.delete()
                            }

                            finished = true
                            return
                        }

                        else -> {
                            // the upload failed: delete any return receipt older than the expiration delay so we stop retrying them forever
                            val expirationTimestamp =
                                System.currentTimeMillis() - Constants.RETURN_RECEIPT_EXPIRATION_DELAY
                            var deletedSome = false
                            for (returnReceiptAndEncryptedPayload in returnReceiptAndEncryptedPayloads) {
                                if (returnReceiptAndEncryptedPayload.returnReceipt.creationTimestamp < expirationTimestamp) {
                                    returnReceiptAndEncryptedPayload.returnReceipt.delete()
                                    deletedSome = true
                                }
                            }
                            if (deletedSome) {
                                sendManagerSession.session.commit()
                            }
                            cancel(null)
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                    sendManagerSession.session.rollback()
                } finally {
                    if (finished) {
                        sendManagerSession.session.commit()
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
        private fun computeUniqueUid(server: String): UID {
            val sha256 = Suite.getHash(Hash.SHA256)
            return UID(sha256.digest(server.toByteArray(StandardCharsets.UTF_8)))
        }
    }
}


internal class UploadReturnReceiptServerMethod(
    private val server: String?,
    private val returnReceiptAndEncryptedPayloads: MutableList<ReturnReceiptAndEncryptedPayload>
) : ServerMethod() {
    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        val encodeds: MutableList<Encoded?> = ArrayList<Encoded?>()
        for (returnReceiptAndEncryptedPayload in returnReceiptAndEncryptedPayloads) {
            encodeds.add(
                Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(returnReceiptAndEncryptedPayload.returnReceipt.getContactIdentity()),
                        Encoded.of(returnReceiptAndEncryptedPayload.returnReceipt.contactDeviceUids!!),
                        Encoded.of(returnReceiptAndEncryptedPayload.returnReceipt.nonce!!),
                        Encoded.of(returnReceiptAndEncryptedPayload.encryptedPayload)
                    )
                )
            )
        }
        @Suppress("UNCHECKED_CAST")
        return Encoded.of(encodeds.toTypedArray<Encoded?>() as Array<Encoded>).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        // nothing to parse here
    }

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/uploadReturnReceipt"
    }
}

internal class ReturnReceiptAndEncryptedPayload(
    @JvmField val returnReceipt: ReturnReceipt,
    @JvmField val encryptedPayload: EncryptedBytes
)