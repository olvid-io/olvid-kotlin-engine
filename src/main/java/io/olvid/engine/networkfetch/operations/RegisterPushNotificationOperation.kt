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
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.PushNotificationTypeAndParameters
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.PushNotificationConfiguration
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import java.nio.charset.StandardCharsets
import java.sql.SQLException
import javax.net.ssl.SSLSocketFactory

class RegisterPushNotificationOperation // will be set during execution
    (
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val ownedIdentity: Identity,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    ownedIdentity.computeUniqueUid(), onFinishCallback, onCancelCallback
) {
    var deviceUid: UID? = null // will be set during execution
        private set


    override fun doCancel() {
        // Nothing special to do on cancel
    }

    override fun doExecute() {
        var finished = false
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    val serverSessionToken: ByteArray? =
                        ServerSession.getToken(fetchManagerSession, ownedIdentity)
                    if (serverSessionToken == null) {
                        cancel(RFC_INVALID_SERVER_SESSION)
                        return
                    }
                    if (cancelWasRequested()) {
                        return
                    }
                    val pushNotificationConfiguration: PushNotificationConfiguration? =
                        PushNotificationConfiguration.get(
                            fetchManagerSession,
                            ownedIdentity
                        )
                    if (pushNotificationConfiguration == null) {
                        cancel(RFC_PUSH_NOTIFICATION_CONFIGURATION_NOT_FOUND)
                        return
                    }
                    this.deviceUid = pushNotificationConfiguration.deviceUid

                    val deviceName =
                        fetchManagerSession.identityDelegate!!.getCurrentDeviceDisplayName(
                            fetchManagerSession.session,
                            ownedIdentity
                        )
                    val encodedDeviceName = Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(
                                if (deviceName == null) ByteArray(0) else deviceName.toByteArray(
                                    StandardCharsets.UTF_8
                                )
                            )
                        )
                    ).bytes

                    val plaintext = ByteArray(((encodedDeviceName.size - 1) or 127) + 1)
                    System.arraycopy(encodedDeviceName, 0, plaintext, 0, encodedDeviceName.size)

                    val encryptedDeviceNameForFirstRegistration =
                        Suite.getPublicKeyEncryption(ownedIdentity.encryptionPublicKey)!!.encrypt(
                            ownedIdentity.encryptionPublicKey,
                            plaintext,
                            Suite.getDefaultPRNGService(0)
                        )!!

                    val keycloakPushTopics =
                        fetchManagerSession.identityDelegate.getKeycloakPushTopics(
                            fetchManagerSession.session,
                            ownedIdentity
                        )
                    val serverMethod = RegisterPushNotificationServerMethod(
                        ownedIdentity,
                        serverSessionToken,
                        pushNotificationConfiguration.deviceUid,
                        pushNotificationConfiguration.pushNotificationTypeAndParameters,
                        keycloakPushTopics,
                        encryptedDeviceNameForFirstRegistration
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
                            fetchManagerSession.identityDelegate.reactivateOwnedIdentityIfNeeded(
                                fetchManagerSession.session,
                                ownedIdentity
                            )
                            if (pushNotificationConfiguration.shouldReactivateCurrentDevice()) {
                                pushNotificationConfiguration.clearKickOtherDevices()
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

                        ServerMethod.ANOTHER_DEVICE_IS_ALREADY_REGISTERED -> {
                            fetchManagerSession.identityDelegate.deactivateOwnedIdentity(
                                fetchManagerSession.session,
                                ownedIdentity
                            )
                            fetchManagerSession.session.commit()
                            cancel(RFC_ANOTHER_DEVICE_IS_ALREADY_REGISTERED)
                            return
                        }

                        ServerMethod.DEVICE_IS_NOT_REGISTERED -> {
                            // this only happens when configuration was set to reactivate curent device, but the provided deviceUidToReplace is invalid/inactive
                            if (pushNotificationConfiguration.shouldReactivateCurrentDevice()) {
                                pushNotificationConfiguration.clearKickOtherDevices()
                                fetchManagerSession.session.commit()
                            }
                            cancel(RFC_DEVICE_UID_TO_REPLACE_NOT_FOUND)
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
        const val RFC_ANOTHER_DEVICE_IS_ALREADY_REGISTERED: Int = 3
        const val RFC_PUSH_NOTIFICATION_CONFIGURATION_NOT_FOUND: Int = 4
        const val RFC_DEVICE_UID_TO_REPLACE_NOT_FOUND: Int = 5
    }
}


internal class RegisterPushNotificationServerMethod(
    private val ownedIdentity: Identity,
    private val token: ByteArray,
    private val deviceUid: UID,
    private val pushNotificationTypeAndParameters: PushNotificationTypeAndParameters,
    keycloakPushTopics: MutableList<String>,
    private val encryptedDeviceNameForFirstRegistration: EncryptedBytes
) : ServerMethod() {
    private val server: String
    private val keycloakPushTopics: Array<String>

    init {
        this.server = ownedIdentity.server
        this.keycloakPushTopics = keycloakPushTopics.toTypedArray<String>()
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        val extraInfo: Encoded?
        when (pushNotificationTypeAndParameters.pushNotificationType) {
            PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_ANDROID -> {
                extraInfo = Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(pushNotificationTypeAndParameters.token!!),
                        Encoded.of(pushNotificationTypeAndParameters.identityMaskingUid!!),
                    )
                )
            }

            PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX, PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON -> {
                extraInfo = Encoded.of(emptyArray<Encoded>())
            }

            else -> {
                extraInfo = Encoded.of(emptyArray<Encoded>())
            }
        }

        if (pushNotificationTypeAndParameters.deviceUidToReplace != null) {
            return Encoded.of(
                arrayOf(
                    Encoded.of(ownedIdentity),
                    Encoded.of(token),
                    Encoded.of(deviceUid),
                    Encoded.of(byteArrayOf(pushNotificationTypeAndParameters.pushNotificationType)),
                    extraInfo,
                    Encoded.of(pushNotificationTypeAndParameters.reactivateCurrentDevice),
                    @Suppress("UNCHECKED_CAST") Encoded.of(keycloakPushTopics),
                    Encoded.of(encryptedDeviceNameForFirstRegistration),
                    Encoded.of(pushNotificationTypeAndParameters.deviceUidToReplace!!),
                )
            ).bytes
        } else {
            return Encoded.of(
                arrayOf(
                    Encoded.of(ownedIdentity),
                    Encoded.of(token),
                    Encoded.of(deviceUid),
                    Encoded.of(byteArrayOf(pushNotificationTypeAndParameters.pushNotificationType)),
                    extraInfo,
                    Encoded.of(pushNotificationTypeAndParameters.reactivateCurrentDevice),
                    @Suppress("UNCHECKED_CAST") Encoded.of(keycloakPushTopics),
                    Encoded.of(encryptedDeviceNameForFirstRegistration),
                )
            ).bytes
        }
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        // Nothing to parse here
    }

    override fun isActiveIdentityRequired(): Boolean {
        return false
    }

    companion object {
        private const val SERVER_METHOD_PATH = "/registerPushNotification"
    }
}