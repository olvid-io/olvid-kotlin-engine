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
import io.olvid.engine.crypto.PRNG
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Operation
import io.olvid.engine.datatypes.ServerMethod
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.ServerQuery
import io.olvid.engine.datatypes.containers.ServerQuery.CheckKeycloakRevocationQuery
import io.olvid.engine.datatypes.containers.ServerQuery.CreateGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeleteGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceDiscoveryQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceManagementDeactivateDeviceQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceManagementSetNicknameQuery
import io.olvid.engine.datatypes.containers.ServerQuery.DeviceManagementSetUnexpiringDeviceQuery
import io.olvid.engine.datatypes.containers.ServerQuery.GetGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.GetKeycloakDataQuery
import io.olvid.engine.datatypes.containers.ServerQuery.GetUserDataQuery
import io.olvid.engine.datatypes.containers.ServerQuery.LockGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.PutGroupLogQuery
import io.olvid.engine.datatypes.containers.ServerQuery.PutUserDataQuery
import io.olvid.engine.datatypes.containers.ServerQuery.UpdateGroupBlobQuery
import io.olvid.engine.datatypes.containers.ServerQuery.UploadPreKeyQuery
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.networkfetch.databases.PendingServerQuery
import io.olvid.engine.networkfetch.databases.ServerSession
import io.olvid.engine.networkfetch.datatypes.FetchManagerSessionFactory
import io.olvid.engine.storage.EngineFile
import io.olvid.engine.storage.EngineFileIo
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.sql.SQLException
import java.util.UUID
import javax.net.ssl.SSLSocketFactory

class ServerQueryOperation(
    private val fetchManagerSessionFactory: FetchManagerSessionFactory,
    private val sslSocketFactory: SSLSocketFactory?,
    private val userAgentOverride: String?,
    @JvmField val serverQueryUid: UID?,
    private val prng: PRNG?,
    onFinishCallback: OnFinishCallback?,
    onCancelCallback: OnCancelCallback?
) : Operation(
    serverQueryUid, onFinishCallback, onCancelCallback
) {
    private var serverQuery: ServerQuery? = null // will be set if the operation finishes normally
    var serverResponse: Encoded? = null // will be set if the operation finishes normally
        private set

    fun getServerQuery(): ServerQuery {
        return serverQuery!!
    }

    override fun doExecute() {
        var finished = false
        try {
            fetchManagerSessionFactory.session!!.use { fetchManagerSession ->
                try {
                    val pendingServerQuery: PendingServerQuery? =
                        PendingServerQuery.get(fetchManagerSession, serverQueryUid)
                    if (pendingServerQuery == null) {
                        cancel(RFC_BAD_ENCODED_SERVER_QUERY)
                        return
                    }
                    try {
                        serverQuery = ServerQuery.of(pendingServerQuery.encodedQuery)
                    } catch (_: DecodingException) {
                        cancel(RFC_BAD_ENCODED_SERVER_QUERY)
                        return
                    }

                    Logger.d("?? Starting server query operation of type " + serverQuery!!.getType().id)

                    val serverMethod: ServerQueryServerMethod
                    val queryType = serverQuery!!.getType()
                    when (queryType.id) {
                        ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID -> {
                            val deviceDiscoveryQuery = queryType as DeviceDiscoveryQuery
                            serverMethod =
                                DeviceDiscoveryServerMethod(deviceDiscoveryQuery.identity)
                        }

                        ServerQuery.TypeId.PUT_USER_DATA_QUERY_ID -> {
                            val putUserDataQuery = queryType as PutUserDataQuery
                            val serverSessionToken: ByteArray? = ServerSession.getToken(
                                fetchManagerSession,
                                putUserDataQuery.ownedIdentity
                            )
                            if (serverSessionToken == null) {
                                cancel(RFC_INVALID_SERVER_SESSION)
                                return
                            }
                            // encrypt the photo
                            val absoluteOrNotPhotoUrl = putUserDataQuery.dataUrl
                            val photoFile: EngineFile
                            if (File(absoluteOrNotPhotoUrl).isAbsolute()) {
                                photoFile = fetchManagerSession.fileIo.file(absoluteOrNotPhotoUrl)
                            } else {
                                photoFile = fetchManagerSession.fileIo.file(
                                    fetchManagerSession.engineBaseDirectory,
                                    absoluteOrNotPhotoUrl
                                )
                            }
                            val buffer: ByteArray
                            try {
                                buffer = ByteArray(photoFile.length().toInt())
                                if (buffer.size == 0) {
                                    throw Exception()
                                }
                            } catch (e: Exception) {
                                // unable to find source file. Finish normally so the protocol can finish
                                Logger.e("PutUserData Error: Unable to open file " + photoFile)
                                serverResponse = null
                                finished = true
                                return
                            }
                            photoFile.openInput().use { f ->
                                var bufferFullness = 0
                                while (bufferFullness < buffer.size) {
                                    val count =
                                        f.read(buffer, bufferFullness, buffer.size - bufferFullness)
                                    if (count < 0) {
                                        break
                                    }
                                    bufferFullness += count
                                }
                            }
                            val authEnc = Suite.getAuthEnc(putUserDataQuery.dataKey)!!
                            val encryptedPhoto =
                                authEnc.encrypt(putUserDataQuery.dataKey, buffer, prng)

                            serverMethod = PutUserDataServerMethod(
                                putUserDataQuery.ownedIdentity,
                                serverSessionToken,
                                putUserDataQuery.serverLabel,
                                encryptedPhoto
                            )
                        }

                        ServerQuery.TypeId.GET_USER_DATA_QUERY_ID -> {
                            val getUserDataQuery = queryType as GetUserDataQuery
                            serverMethod = GetUserDataServerMethod(
                                getUserDataQuery.identity,
                                getUserDataQuery.serverLabel,
                                getUserDataQuery.retryIfNotFound,
                                fetchManagerSession.engineBaseDirectory,
                                fetchManagerSession.fileIo
                            )
                        }

                        ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID -> {
                            val checkKeycloakRevocationQuery =
                                queryType as CheckKeycloakRevocationQuery
                            serverMethod = CheckKeycloakRevocationServerMethod(
                                checkKeycloakRevocationQuery.server,
                                checkKeycloakRevocationQuery.signedContactDetails
                            )
                        }

                        ServerQuery.TypeId.CREATE_GROUP_BLOB_QUERY_ID -> {
                            val createGroupBlobQuery = queryType as CreateGroupBlobQuery
                            val serverSessionToken: ByteArray? = ServerSession.getToken(
                                fetchManagerSession,
                                serverQuery!!.getOwnedIdentity()
                            )
                            if (serverSessionToken == null) {
                                cancel(RFC_INVALID_SERVER_SESSION)
                                return
                            }
                            serverMethod = CreateGroupBlobServerMethod(
                                serverQuery!!.getOwnedIdentity()!!,
                                serverSessionToken,
                                createGroupBlobQuery.server,
                                createGroupBlobQuery.groupUid,
                                createGroupBlobQuery.encodedGroupAdminPublicKey,
                                createGroupBlobQuery.encryptedBlob
                            )
                        }

                        ServerQuery.TypeId.GET_GROUP_BLOB_QUERY_ID -> {
                            val groupBlobQuery = queryType as GetGroupBlobQuery
                            serverMethod = GetGroupBlobServerMethod(
                                groupBlobQuery.server,
                                groupBlobQuery.groupUid,
                                groupBlobQuery.serverQueryNonce
                            )
                        }

                        ServerQuery.TypeId.LOCK_GROUP_BLOB_QUERY_ID -> {
                            val lockGroupBlobQuery = queryType as LockGroupBlobQuery
                            serverMethod = LockGroupBlobServerMethod(
                                lockGroupBlobQuery.server,
                                lockGroupBlobQuery.groupUid,
                                lockGroupBlobQuery.lockNonce,
                                lockGroupBlobQuery.signature
                            )
                        }

                        ServerQuery.TypeId.UPDATE_GROUP_BLOB_QUERY_ID -> {
                            val updateGroupBlobQuery = queryType as UpdateGroupBlobQuery
                            serverMethod = UpdateGroupBlobServerMethod(
                                updateGroupBlobQuery.server,
                                updateGroupBlobQuery.groupUid,
                                updateGroupBlobQuery.lockNonce,
                                updateGroupBlobQuery.encryptedBlob,
                                updateGroupBlobQuery.encodedGroupAdminPublicKey,
                                updateGroupBlobQuery.signature
                            )
                        }

                        ServerQuery.TypeId.PUT_GROUP_LOG_QUERY_ID -> {
                            val putGroupLogQuery = queryType as PutGroupLogQuery
                            serverMethod = PutGroupLogServerMethod(
                                putGroupLogQuery.server,
                                putGroupLogQuery.groupUid,
                                putGroupLogQuery.signature
                            )
                        }

                        ServerQuery.TypeId.DELETE_GROUP_BLOB_QUERY_ID -> {
                            val deleteGroupBlobQuery = queryType as DeleteGroupBlobQuery
                            serverMethod = DeleteGroupBlobServerMethod(
                                deleteGroupBlobQuery.server,
                                deleteGroupBlobQuery.groupUid,
                                deleteGroupBlobQuery.signature
                            )
                        }

                        ServerQuery.TypeId.GET_KEYCLOAK_DATA_QUERY_ID -> {
                            val getKeycloakDataQuery = queryType as GetKeycloakDataQuery
                            serverMethod = GetKeycloakDataServerMethod(
                                getKeycloakDataQuery.server,
                                getKeycloakDataQuery.serverLabel,
                                fetchManagerSession.engineBaseDirectory,
                                fetchManagerSession.fileIo
                            )
                        }

                        ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID -> {
                            serverMethod =
                                OwnedDeviceDiscoveryServerMethod(serverQuery!!.getOwnedIdentity()!!)
                        }

                        ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID -> {
                            val serverSessionToken: ByteArray? = ServerSession.getToken(
                                fetchManagerSession,
                                serverQuery!!.getOwnedIdentity()
                            )
                            if (serverSessionToken == null) {
                                cancel(RFC_INVALID_SERVER_SESSION)
                                return
                            }
                            serverMethod = DeviceManagementServerMethod(
                                serverQuery!!.getOwnedIdentity()!!,
                                serverSessionToken,
                                serverQuery!!.getType()
                            )
                        }

                        ServerQuery.TypeId.UPLOAD_PRE_KEY_QUERY_ID -> {
                            val uploadPreKeyQuery = queryType as UploadPreKeyQuery
                            val serverSessionToken: ByteArray? = ServerSession.getToken(
                                fetchManagerSession,
                                serverQuery!!.getOwnedIdentity()
                            )
                            if (serverSessionToken == null) {
                                cancel(RFC_INVALID_SERVER_SESSION)
                                return
                            }
                            serverMethod = UploadPreKeyServerMethod(
                                serverQuery!!.getOwnedIdentity()!!,
                                serverSessionToken,
                                uploadPreKeyQuery.deviceUid,
                                uploadPreKeyQuery.preKeyBytes
                            )
                        }

                        ServerQuery.TypeId.REGISTER_API_KEY_QUERY_ID, ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID, ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID, ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID, ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID, ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION -> {
                            cancel(RFC_BAD_ENCODED_SERVER_QUERY)
                            return
                        }

                        else -> {
                            cancel(RFC_BAD_ENCODED_SERVER_QUERY)
                            return
                        }
                    }
                    serverMethod.setSslSocketFactory(sslSocketFactory, userAgentOverride)

                    val returnStatus = serverMethod.execute(
                        fetchManagerSession.identityDelegate!!.isActiveOwnedIdentity(
                            fetchManagerSession.session,
                            serverQuery!!.getOwnedIdentity()
                        )
                    )
                    Logger.d("?? Server query return status (after parse): " + returnStatus)

                    when (returnStatus) {
                        ServerMethod.OK -> {
                            // some parseReceivedData methods change the actual returnStatus to OK --> this way the protocol can properly finish/abort
                            serverResponse = serverMethod.serverResponse
                            finished = true
                            return
                        }

                        ServerMethod.INVALID_SESSION -> {
                            cancel(RFC_INVALID_SERVER_SESSION)
                            return
                        }

                        ServerMethod.IDENTITY_IS_NOT_ACTIVE -> {
                            cancel(RFC_IDENTITY_IS_INACTIVE)
                            return
                        }

                        ServerMethod.PAYLOAD_TOO_LARGE -> {
                            cancel(RFC_USER_DATA_TOO_LARGE)
                            return
                        }

                        ServerMethod.DEVICE_IS_NOT_REGISTERED -> {
                            // if the device is not registered:
                            // - cancel if this is a remote device
                            // - retry later if this is our current device for a set nickname request
                            if (serverQuery!!.getType() is DeviceManagementSetNicknameQuery && (serverQuery!!.getType() as DeviceManagementSetNicknameQuery).isCurrentDevice) {
                                cancel(RFC_DEVICE_NOT_YET_REGISTERED)
                            } else {
                                cancel(RFC_DEVICE_DOES_NOT_EXIST)
                            }
                            return
                        }

                        ServerMethod.MALFORMED_URL -> {
                            cancel(RFC_MALFORMED_URL)
                            return
                        }

                        else -> {
                            // check if the serverQuery has expired
                            if (System.currentTimeMillis() > pendingServerQuery.creationTimestamp + Constants.SERVER_QUERY_EXPIRATION_DELAY) {
                                when (serverQuery!!.getType().id) {
                                    ServerQuery.TypeId.DEVICE_DISCOVERY_QUERY_ID -> {
                                        serverResponse =
                                            Encoded.of(HashMap<DictionaryKey, Encoded>()) // return an empty dictionary so we know it's not a real output
                                        finished = true
                                        return
                                    }

                                    ServerQuery.TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID -> {
                                        serverResponse =
                                            Encoded.of(ByteArray(0)) // return an empty byte array
                                        finished = true
                                        return
                                    }

                                    ServerQuery.TypeId.PUT_USER_DATA_QUERY_ID, ServerQuery.TypeId.GET_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.PUT_GROUP_LOG_QUERY_ID, ServerQuery.TypeId.LOCK_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.UPLOAD_PRE_KEY_QUERY_ID -> {
                                        serverResponse = null
                                        finished = true
                                        return
                                    }

                                    ServerQuery.TypeId.GET_USER_DATA_QUERY_ID, ServerQuery.TypeId.GET_KEYCLOAK_DATA_QUERY_ID -> {
                                        serverResponse =
                                            Encoded.of("") // as if it was deleted from the server
                                        finished = true
                                        return
                                    }

                                    ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID -> {
                                        serverResponse =
                                            Encoded.of(true) // consider the user is not revoked (rationale: another protocol has probably been run since then, we do not want to delete the user)
                                        finished = true
                                        return
                                    }

                                    ServerQuery.TypeId.CREATE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.UPDATE_GROUP_BLOB_QUERY_ID, ServerQuery.TypeId.DELETE_GROUP_BLOB_QUERY_ID -> {
                                        serverResponse = Encoded.of(false) // consider the query failed
                                        finished = true
                                        return
                                    }

                                    ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID, ServerQuery.TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID -> {
                                        serverResponse = null
                                        finished = true
                                        return
                                    }

                                    ServerQuery.TypeId.REGISTER_API_KEY_QUERY_ID, ServerQuery.TypeId.TRANSFER_SOURCE_QUERY_ID, ServerQuery.TypeId.TRANSFER_TARGET_QUERY_ID, ServerQuery.TypeId.TRANSFER_RELAY_QUERY_ID, ServerQuery.TypeId.TRANSFER_WAIT_QUERY_ID, ServerQuery.TypeId.TRANSFER_CLOSE_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID, ServerQuery.TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE, ServerQuery.TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION -> {}
                                    else -> {}
                                }
                            } else if (serverQuery!!.getType().id == ServerQuery.TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID && returnStatus == ServerMethod.SERVER_CONNECTION_ERROR) {
                                // if not able to connect to keycloak, assume the user is not revoked. This is required in setups where one of the user's devices does not have access to keycloak
                                // TODO: once we implement visibility rules in keycloak, this must be removed and replaced by synchronisation messages between owned devices in the protocol
                                serverResponse = Encoded.of(true)
                                finished = true
                                return
                            }
                            cancel(RFC_NETWORK_ERROR)
                        }
                    }
                } catch (e: Exception) {
                    Logger.x(e)
                } finally {
                    if (finished) {
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
        }
    }

    override fun doCancel() {
        // Nothing special to do on cancel
    }

    companion object {
        // possible reasons for cancel
        const val RFC_NETWORK_ERROR: Int = 1
        const val RFC_BAD_ENCODED_SERVER_QUERY: Int = 2
        const val RFC_INVALID_SERVER_SESSION: Int = 3
        const val RFC_IDENTITY_IS_INACTIVE: Int = 4
        const val RFC_USER_DATA_TOO_LARGE: Int = 5
        const val RFC_DEVICE_DOES_NOT_EXIST: Int = 6
        const val RFC_DEVICE_NOT_YET_REGISTERED: Int = 7
        const val RFC_MALFORMED_URL: Int = 8
    }
}

internal abstract class ServerQueryServerMethod : ServerMethod() {
    abstract val serverResponse: Encoded?

    override fun isActiveIdentityRequired(): Boolean {
        return true
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        Logger.d("?? Server query return status (before parse): " + returnStatus)
    }
}

internal class DeviceDiscoveryServerMethod(private val identity: Identity) :
    ServerQueryServerMethod() {
    private val server: String

    override var serverResponse: Encoded? = null

    init {
        this.server = identity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity)
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                // check that decoding works properly
                receivedData!![0]!!.decodeDictionary()
                serverResponse = receivedData[0]
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/deviceDiscovery"
    }
}

internal class OwnedDeviceDiscoveryServerMethod(private val identity: Identity) :
    ServerQueryServerMethod() {
    private val server: String

    override var serverResponse: Encoded? = null

    init {
        this.server = identity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity)
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                // check that decoding works properly
                receivedData!![0]!!.decodeEncryptedData()
                serverResponse = receivedData[0]
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/ownedDeviceDiscovery"
    }
}

internal class PutUserDataServerMethod(
    private val identity: Identity,
    private val token: ByteArray,
    private val serverLabel: UID,
    private val data: EncryptedBytes
) : ServerQueryServerMethod() {
    private val server: String

    override var serverResponse: Encoded? = null

    init {
        this.server = identity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity),
                Encoded.of(token),
                Encoded.of(serverLabel),
                Encoded.of(data),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            if (receivedData!!.size == 0) {
                // check that decoding works properly
                serverResponse = null
            } else {
                returnStatus = GENERAL_ERROR
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/putUserData"
    }
}

internal open class GetUserDataServerMethod(
    protected val identity: Identity,
    protected val serverLabel: UID,
    protected val retryIfNotFound: Boolean,
    protected val engineBaseDirectory: String?,
    protected val fileIo: EngineFileIo?
) : ServerQueryServerMethod() {
    override var serverResponse: Encoded? = null

    override fun getServer(): String {
        return identity.server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(identity),
                Encoded.of(serverLabel),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                // write the result to a file
                val encryptedData = receivedData!![0]!!.decodeEncryptedData()
                // Ugly hack: the filename contains a timestamp after which the file is considered "orphan" and can be deleted
                val userDataPath =
                    Constants.DOWNLOADED_USER_DATA_DIRECTORY + File.separator + (System.currentTimeMillis() + Constants.GET_USER_DATA_LOCAL_FILE_LIFESPAN) + "." + Logger.toHexString(
                        serverLabel.bytes
                    ) + "-" + Logger.getUuidString(
                        UUID.randomUUID()
                    )
                fileIo!!.file(engineBaseDirectory, userDataPath).openOutput().use { fis ->
                    fis.write(encryptedData.getBytes())
                }
                serverResponse = Encoded.of(userDataPath)
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            } catch (e: IOException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        } else if (returnStatus == DELETED_FROM_SERVER && !retryIfNotFound) {
            returnStatus = OK
            serverResponse = Encoded.of("")
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/getUserData"
    }
}

internal class CheckKeycloakRevocationServerMethod(
    keycloakServerUrl: String?, // this is a JWT
    private val signedContactDetails: String
) : ServerQueryServerMethod() {
    private val server: String
    private val path: String

    override var serverResponse: Encoded? = null

    init {
        val url = keycloakServerUrl + SERVER_METHOD_PATH
        val pos = url.indexOf('/', 8)
        this.server = url.substring(0, pos)
        this.path = url.substring(pos)
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return path
    }

    override fun getDataToSend(): ByteArray {
        val jsonString = "{\"signature\": \"" + signedContactDetails + "\"}"
        return jsonString.toByteArray(StandardCharsets.UTF_8)
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                val verificationSuccessful = receivedData!![0]!!.decodeBoolean()
                Logger.w("Server responded to verify server query: " + verificationSuccessful)
                serverResponse = Encoded.of(verificationSuccessful)
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "olvid-rest/verify"
    }
}

internal class CreateGroupBlobServerMethod(
    private val ownedIdentity: Identity,
    private val token: ByteArray,
    private val server: String?,
    private val groupUid: UID,
    private val encodedGroupAdminPublicKey: Encoded?,
    private val encryptedBlob: EncryptedBytes
) : ServerQueryServerMethod() {
    override var serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(ownedIdentity),
                Encoded.of(token),
                Encoded.of(groupUid),
                encodedGroupAdminPublicKey!!,
                Encoded.of(encryptedBlob),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            serverResponse = Encoded.of(0) // success
        } else if (returnStatus == GROUP_UID_ALREADY_USED) {
            returnStatus = OK
            serverResponse = Encoded.of(2) // definitive fail
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/groupBlobCreate"
    }
}

internal class GetGroupBlobServerMethod(
    private val server: String?,
    private val groupUid: UID,
    private val nonce: ByteArray
) : ServerQueryServerMethod() {
    override var serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(groupUid),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                if (receivedData!!.size != 4) {
                    throw DecodingException()
                }
                val encryptedBlob = receivedData[0]!!.decodeEncryptedData()
                val encodedLogItems = receivedData[1]!!.decodeList()
                for (encodedLogItem in encodedLogItems) {
                    encodedLogItem.decodeBytes()
                }
                val groupAdminPublicKey =
                    receivedData[2]!!.decodePublicKey() as ServerAuthenticationPublicKey?
                val updateTimestamp = receivedData[3]!!.decodeLong()
                serverResponse = Encoded.of(
                    arrayOf<Encoded>(
                        receivedData[0]!!,
                        receivedData[1]!!,
                        receivedData[2]!!,
                        Encoded.of(nonce),
                        receivedData[3]!!,
                    )
                )
            } catch (e: Exception) {
                Logger.x(e)
                returnStatus = MALFORMED_SERVER_RESPONSE
            }
        } else if (returnStatus == DELETED_FROM_SERVER) {
            // if the blob is not found on the server, behave as a success to let the protocol know the blob was deleted
            returnStatus = OK
            serverResponse = Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(true),
                )
            )
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/groupBlobGet"
    }
}

internal class LockGroupBlobServerMethod(
    private val server: String?,
    private val groupUid: UID,
    private val lockNonce: ByteArray,
    private val signature: ByteArray
) : ServerQueryServerMethod() {
    override var serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(lockNonce),
                Encoded.of(signature),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                if (receivedData!!.size != 4) {
                    throw DecodingException()
                }
                val encryptedBlob = receivedData[0]!!.decodeEncryptedData()
                val encodedLogItems = receivedData[1]!!.decodeList()
                for (encodedLogItem in encodedLogItems) {
                    encodedLogItem.decodeBytes()
                }
                val groupAdminPublicKey =
                    receivedData[2]!!.decodePublicKey() as ServerAuthenticationPublicKey?
                val updateTimestamp = receivedData[3]!!.decodeLong()
                serverResponse = Encoded.of(
                    arrayOf<Encoded>(
                        receivedData[0]!!,
                        receivedData[1]!!,
                        receivedData[2]!!,
                        Encoded.of(lockNonce),
                        receivedData[3]!!,
                    )
                )
            } catch (e: Exception) {
                Logger.x(e)
                returnStatus = MALFORMED_SERVER_RESPONSE
            }
        } else if (returnStatus == DELETED_FROM_SERVER
            || returnStatus == INVALID_SIGNATURE
        ) {
            // if the blob is not found on the server, or the signature is invalid, behave as a success to let the protocol properly abort
            returnStatus = OK
            serverResponse = null
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/groupBlobLock"
    }
}

internal class UpdateGroupBlobServerMethod(
    private val server: String?,
    private val groupUid: UID,
    private val lockNonce: ByteArray,
    private val encryptedBlob: EncryptedBytes,
    private val encodedGroupAdminPublicKey: Encoded?,
    private val signature: ByteArray
) : ServerQueryServerMethod() {
    override var serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(lockNonce),
                Encoded.of(encryptedBlob),
                encodedGroupAdminPublicKey!!,
                Encoded.of(signature),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            serverResponse = Encoded.of(0) // success
        } else if (returnStatus == GROUP_NOT_LOCKED) {
            returnStatus = OK
            serverResponse = Encoded.of(1) // retry-able fail
        } else if (returnStatus == DELETED_FROM_SERVER
            || returnStatus == INVALID_SIGNATURE
        ) {
            returnStatus = OK
            serverResponse = Encoded.of(2) // definitive fail
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/groupBlobUpdate"
    }
}

internal class PutGroupLogServerMethod(
    private val server: String?,
    private val groupUid: UID,
    private val signature: ByteArray
) : ServerQueryServerMethod() {
    override val serverResponse: Encoded? = null

    override fun isActiveIdentityRequired(): Boolean {
        // this server query is also called when an owned identity is deleted with contact notification --> it should not require an active identity
        return false
    }

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(signature),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == DELETED_FROM_SERVER) {
            // if the group was deleted from the server, still mark the query as successful
            returnStatus = OK
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/groupLogPut"
    }
}


internal class DeleteGroupBlobServerMethod(
    private val server: String?,
    private val groupUid: UID,
    private val signature: ByteArray
) : ServerQueryServerMethod() {
    override var serverResponse: Encoded? = null

    override fun isActiveIdentityRequired(): Boolean {
        // this server query is also called when an owned identity is deleted with contact notification --> it should not require an active identity
        return false
    }

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(signature),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        serverResponse = Encoded.of(returnStatus == OK)

        if (returnStatus == INVALID_SIGNATURE) {
            // if the signature is invalid, still mark the query as successful
            returnStatus = OK
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/groupBlobDelete"
    }
}

internal class GetKeycloakDataServerMethod(
    keycloakServerUrl: String?,
    private val serverLabel: UID,
    engineBaseDirectory: String?,
    private val fileIo: EngineFileIo?
) : ServerQueryServerMethod() {
    private val server: String
    private val path: String
    private val engineBaseDirectory: String?
    override var serverResponse: Encoded? = null

    init {
        val url = keycloakServerUrl + SERVER_METHOD_PATH
        val pos = url.indexOf('/', 8)
        this.server = url.substring(0, pos)
        this.path = url.substring(pos)
        this.engineBaseDirectory = engineBaseDirectory
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return path
    }

    override fun getDataToSend(): ByteArray {
        return serverLabel.bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                // write the result to a file
                val encryptedData = receivedData!![0]!!.decodeEncryptedData()
                // Ugly hack: the filename contains a timestamp after which the file is considered "orphan" and can be deleted
                val userDataPath =
                    Constants.DOWNLOADED_USER_DATA_DIRECTORY + File.separator + (System.currentTimeMillis() + Constants.GET_USER_DATA_LOCAL_FILE_LIFESPAN) + "." + Logger.toHexString(
                        serverLabel.bytes
                    ) + "-" + Logger.getUuidString(
                        UUID.randomUUID()
                    )
                fileIo!!.file(engineBaseDirectory, userDataPath).openOutput().use { fis ->
                    fis.write(encryptedData.getBytes())
                }
                serverResponse = Encoded.of(userDataPath)
            } catch (e: DecodingException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            } catch (e: IOException) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        } else if (returnStatus == DELETED_FROM_SERVER) {
            returnStatus = OK
            serverResponse = Encoded.of("")
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "olvid-rest/getData"
    }
}

internal class DeviceManagementServerMethod(
    private val identity: Identity,
    private val token: ByteArray,
    private val queryType: ServerQuery.Type?
) : ServerQueryServerMethod() {
    private val server: String
    override var serverResponse: Encoded? = null

    init {
        this.server = identity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        if (queryType is DeviceManagementSetNicknameQuery) {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(identity),
                    Encoded.of(token),
                    Encoded.of(byteArrayOf(0x00.toByte())),
                    Encoded.of(queryType.deviceUid),
                    Encoded.of(queryType.encryptedDeviceName),
                )
            ).bytes
        } else if (queryType is DeviceManagementDeactivateDeviceQuery) {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(identity),
                    Encoded.of(token),
                    Encoded.of(byteArrayOf(0x01.toByte())),
                    Encoded.of(queryType.deviceUid),
                )
            ).bytes
        } else if (queryType is DeviceManagementSetUnexpiringDeviceQuery) {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(identity),
                    Encoded.of(token),
                    Encoded.of(byteArrayOf(0x02.toByte())),
                    Encoded.of(queryType.deviceUid),
                )
            ).bytes
        } else {
            // invalid query type
            return ByteArray(0)
        }
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            if (receivedData!!.size == 0) {
                // check that decoding works properly
                serverResponse = null
            } else {
                returnStatus = GENERAL_ERROR
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/deviceManagement"
    }
}


internal class RegisterApiKeyServerMethod(
    private val ownedIdentity: Identity,
    private val token: ByteArray,
    private val apiKeyString: String
) : ServerQueryServerMethod() {
    private val server: String
    override val serverResponse: Encoded? = null

    init {
        this.server = ownedIdentity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(ownedIdentity),
                Encoded.of(token),
                Encoded.of(apiKeyString),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/registerApiKey"
    }
}


internal class UploadPreKeyServerMethod(
    private val ownedIdentity: Identity,
    private val token: ByteArray,
    private val deviceUid: UID,
    private val preKeyBytes: ByteArray
) : ServerQueryServerMethod() {
    private val server: String
    override val serverResponse: Encoded? = null

    init {
        this.server = ownedIdentity.server
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(ownedIdentity),
                Encoded.of(token),
                Encoded.of(deviceUid),
                Encoded(preKeyBytes),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        // if the server rejects our pre key there is not much we can do, so no retry
        if (returnStatus == INVALID_SIGNATURE
            || returnStatus == DEVICE_IS_NOT_REGISTERED
        ) {
            returnStatus = OK
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/uploadPreKey"
    }
}


// region backups v2
internal class BackupsV2CreateBackupServerMethod(
    private val server: String?,
    private val backupUid: UID,
    private val serverAuthenticationPublicKey: ServerAuthenticationPublicKey
) : ServerQueryServerMethod() {
    override val serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(backupUid),
                Encoded.of(serverAuthenticationPublicKey),
            )
        ).bytes
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/backupCreate"
    }
}

internal class BackupsV2UploadBackupsServerMethod(
    private val server: String?,
    private val backupUid: UID,
    private val threadId: UID,
    private val version: Long,
    private val encryptedBackup: EncryptedBytes,
    private val signature: ByteArray
) : ServerQueryServerMethod() {
    override val serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(backupUid),
                Encoded.of(threadId),
                Encoded.of(version),
                Encoded.of(encryptedBackup),
                Encoded.of(signature),
            )
        ).bytes
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/backupUpload"
    }
}

internal class BackupsV2DeleteBackupServerMethod(
    private val server: String?,
    private val backupUid: UID,
    private val threadId: UID,
    private val version: Long,
    private val signature: ByteArray
) : ServerQueryServerMethod() {
    override val serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(backupUid),
                Encoded.of(threadId),
                Encoded.of(version),
                Encoded.of(signature),
            )
        ).bytes
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/backupDelete"
    }
}


internal class BackupsV2ListBackupsServerMethod(
    private val server: String?,
    private val backupUid: UID
) : ServerQueryServerMethod() {
    override var serverResponse: Encoded? = null

    override fun getServer(): String? {
        return server
    }

    override fun getServerMethod(): String {
        return SERVER_METHOD_PATH
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(backupUid),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            if (receivedData!!.size == 1) {
                serverResponse = receivedData[0]
            } else {
                returnStatus = MALFORMED_SERVER_RESPONSE
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "/backupList"
    }
}


internal class BackupsV2DownloadProfilePictureServerMethod(
    identity: Identity,
    photoLabel: UID,
    private val photoKey: AuthEncKey?
) : GetUserDataServerMethod(identity, photoLabel, false, null, null) {
    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        if (returnStatus == OK) {
            try {
                // decrypt the result
                val encryptedData = receivedData!![0]!!.decodeEncryptedData()
                val authEnc = Suite.getAuthEnc(photoKey)!!
                serverResponse = Encoded.of(authEnc.decrypt(photoKey, encryptedData)!!)
            } catch (e: Exception) {
                Logger.x(e)
                returnStatus = GENERAL_ERROR
            }
        }
    }
}

internal class KeycloakIdBasedAuthRequestChallengeServerMethod(
    keycloakServerUrl: String?,
    keycloakUserId: String,
    nonce: ByteArray
) : ServerQueryServerMethod() {
    @JvmField val server: String
    @JvmField val path: String
    @JvmField val keycloakUserId: String
    @JvmField val nonce: ByteArray
    override var serverResponse: Encoded? = null

    init {
        val url = keycloakServerUrl + SERVER_METHOD_PATH
        val pos = url.indexOf('/', 8)
        this.server = url.substring(0, pos)
        this.path = url.substring(pos)

        this.keycloakUserId = keycloakUserId
        this.nonce = nonce
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return path
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(keycloakUserId),
                Encoded.of(nonce),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            try {
                // check the nonce matches and only return the challenge
                if (receivedData!!.size == 2 && receivedData[1]!!.decodeBytes()
                        .contentEquals(nonce)
                ) {
                    serverResponse = receivedData[0]
                } else {
                    returnStatus = MALFORMED_SERVER_RESPONSE
                }
            } catch (_: Exception) {
                returnStatus = MALFORMED_SERVER_RESPONSE
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "olvid-rest/requestChallenge"
    }
}

internal class KeycloakIdBasedAuthGetSessionServerMethod(
    keycloakServerUrl: String?,
    challengeResponse: ByteArray,
    nonce: ByteArray
) : ServerQueryServerMethod() {
    @JvmField val server: String
    @JvmField val path: String
    @JvmField val challengeResponse: ByteArray
    @JvmField val nonce: ByteArray
    override var serverResponse: Encoded? = null

    init {
        val url = keycloakServerUrl + SERVER_METHOD_PATH
        val pos = url.indexOf('/', 8)
        this.server = url.substring(0, pos)
        this.path = url.substring(pos)

        this.challengeResponse = challengeResponse
        this.nonce = nonce
    }

    override fun getServer(): String {
        return server
    }

    override fun getServerMethod(): String {
        return path
    }

    override fun getDataToSend(): ByteArray {
        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(challengeResponse),
                Encoded.of(nonce),
            )
        ).bytes
    }

    override fun parseReceivedData(receivedData: Array<Encoded?>?) {
        super.parseReceivedData(receivedData)
        if (returnStatus == OK) {
            if (receivedData!!.size == 1) {
                serverResponse = receivedData[0]
            } else {
                returnStatus = MALFORMED_SERVER_RESPONSE
            }
        }
    }


    companion object {
        private const val SERVER_METHOD_PATH = "olvid-rest/getSession"
    }
} // endregion
