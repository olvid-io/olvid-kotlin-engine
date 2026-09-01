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
package io.olvid.engine.datatypes.containers

import io.olvid.engine.datatypes.EncryptedBytes
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded

class ServerQuery(@JvmField val encodedElements: Encoded?, @JvmField val ownedIdentity: Identity?, @JvmField val type: Type) {
    var encodedResponse: Encoded? = null
        private set

    val isWebSocket: Boolean
        get() = type.isWebSocket

    fun encode(): Encoded {
        return Encoded.of(
            arrayOf<Encoded>(
                encodedElements!!,
                Encoded.of(ownedIdentity!!),
                type.encode()
            )
        )
    }

    fun setResponse(encodedResponse: Encoded?) {
        this.encodedResponse = encodedResponse
    }


    enum class TypeId(val value: Int) {
        DEVICE_DISCOVERY_QUERY_ID(0),
        PUT_USER_DATA_QUERY_ID(1),
        GET_USER_DATA_QUERY_ID(2),
        CHECK_KEYCLOAK_REVOCATION_QUERY_ID(3),
        CREATE_GROUP_BLOB_QUERY_ID(4),
        GET_GROUP_BLOB_QUERY_ID(5),
        LOCK_GROUP_BLOB_QUERY_ID(6),
        UPDATE_GROUP_BLOB_QUERY_ID(7),
        PUT_GROUP_LOG_QUERY_ID(8),
        DELETE_GROUP_BLOB_QUERY_ID(9),
        GET_KEYCLOAK_DATA_QUERY_ID(10),
        OWNED_DEVICE_DISCOVERY_QUERY_ID(11),
        DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID(12),
        DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID(13),
        DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID(14),
        REGISTER_API_KEY_QUERY_ID(15),
        UPLOAD_PRE_KEY_QUERY_ID(16),

        TRANSFER_SOURCE_QUERY_ID(1000),
        TRANSFER_TARGET_QUERY_ID(1001),
        TRANSFER_RELAY_QUERY_ID(1002),
        TRANSFER_WAIT_QUERY_ID(1003),
        TRANSFER_CLOSE_QUERY_ID(1004),

        BACKUPS_V2_CREATE_BACKUP_QUERY_ID(2000),
        BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID(2001),
        BACKUPS_V2_DELETE_BACKUP_QUERY_ID(2002),
        BACKUPS_V2_LIST_BACKUPS_QUERY_ID(2003),
        BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID(2004),

        KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE(3000),
        KEYCLOAK_ID_BASED_AUTH_GET_SESSION(3001);

        companion object {
            private val valueMap: MutableMap<Int?, TypeId?> = HashMap()

            init {
                for (step in entries) {
                    valueMap[step.value] = step
                }
            }

            fun fromIntValue(value: Int): TypeId? {
                return valueMap[value]
            }
        }
    }

    abstract class Type {
        abstract val id: TypeId?

        abstract val server: String?

        abstract val encodedParts: Array<Encoded>

        abstract val isWebSocket: Boolean

        fun encode(): Encoded {
            return Encoded.of(
                arrayOf(
                    Encoded.of(
                        this.id!!.value.toLong()
                    ),
                    Encoded.of(this.server!!),
                    Encoded.of(this.encodedParts),
                )
            )
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): Type {
                val list: Array<Encoded> = encoded.decodeList()
                if (list.size != 3) {
                    throw DecodingException()
                }
                val id = list[0].decodeLong().toInt()
                val server = list[1].decodeString()
                val encodedParts: Array<Encoded> = list[2].decodeList()
                val typeId: TypeId = TypeId.fromIntValue(id) ?: throw DecodingException()
                when (typeId) {
                    TypeId.DEVICE_DISCOVERY_QUERY_ID -> return DeviceDiscoveryQuery(
                        server,
                        encodedParts
                    )

                    TypeId.PUT_USER_DATA_QUERY_ID -> return PutUserDataQuery(server, encodedParts)
                    TypeId.GET_USER_DATA_QUERY_ID -> return GetUserDataQuery(server, encodedParts)
                    TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID -> return CheckKeycloakRevocationQuery(
                        server,
                        encodedParts
                    )

                    TypeId.CREATE_GROUP_BLOB_QUERY_ID -> return CreateGroupBlobQuery(
                        server,
                        encodedParts
                    )

                    TypeId.GET_GROUP_BLOB_QUERY_ID -> return GetGroupBlobQuery(server, encodedParts)
                    TypeId.LOCK_GROUP_BLOB_QUERY_ID -> return LockGroupBlobQuery(
                        server,
                        encodedParts
                    )

                    TypeId.UPDATE_GROUP_BLOB_QUERY_ID -> return UpdateGroupBlobQuery(
                        server,
                        encodedParts
                    )

                    TypeId.PUT_GROUP_LOG_QUERY_ID -> return PutGroupLogQuery(server, encodedParts)
                    TypeId.DELETE_GROUP_BLOB_QUERY_ID -> return DeleteGroupBlobQuery(
                        server,
                        encodedParts
                    )

                    TypeId.GET_KEYCLOAK_DATA_QUERY_ID -> return GetKeycloakDataQuery(
                        server,
                        encodedParts
                    )

                    TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID -> return OwnedDeviceDiscoveryQuery(
                        server,
                        encodedParts
                    )

                    TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID -> return DeviceManagementSetNicknameQuery(
                        server,
                        encodedParts
                    )

                    TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID -> return DeviceManagementDeactivateDeviceQuery(
                        server,
                        encodedParts
                    )

                    TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID -> return DeviceManagementSetUnexpiringDeviceQuery(
                        server,
                        encodedParts
                    )

                    TypeId.REGISTER_API_KEY_QUERY_ID -> return RegisterApiKeyQuery(
                        server,
                        encodedParts
                    )

                    TypeId.UPLOAD_PRE_KEY_QUERY_ID -> return UploadPreKeyQuery(server, encodedParts)

                    TypeId.TRANSFER_SOURCE_QUERY_ID -> return TransferSourceQuery(encodedParts)
                    TypeId.TRANSFER_TARGET_QUERY_ID -> return TransferTargetQuery(encodedParts)
                    TypeId.TRANSFER_RELAY_QUERY_ID -> return TransferRelayQuery(encodedParts)
                    TypeId.TRANSFER_WAIT_QUERY_ID -> return TransferWaitQuery(encodedParts)
                    TypeId.TRANSFER_CLOSE_QUERY_ID -> return TransferCloseQuery(encodedParts)

                    TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID, TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID, TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID, TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID, TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID, TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE, TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION -> throw DecodingException()
                }
            }
        }
    }

    class DeviceDiscoveryQuery : Type {
        override val server: String?
        @JvmField val identity: Identity

        constructor(identity: Identity) {
            this.server = identity.server
            this.identity = identity
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size != 1) {
                throw DecodingException()
            }
            this.identity = encodedParts[0].decodeIdentity()
        }

        override val id: TypeId = TypeId.DEVICE_DISCOVERY_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(identity),
            )}

        override val isWebSocket: Boolean = false
    }

    class PutUserDataQuery : Type {
        override val server: String?
        @JvmField val ownedIdentity: Identity
        @JvmField val serverLabel: UID
        @JvmField val dataUrl: String // always a relative path
        @JvmField val dataKey: AuthEncKey?

        constructor(
            ownedIdentity: Identity,
            serverLabel: UID,
            dataUrl: String,
            dataKey: AuthEncKey?
        ) {
            this.server = ownedIdentity.server
            this.ownedIdentity = ownedIdentity
            this.serverLabel = serverLabel
            this.dataUrl = dataUrl
            this.dataKey = dataKey
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size != 4) {
                throw DecodingException()
            }
            this.ownedIdentity = encodedParts[0].decodeIdentity()
            this.serverLabel = encodedParts[1].decodeUid()
            this.dataUrl = encodedParts[2].decodeString()
            this.dataKey = encodedParts[3].decodeSymmetricKey() as AuthEncKey?
        }

        override val id: TypeId = TypeId.PUT_USER_DATA_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(ownedIdentity),
                Encoded.of(serverLabel),
                Encoded.of(dataUrl),
                Encoded.of(dataKey!!),
            )}

        override val isWebSocket: Boolean = false
    }

    class GetUserDataQuery : Type {
        override val server: String?
        @JvmField val identity: Identity
        @JvmField val serverLabel: UID
        @JvmField val retryIfNotFound: Boolean

        constructor(identity: Identity, serverLabel: UID, retryIfNotFound: Boolean) {
            this.server = identity.server
            this.identity = identity
            this.serverLabel = serverLabel
            this.retryIfNotFound = retryIfNotFound
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            // size == 2 is for legacy queries, before we had retryIfNotFound
            if (encodedParts.size != 2 && encodedParts.size != 3) {
                throw DecodingException()
            }
            this.identity = encodedParts[0].decodeIdentity()
            this.serverLabel = encodedParts[1].decodeUid()
            this.retryIfNotFound = if (encodedParts.size == 3) {
                encodedParts[2].decodeBoolean()
            } else {
                false
            }
        }

        override val id: TypeId = TypeId.GET_USER_DATA_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(identity),
                Encoded.of(serverLabel),
                Encoded.of(retryIfNotFound),
            )}

        override val isWebSocket: Boolean = false
    }

    class CheckKeycloakRevocationQuery : Type {
        override val server: String?
        @JvmField val signedContactDetails: String // this is a JWT

        constructor(keycloakServerUrl: String?, signedContactDetails: String) {
            this.server = keycloakServerUrl
            this.signedContactDetails = signedContactDetails
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 1) {
                this.signedContactDetails = encodedParts[0].decodeString()
            } else if (encodedParts.size == 2) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.signedContactDetails = encodedParts[1].decodeString()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.CHECK_KEYCLOAK_REVOCATION_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(signedContactDetails),
            )}

        override val isWebSocket: Boolean = false
    }

    class CreateGroupBlobQuery : Type {
        override val server: String?
        @JvmField val groupUid: UID
        @JvmField val encodedGroupAdminPublicKey: Encoded?
        @JvmField val encryptedBlob: EncryptedBytes

        constructor(
            groupIdentifier: GroupV2.Identifier,
            encodedGroupAdminPublicKey: Encoded?,
            encryptedBlob: EncryptedBytes
        ) {
            this.server = groupIdentifier.serverUrl
            this.groupUid = groupIdentifier.groupUid
            this.encodedGroupAdminPublicKey = encodedGroupAdminPublicKey
            this.encryptedBlob = encryptedBlob
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 3) {
                this.groupUid = encodedParts[0].decodeUid()
                this.encodedGroupAdminPublicKey = encodedParts[1]
                this.encryptedBlob = encodedParts[2].decodeEncryptedData()
            } else if (encodedParts.size == 4) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.groupUid = encodedParts[1].decodeUid()
                this.encodedGroupAdminPublicKey = encodedParts[2]
                this.encryptedBlob = encodedParts[3].decodeEncryptedData()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.CREATE_GROUP_BLOB_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(groupUid),
                encodedGroupAdminPublicKey!!,
                Encoded.of(encryptedBlob),
            )}

        override val isWebSocket: Boolean = false
    }

    class GetGroupBlobQuery : Type {
        override val server: String?
        @JvmField val groupUid: UID
        @JvmField val serverQueryNonce: ByteArray

        constructor(groupIdentifier: GroupV2.Identifier, serverQueryNonce: ByteArray) {
            this.server = groupIdentifier.serverUrl
            this.groupUid = groupIdentifier.groupUid
            this.serverQueryNonce = serverQueryNonce
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 2) {
                this.groupUid = encodedParts[0].decodeUid()
                this.serverQueryNonce = encodedParts[1].decodeBytes()
            } else if (encodedParts.size == 3) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.groupUid = encodedParts[1].decodeUid()
                this.serverQueryNonce = encodedParts[2].decodeBytes()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.GET_GROUP_BLOB_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(serverQueryNonce),
            )}

        override val isWebSocket: Boolean = false
    }

    class LockGroupBlobQuery : Type {
        override val server: String?
        @JvmField val groupUid: UID
        @JvmField val signature: ByteArray
        @JvmField val lockNonce: ByteArray

        constructor(
            groupIdentifier: GroupV2.Identifier,
            lockNonce: ByteArray,
            signature: ByteArray
        ) {
            this.server = groupIdentifier.serverUrl
            this.groupUid = groupIdentifier.groupUid
            this.signature = signature
            this.lockNonce = lockNonce
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 3) {
                this.groupUid = encodedParts[0].decodeUid()
                this.signature = encodedParts[1].decodeBytes()
                this.lockNonce = encodedParts[2].decodeBytes()
            } else if (encodedParts.size == 4) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.groupUid = encodedParts[1].decodeUid()
                this.signature = encodedParts[2].decodeBytes()
                this.lockNonce = encodedParts[3].decodeBytes()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.LOCK_GROUP_BLOB_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(signature),
                Encoded.of(lockNonce),
            )}

        override val isWebSocket: Boolean = false
    }

    class UpdateGroupBlobQuery : Type {
        override val server: String?
        @JvmField val groupUid: UID
        @JvmField val encodedGroupAdminPublicKey: Encoded?
        @JvmField val encryptedBlob: EncryptedBytes
        @JvmField val signature: ByteArray
        @JvmField val lockNonce: ByteArray

        constructor(
            groupIdentifier: GroupV2.Identifier,
            lockNonce: ByteArray,
            encryptedBlob: EncryptedBytes,
            encodedGroupAdminPublicKey: Encoded?,
            signature: ByteArray
        ) {
            this.server = groupIdentifier.serverUrl
            this.groupUid = groupIdentifier.groupUid
            this.encodedGroupAdminPublicKey = encodedGroupAdminPublicKey
            this.encryptedBlob = encryptedBlob
            this.signature = signature
            this.lockNonce = lockNonce
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 5) {
                this.groupUid = encodedParts[0].decodeUid()
                this.encodedGroupAdminPublicKey = encodedParts[1]
                this.encryptedBlob = encodedParts[2].decodeEncryptedData()
                this.signature = encodedParts[3].decodeBytes()
                this.lockNonce = encodedParts[4].decodeBytes()
            } else if (encodedParts.size == 6) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.groupUid = encodedParts[1].decodeUid()
                this.encodedGroupAdminPublicKey = encodedParts[2]
                this.encryptedBlob = encodedParts[3].decodeEncryptedData()
                this.signature = encodedParts[4].decodeBytes()
                this.lockNonce = encodedParts[5].decodeBytes()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.UPDATE_GROUP_BLOB_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(groupUid),
                encodedGroupAdminPublicKey!!,
                Encoded.of(encryptedBlob),
                Encoded.of(signature),
                Encoded.of(lockNonce),
            )}

        override val isWebSocket: Boolean = false
    }

    class PutGroupLogQuery : Type {
        override val server: String?
        @JvmField val groupUid: UID
        @JvmField val signature: ByteArray

        constructor(groupIdentifier: GroupV2.Identifier, signature: ByteArray) {
            this.server = groupIdentifier.serverUrl
            this.groupUid = groupIdentifier.groupUid
            this.signature = signature
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 2) {
                this.groupUid = encodedParts[0].decodeUid()
                this.signature = encodedParts[1].decodeBytes()
            } else if (encodedParts.size == 3) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.groupUid = encodedParts[1].decodeUid()
                this.signature = encodedParts[2].decodeBytes()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.PUT_GROUP_LOG_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(signature),
            )}

        override val isWebSocket: Boolean = false
    }

    class DeleteGroupBlobQuery : Type {
        override val server: String?
        @JvmField val groupUid: UID
        @JvmField val signature: ByteArray

        constructor(groupIdentifier: GroupV2.Identifier, signature: ByteArray) {
            this.server = groupIdentifier.serverUrl
            this.groupUid = groupIdentifier.groupUid
            this.signature = signature
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 2) {
                this.groupUid = encodedParts[0].decodeUid()
                this.signature = encodedParts[1].decodeBytes()
            } else if (encodedParts.size == 3) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.groupUid = encodedParts[1].decodeUid()
                this.signature = encodedParts[2].decodeBytes()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.DELETE_GROUP_BLOB_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(groupUid),
                Encoded.of(signature),
            )}

        override val isWebSocket: Boolean = false
    }

    class GetKeycloakDataQuery : Type {
        override val server: String?
        @JvmField val serverLabel: UID

        constructor(serverUrl: String?, serverLabel: UID) {
            this.server = serverUrl
            this.serverLabel = serverLabel
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size == 1) {
                this.serverLabel = encodedParts[0].decodeUid()
            } else if (encodedParts.size == 2) {
                // legacy encoder
                // this.server = encodedParts[0].decodeString();
                this.serverLabel = encodedParts[1].decodeUid()
            } else {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.GET_KEYCLOAK_DATA_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(serverLabel),
            )}

        override val isWebSocket: Boolean = false
    }

    class OwnedDeviceDiscoveryQuery : Type {
        override val server: String?

        constructor(ownedIdentity: Identity) {
            this.server = ownedIdentity.server
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size > 1) {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.OWNED_DEVICE_DISCOVERY_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return emptyArray()}

        override val isWebSocket: Boolean = false
    }

    class DeviceManagementSetNicknameQuery : Type {
        override val server: String?
        @JvmField val deviceUid: UID
        @JvmField val encryptedDeviceName: EncryptedBytes
        @JvmField val isCurrentDevice: Boolean

        constructor(
            ownedIdentity: Identity,
            deviceUid: UID,
            encryptedDeviceName: EncryptedBytes,
            isCurrentDevice: Boolean
        ) {
            this.server = ownedIdentity.server
            this.deviceUid = deviceUid
            this.encryptedDeviceName = encryptedDeviceName
            this.isCurrentDevice = isCurrentDevice
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size != 3) {
                throw DecodingException()
            }
            this.deviceUid = encodedParts[0].decodeUid()
            this.encryptedDeviceName = encodedParts[1].decodeEncryptedData()
            this.isCurrentDevice = encodedParts[2].decodeBoolean()
        }

        override val id: TypeId = TypeId.DEVICE_MANAGEMENT_SET_NICKNAME_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(deviceUid),
                Encoded.of(encryptedDeviceName),
                Encoded.of(isCurrentDevice),
            )}

        override val isWebSocket: Boolean = false
    }

    class DeviceManagementDeactivateDeviceQuery : Type {
        override val server: String?
        @JvmField val deviceUid: UID

        constructor(ownedIdentity: Identity, deviceUid: UID) {
            this.server = ownedIdentity.server
            this.deviceUid = deviceUid
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size != 1) {
                throw DecodingException()
            }
            this.deviceUid = encodedParts[0].decodeUid()
        }

        override val id: TypeId = TypeId.DEVICE_MANAGEMENT_DEACTIVATE_DEVICE_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(deviceUid),
            )}

        override val isWebSocket: Boolean = false
    }

    class DeviceManagementSetUnexpiringDeviceQuery : Type {
        override val server: String?
        @JvmField val deviceUid: UID

        constructor(ownedIdentity: Identity, deviceUid: UID) {
            this.server = ownedIdentity.server
            this.deviceUid = deviceUid
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size != 1) {
                throw DecodingException()
            }
            this.deviceUid = encodedParts[0].decodeUid()
        }

        override val id: TypeId = TypeId.DEVICE_MANAGEMENT_SET_UNEXPIRING_DEVICE_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(deviceUid),
            )}

        override val isWebSocket: Boolean = false
    }

    class RegisterApiKeyQuery : Type {
        override val server: String?
        @JvmField val apiKeyString: String
        @JvmField val serverSessionToken: ByteArray

        constructor(ownedIdentity: Identity, serverSessionToken: ByteArray, apiKeyString: String) {
            this.server = ownedIdentity.server
            this.apiKeyString = apiKeyString
            this.serverSessionToken = serverSessionToken
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size != 2) {
                throw DecodingException()
            }
            this.apiKeyString = encodedParts[0].decodeString()
            this.serverSessionToken = encodedParts[1].decodeBytes()
        }

        override val id: TypeId = TypeId.REGISTER_API_KEY_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(apiKeyString),
                Encoded.of(serverSessionToken),
            )}

        override val isWebSocket: Boolean = false
    }

    class UploadPreKeyQuery : Type {
        override val server: String?

        @JvmField val deviceUid: UID
        @JvmField val preKeyBytes: ByteArray

        constructor(ownedIdentity: Identity, deviceUid: UID, preKeyBytes: ByteArray) {
            this.server = ownedIdentity.server
            this.deviceUid = deviceUid
            this.preKeyBytes = preKeyBytes
        }

        constructor(server: String?, encodedParts: Array<Encoded>) {
            this.server = server
            if (encodedParts.size != 2) {
                throw DecodingException()
            }
            this.deviceUid = encodedParts[0].decodeUid()
            this.preKeyBytes = encodedParts[1].decodeBytes()
        }

        override val id: TypeId = TypeId.UPLOAD_PRE_KEY_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            return arrayOf(
                Encoded.of(deviceUid),
                Encoded.of(preKeyBytes),
            )}

        override val isWebSocket: Boolean = false
    }

    // region transfers
    class TransferSourceQuery : Type {
        constructor()

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 0) {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.TRANSFER_SOURCE_QUERY_ID
        override val server: String = ""

        override val encodedParts: Array<Encoded> get() {
            return emptyArray()}

        override val isWebSocket: Boolean = true
    }

    class TransferTargetQuery : Type {
        @JvmField val sessionNumber: Long
        @JvmField val payload: ByteArray

        constructor(sessionNumber: Long, payload: ByteArray) {
            this.sessionNumber = sessionNumber
            this.payload = payload
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 2) {
                throw DecodingException()
            }
            this.sessionNumber = encodedParts[0].decodeLong()
            this.payload = encodedParts[1].decodeBytes()
        }

        override val id: TypeId = TypeId.TRANSFER_TARGET_QUERY_ID
        override val server: String = ""

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(sessionNumber),
                Encoded.of(payload),
            )}

        override val isWebSocket: Boolean = true
    }

    class TransferRelayQuery : Type {
        @JvmField val connectionIdentifier: String
        @JvmField val payload: ByteArray
        @JvmField val noResponseExpected: Boolean

        constructor(connectionIdentifier: String, payload: ByteArray, noResponseExpected: Boolean) {
            this.connectionIdentifier = connectionIdentifier
            this.payload = payload
            this.noResponseExpected = noResponseExpected
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 3) {
                throw DecodingException()
            }
            this.connectionIdentifier = encodedParts[0].decodeString()
            this.payload = encodedParts[1].decodeBytes()
            this.noResponseExpected = encodedParts[2].decodeBoolean()
        }

        override val id: TypeId = TypeId.TRANSFER_RELAY_QUERY_ID
        override val server: String = ""

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(connectionIdentifier),
                Encoded.of(payload),
                Encoded.of(noResponseExpected),
            )}

        override val isWebSocket: Boolean = true
    }

    class TransferWaitQuery : Type {
        constructor()

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 0) {
                throw DecodingException()
            }
        }

        override val id: TypeId = TypeId.TRANSFER_WAIT_QUERY_ID
        override val server: String = ""

        override val encodedParts: Array<Encoded> get() {
            return emptyArray()}

        override val isWebSocket: Boolean = true
    }

    class TransferCloseQuery : Type {
        @JvmField val abort: Boolean

        constructor(abort: Boolean) {
            this.abort = abort
        }

        constructor(encodedParts: Array<Encoded>) {
            if (encodedParts.size != 1) {
                throw DecodingException()
            }
            this.abort = encodedParts[0].decodeBoolean()
        }

        override val id: TypeId = TypeId.TRANSFER_CLOSE_QUERY_ID
        override val server: String = ""

        override val encodedParts: Array<Encoded> get() {
            return arrayOf<Encoded>(
                Encoded.of(abort),
            )}

        override val isWebSocket: Boolean = true
    }

    // endregion
    // region backups v2
    class BackupsV2CreateBackupQuery(
        override val server: String?,
        @JvmField val backupUid: UID?,
        @JvmField val serverAuthenticationPublicKey: ServerAuthenticationPublicKey?
    ) : Type() {
        override val id: TypeId = TypeId.BACKUPS_V2_CREATE_BACKUP_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            throw RuntimeException("BackupsV2 server queries cannot be encoded.")}

        override val isWebSocket: Boolean = false
        fun getBackupUid(): UID? = backupUid
    }

    class BackupsV2UploadBackupQuery(
        override val server: String?,
        @JvmField val backupUid: UID?,
        @JvmField val threadId: UID?,
        @JvmField val version: Long,
        @JvmField val encryptedBackup: EncryptedBytes?,
        @JvmField val signature: ByteArray?
    ) : Type() {
        override val id: TypeId = TypeId.BACKUPS_V2_UPLOAD_BACKUP_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            throw RuntimeException("BackupsV2 server queries cannot be encoded.")}

        override val isWebSocket: Boolean = false
        fun getBackupUid(): UID? = backupUid
        fun getThreadId(): UID? = threadId
        fun getVersion(): Long = version
        fun getEncryptedBackup(): EncryptedBytes? = encryptedBackup
    }

    class BackupsV2DeleteBackupQuery(
        override val server: String?,
        @JvmField val backupUid: UID?,
        @JvmField val threadId: UID?,
        @JvmField val version: Long,
        @JvmField val signature: ByteArray?
    ) : Type() {
        override val id: TypeId = TypeId.BACKUPS_V2_DELETE_BACKUP_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            throw RuntimeException("BackupsV2 server queries cannot be encoded.")}

        override val isWebSocket: Boolean = false
        fun getBackupUid(): UID? = backupUid
        fun getThreadId(): UID? = threadId
        fun getVersion(): Long = version
    }

    class BackupsV2ListBackupsQuery(override val server: String?, @JvmField val backupUid: UID?) : Type() {
        override val id: TypeId = TypeId.BACKUPS_V2_LIST_BACKUPS_QUERY_ID

        override val encodedParts: Array<Encoded> get() {
            throw RuntimeException("BackupsV2 server queries cannot be encoded.")}

        override val isWebSocket: Boolean = false
        fun getBackupUid(): UID? = backupUid
    }

    class BackupsV2DownloadProfilePictureQuery(
        @JvmField val identity: Identity,
        @JvmField val photoLabel: UID?,
        @JvmField val photoKey: AuthEncKey?
    ) : Type() {
        override val id: TypeId = TypeId.BACKUPS_V2_DOWNLOAD_PROFILE_PICTURE_QUERY_ID
        override val server: String get() = identity.server

        override val encodedParts: Array<Encoded> get() {
            throw RuntimeException("BackupsV2 server queries cannot be encoded.")}

        override val isWebSocket: Boolean = false
        fun getIdentity(): Identity = identity
        fun getPhotoLabel(): UID? = photoLabel
    }

    class KeycloakIdBasedAuthRequestChallengeQuery(
        @JvmField val keycloakServerUrl: String?,
        @JvmField val keycloakUserId: String?,
        @JvmField val nonce: ByteArray?
    ) : Type() {
        override val id: TypeId = TypeId.KEYCLOAK_ID_BASED_AUTH_REQUEST_CHALLENGE
        override val server: String? get() = keycloakServerUrl

        override val encodedParts: Array<Encoded> get() {
            throw RuntimeException("KeycloakIdBasedAuth server queries cannot be encoded.")}

        override val isWebSocket: Boolean = false
        fun getKeycloakServerUrl(): String? = keycloakServerUrl
        fun getKeycloakUserId(): String? = keycloakUserId
    }

    class KeycloakIdBasedAuthGetSessionQuery(
        @JvmField val keycloakServerUrl: String?,
        @JvmField val challengeResponse: ByteArray?,
        @JvmField val nonce: ByteArray?
    ) : Type() {
        override val id: TypeId = TypeId.KEYCLOAK_ID_BASED_AUTH_GET_SESSION
        override val server: String? get() = keycloakServerUrl

        override val encodedParts: Array<Encoded> get() {
            throw RuntimeException("KeycloakIdBasedAuth server queries cannot be encoded.")}

        override val isWebSocket: Boolean = false
    } // endregion

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encoded: Encoded): ServerQuery {
            val list: Array<Encoded> = encoded.decodeList()
            if (list.size != 3) {
                throw DecodingException()
            }
            return ServerQuery(
                list[0],
                list[1].decodeIdentity(),
                Type.of(list[2])
            )
        }
    }
    fun getEncodedElements(): Encoded? = encodedElements
    fun getOwnedIdentity(): Identity? = ownedIdentity
    fun getType(): Type = type
}
