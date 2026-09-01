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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Hash
import io.olvid.engine.crypto.KDF
import io.olvid.engine.crypto.PRNGService
import io.olvid.engine.crypto.Signature
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPrivateKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.metamanager.IdentityDelegate
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.util.Arrays

object GroupV2 {
    @JvmStatic
    fun getSharedBlobSecretKey(blobMainSeed: Seed, blobVersionSeed: Seed?): AuthEncKey? {
        return Suite.getKDF(KDF.KDF_SHA256).gen(
            Seed(blobMainSeed, blobVersionSeed!!),
            Suite.getDefaultAuthEnc(0).getKDFDelegate()
        )[0] as AuthEncKey?
    }


    enum class Permission {
        GROUP_ADMIN,  // allows changing members and their permissions
        REMOTE_DELETE_ANYTHING,  // allows to remote-delete any message or the whole discussion
        EDIT_OR_REMOTE_DELETE_OWN_MESSAGES,  // allows to edit your messages and remote delete them
        CHANGE_SETTINGS,
        SEND_MESSAGE;

        val string: String
            get() {
                when (this) {
                    Permission.GROUP_ADMIN -> return "ga"
                    Permission.REMOTE_DELETE_ANYTHING -> return "rd"
                    Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES -> return "eo"
                    Permission.CHANGE_SETTINGS -> return "cs"
                    Permission.SEND_MESSAGE -> return "sm"
                }
                return ""
            }

        companion object {
            @JvmField
            val DEFAULT_MEMBER_PERMISSIONS: Array<Permission?> = arrayOf<Permission?>(
                Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES,
                Permission.SEND_MESSAGE
            )
            @JvmField
            val DEFAULT_ADMIN_PERMISSIONS: Array<Permission?> = arrayOf<Permission?>(
                Permission.GROUP_ADMIN,
                Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES,
                Permission.CHANGE_SETTINGS,
                Permission.SEND_MESSAGE
            )

            private val valueMap: MutableMap<String?, Permission?> = HashMap<String?, Permission?>()

            init {
                valueMap.put("ga", Permission.GROUP_ADMIN)
                valueMap.put("rd", Permission.REMOTE_DELETE_ANYTHING)
                valueMap.put("eo", Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES)
                valueMap.put("cs", Permission.CHANGE_SETTINGS)
                valueMap.put("sm", Permission.SEND_MESSAGE)
            }

            @JvmStatic
            fun fromString(value: String?): Permission? {
                return valueMap.get(value)
            }

            @JvmStatic
            fun fromStrings(permissionStrings: MutableCollection<String?>): java.util.HashSet<Permission> {
                val res = java.util.HashSet<Permission>()
                for (permissionString in permissionStrings) {
                    val perm: Permission? = fromString(permissionString)
                    if (perm != null) {
                        res.add(perm)
                    }
                }
                return res
            }


            @JvmStatic
            fun deserializePermissions(serializedPermissions: ByteArray): MutableList<String?> {
                val permissionStrings: MutableList<String?> = ArrayList<String?>()
                var startPos = 0
                for (i in serializedPermissions.indices) {
                    if (serializedPermissions[i].toInt() == 0x00) {
                        permissionStrings.add(
                            String(
                                Arrays.copyOfRange(
                                    serializedPermissions,
                                    startPos,
                                    i
                                ), StandardCharsets.UTF_8
                            )
                        )
                        startPos = i + 1
                    }
                }
                if (startPos != serializedPermissions.size) {
                    permissionStrings.add(
                        String(
                            Arrays.copyOfRange(
                                serializedPermissions,
                                startPos,
                                serializedPermissions.size
                            ), StandardCharsets.UTF_8
                        )
                    )
                }
                return permissionStrings
            }

            @JvmStatic
            fun deserializeKnownPermissions(serializedPermissions: ByteArray): java.util.HashSet<Permission> {
                val permissionStrings: MutableList<String?> =
                    deserializePermissions(serializedPermissions)
                val permissions = java.util.HashSet<Permission>()
                for (permissionString in permissionStrings) {
                    val permission: Permission? = fromString(permissionString)
                    if (permission != null) {
                        permissions.add(permission)
                    }
                }
                return permissions
            }

            @JvmStatic
            fun serializePermissionStrings(permissionStrings: MutableCollection<String>): ByteArray? {
                if (permissionStrings.size == 0) {
                    return ByteArray(0)
                } else {
                    try {
                        ByteArrayOutputStream().use { baos ->
                            for (permissionString in permissionStrings) {
                                if (baos.size() > 0) {
                                    baos.write(byteArrayOf(0))
                                }
                                baos.write(permissionString.toByteArray(StandardCharsets.UTF_8))
                            }
                            return baos.toByteArray()
                        }
                    } catch (_: IOException) {
                        return null
                    }
                }
            }

            @JvmStatic
            fun serializePermissions(permissions: Collection<Permission?>): ByteArray? {
                if (permissions.size == 0) {
                    return ByteArray(0)
                } else {
                    try {
                        ByteArrayOutputStream().use { baos ->
                            for (permission in permissions) {
                                if (permission == null) continue
                                if (baos.size() > 0) {
                                    baos.write(byteArrayOf(0))
                                }
                                baos.write(permission.string.toByteArray(StandardCharsets.UTF_8))
                            }
                            return baos.toByteArray()
                        }
                    } catch (_: IOException) {
                        return null
                    }
                }
            }
        }
    }

    class Identifier(@JvmField val groupUid: UID, @JvmField val serverUrl: String, @JvmField val category: Int) {
        val bytes: ByteArray
            get() = encode().bytes

        fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(groupUid),
                    Encoded.of(serverUrl),
                    Encoded.of(category.toLong()),
                )
            )
        }

        fun computeProtocolInstanceUid(): UID {
            val prngSeed = Seed(this.bytes)
            val seededPRNG = Suite.getDefaultPRNG(0, prngSeed)
            return UID(seededPRNG)
        }

        override fun equals(other: Any?): Boolean {
            val o = (other as? Identifier) ?: return false
            return category == o.category && serverUrl == o.serverUrl && groupUid == o.groupUid
        }

        override fun hashCode(): Int {
            return serverUrl.hashCode() + 31 * groupUid.hashCode() + category
        }

        companion object {
            const val CATEGORY_SERVER: Int = 0
            const val CATEGORY_KEYCLOAK: Int = 1

            @JvmStatic
            @Throws(DecodingException::class)
            fun of(bytesGroupIdentifier: ByteArray): Identifier {
                return of(Encoded(bytesGroupIdentifier))
            }

            @Throws(DecodingException::class)
            @JvmStatic
            fun of(encoded: Encoded): Identifier {
                val encodeds = encoded.decodeList()
                if (encodeds.size != 3) {
                    throw DecodingException()
                }
                return when (encodeds[2].decodeLong().toInt()) {
                    CATEGORY_SERVER -> Identifier(
                        encodeds[0].decodeUid(),
                        encodeds[1].decodeString(),
                        CATEGORY_SERVER
                    )

                    CATEGORY_KEYCLOAK -> Identifier(
                        encodeds[0].decodeUid(),
                        encodeds[1].decodeString(),
                        CATEGORY_KEYCLOAK
                    )

                    else -> throw DecodingException()
                }
            }
        }
        fun getGroupUid(): UID = groupUid
        fun getServerUrl(): String = serverUrl
        fun getCategory(): Int = category
    }


    class AdministratorsChain // no longer used, but could be useful one day!
    //        public boolean isChainCreatedBy(Identity identity) {
    //            return blocks.length > 0 && blocks[0].isSignatureValid(new Identity[]{identity});
    //        }
    private constructor(
        @JvmField val groupUid: UID,
        @JvmField val blocks: Array<Block?>,
        @JvmField var integrityWasChecked: Boolean
    ) {
        @Throws(Exception::class)
        fun withCheckedIntegrity(
            expectedGroupUid: UID?,
            latestUpdateAdministratorIdentity: Identity?,
            alreadyTrustedPrefixAdministratorChain: AdministratorsChain?
        ): AdministratorsChain {
            if (latestUpdateAdministratorIdentity != null) {
                // first check the administrator is indeed part of the last block list of admins
                var found = false
                for (identity in blocks[blocks.size - 1]!!.innerData.administratorIdentities) {
                    if (identity.equals(latestUpdateAdministratorIdentity)) {
                        found = true
                        break
                    }
                }

                if (!found) {
                    throw Exception("Administrator is not a valid administrator for this chain")
                }
            }

            if (expectedGroupUid != groupUid) {
                throw Exception("GroupUid of chain does not match expected groupUid")
            }

            if (integrityWasChecked) {
                return this
            }

            if (alreadyTrustedPrefixAdministratorChain != null && alreadyTrustedPrefixAdministratorChain.blocks.size > 0) {
                // check the prefix is indeed a prefix
                if (!isPrefixedBy(alreadyTrustedPrefixAdministratorChain)) {
                    throw Exception("Trusted prefix is not a prefix")
                }

                // check the new blocks
                for (i in alreadyTrustedPrefixAdministratorChain.blocks.size..<blocks.size) {
                    if (!blocks[i]!!.innerData.previousBlockHash.contentEquals(blocks[i - 1]!!.computeSha256())) {
                        throw Exception("Invalid block hash chaining at block " + i)
                    }
                    if (!blocks[i]!!.isSignatureValid(
                            blocks[i - 1]!!.innerData.administratorIdentities,
                            blocks[i]!!.innerData.administratorIdentities[0]
                        )
                    ) {
                        throw Exception("Invalid block signature at block " + i)
                    }
                }
            } else {
                // verify the groupUID
                if (!groupUid.equals(UID(blocks[0]!!.computeSha256()))) {
                    throw Exception("Invalid groupUid")
                }

                // check the first block's signature
                if (!blocks[0]!!.isSignatureValid(
                        blocks[0]!!.innerData.administratorIdentities,
                        blocks[0]!!.innerData.administratorIdentities[0]
                    )
                ) {
                    throw Exception("Invalid block signature at block 0")
                }

                // check following blocks
                for (i in 1..<blocks.size) {
                    if (!blocks[i]!!.innerData.previousBlockHash.contentEquals(blocks[i - 1]!!.computeSha256())) {
                        throw Exception("Invalid block hash chaining at block " + i)
                    }
                    if (!blocks[i]!!.isSignatureValid(
                            blocks[i - 1]!!.innerData.administratorIdentities,
                            blocks[i]!!.innerData.administratorIdentities[0]
                        )
                    ) {
                        throw Exception("Invalid block signature at block " + i)
                    }
                }
            }

            integrityWasChecked = true
            return this
        }

        fun isPrefixedBy(prefix: AdministratorsChain): Boolean {
            if (prefix.groupUid != groupUid) {
                return false
            }
            if (prefix.blocks.size > blocks.size) {
                return false
            }
            for (i in prefix.blocks.indices) {
                if (blocks[i]!!.encodedInnerData != prefix.blocks[i]!!.encodedInnerData) {
                    return false
                }
            }
            return true
        }

        fun encode(): Encoded {
            val encodeds = Array(blocks.size) { i -> blocks[i]!!.encode() }
            return Encoded.of(encodeds)
        }

        val adminIdentities: HashSet<Identity?>
            get() {
                if (blocks.size == 0) {
                    return java.util.HashSet<Identity?>()
                }
                return java.util.HashSet<Identity?>(
                    Arrays.asList<Identity?>(
                        *blocks[blocks.size - 1]!!.innerData.administratorIdentities
                    )
                )
            }

        @Throws(Exception::class)
        fun buildNewChainByAppendingABlock(
            session: Session,
            identityDelegate: IdentityDelegate,
            ownedIdentity: Identity?,
            otherAdministratorIdentities: Array<Identity?>,
            prng: PRNGService?
        ): AdministratorsChain? {
            if (blocks.size == 0) {
                return null
            }
            if (!Arrays.asList<Identity?>(*blocks[blocks.size - 1]!!.innerData.administratorIdentities)
                    .contains(ownedIdentity)
            ) {
                Logger.e("Trying to append block to AdministratorsChain using an identity not in the last block!")
                throw Exception()
            }
            val newBlocks = arrayOfNulls<Block>(blocks.size + 1)
            System.arraycopy(blocks, 0, newBlocks, 0, blocks.size)
            newBlocks[newBlocks.size - 1] = AdministratorsChain.Block(
                session,
                identityDelegate,
                blocks[blocks.size - 1]!!,
                ownedIdentity,
                otherAdministratorIdentities,
                prng
            )
            return AdministratorsChain(
                groupUid,
                newBlocks,
                true
            )
        }

        class Block {
            val encodedInnerData: Encoded
            val innerData: InnerData
            val signature: ByteArray?

            internal constructor(
                session: Session,
                identityDelegate: IdentityDelegate,
                ownedIdentity: Identity?,
                otherAdministratorIdentities: Array<Identity?>,
                prng: PRNGService
            ) {
                this.innerData = InnerData(ownedIdentity, otherAdministratorIdentities, prng)
                this.encodedInnerData = innerData.encode()
                this.signature = identityDelegate.signBlock(
                    session,
                    Constants.SignatureContext.GROUP_ADMINISTRATORS_CHAIN,
                    encodedInnerData.bytes,
                    ownedIdentity,
                    prng
                )
            }

            internal constructor(
                session: Session,
                identityDelegate: IdentityDelegate,
                previousBlock: Block,
                ownedIdentity: Identity?,
                otherAdministratorIdentities: Array<Identity?>,
                prng: PRNGService?
            ) {
                val previousBlockHash = previousBlock.computeSha256()
                val administratorIdentities: Array<Identity> = Array(otherAdministratorIdentities.size + 1) { i ->
                    if (i == 0) ownedIdentity!! else otherAdministratorIdentities[i - 1]!!
                }
                this.innerData = InnerData(previousBlockHash, administratorIdentities)
                this.encodedInnerData = innerData.encode()
                this.signature = identityDelegate.signBlock(
                    session,
                    Constants.SignatureContext.GROUP_ADMINISTRATORS_CHAIN,
                    encodedInnerData.bytes,
                    ownedIdentity,
                    prng
                )
            }

            internal constructor(
                encodedInnerData: Encoded,
                innerData: InnerData,
                signature: ByteArray?
            ) {
                this.encodedInnerData = encodedInnerData
                this.innerData = innerData
                this.signature = signature
            }

            fun encode(): Encoded {
                return Encoded.of(
                    arrayOf<Encoded>(
                        encodedInnerData,
                        Encoded.of(signature!!),
                    )
                )
            }

            fun computeSha256(): ByteArray {
                return Suite.getHash(Hash.SHA256).digest(encode().bytes)
            }

            fun isSignatureValid(
                previousBlockAdministratorIdentities: Array<Identity>,
                probableSignerIdentity: Identity?
            ): Boolean {
                // first check the signature from the probableSignerIdentity
                for (administratorIdentity in previousBlockAdministratorIdentities) {
                    if (administratorIdentity.equals(probableSignerIdentity)) {
                        try {
                            if (Signature.verify(
                                    Constants.SignatureContext.GROUP_ADMINISTRATORS_CHAIN,
                                    encodedInnerData.bytes,
                                    administratorIdentity,
                                    signature!!
                                )
                            ) {
                                return true
                            }
                        } catch (_: Exception) {
                        }
                        break
                    }
                }
                // if first check failed, try all other admins
                for (administratorIdentity in previousBlockAdministratorIdentities) {
                    try {
                        if (!administratorIdentity.equals(probableSignerIdentity)) {
                            if (Signature.verify(
                                    Constants.SignatureContext.GROUP_ADMINISTRATORS_CHAIN,
                                    encodedInnerData.bytes,
                                    administratorIdentity,
                                    signature!!
                                )
                            ) {
                                return true
                            }
                        }
                    } catch (_: Exception) {
                    }
                }
                return false
            }

            class InnerData {
                val previousBlockHash: ByteArray
                val administratorIdentities: Array<Identity>

                internal constructor(
                    previousBlockHash: ByteArray,
                    administratorIdentities: Array<Identity>
                ) {
                    this.previousBlockHash = previousBlockHash
                    this.administratorIdentities = administratorIdentities
                }

                // create the first block InnerData, with no chaining
                internal constructor(
                    ownedIdentity: Identity?,
                    otherAdministratorIdentities: Array<Identity?>,
                    prng: PRNGService
                ) {
                    this.previousBlockHash = prng.bytes(Suite.getHash(Hash.SHA256).outputLength())
                    this.administratorIdentities = Array(otherAdministratorIdentities.size + 1) { i ->
                        if (i == 0) ownedIdentity!! else otherAdministratorIdentities[i - 1]!!
                    }
                }

                fun encode(): Encoded {
                    return Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(previousBlockHash),
                            Encoded.of(administratorIdentities),
                        )
                    )
                }

                companion object {
                    @JvmStatic
                    @Throws(DecodingException::class)
                    fun of(encoded: Encoded): InnerData {
                        val encodeds = encoded.decodeList()
                        if (encodeds.size != 2) {
                            throw DecodingException()
                        }
                        return InnerData(
                            encodeds[0].decodeBytes(),
                            encodeds[1].decodeIdentityArray()
                        )
                    }
                }
            }

            companion object {
                @JvmStatic
                @Throws(DecodingException::class)
                fun of(encoded: Encoded): Block {
                    val encodeds = encoded.decodeList()
                    if (encodeds.size != 2) {
                        throw DecodingException()
                    }
                    return Block(
                        encodeds[0],
                        InnerData.of(encodeds[0]),
                        encodeds[1].decodeBytes()
                    )
                }
            }
        }

        companion object {
            @Throws(Exception::class)
            @JvmStatic
            fun startNewChain(
                session: Session,
                identityDelegate: IdentityDelegate,
                ownedIdentity: Identity?,
                otherAdministratorIdentities: Array<Identity?>,
                prng: PRNGService
            ): AdministratorsChain {
                val firstBlock = AdministratorsChain.Block(
                    session,
                    identityDelegate,
                    ownedIdentity,
                    otherAdministratorIdentities,
                    prng
                )
                return AdministratorsChain(
                    UID(firstBlock.computeSha256()),
                    arrayOf<Block?>(firstBlock),
                    true
                )
            }

            @Throws(DecodingException::class)
            @JvmStatic
            fun of(encoded: Encoded): AdministratorsChain {
                val encodeds = encoded.decodeList()
                if (encodeds.size == 0) {
                    throw DecodingException()
                }
                val blocks = arrayOfNulls<Block>(encodeds.size)
                for (i in blocks.indices) {
                    blocks[i] = Block.of(encodeds[i])
                }
                return AdministratorsChain(UID(blocks[0]!!.computeSha256()), blocks, false)
            }
        }
    }

    class ServerBlob(
        @JvmField val administratorsChain: AdministratorsChain,
        @JvmField val groupMemberIdentityAndPermissionsAndDetailsList: java.util.HashSet<IdentityAndPermissionsAndDetails>,
        @JvmField val version: Int,
        @JvmField val serializedGroupDetails: String, // null if the group does not have a photo
        @JvmField val serverPhotoInfo: ServerPhotoInfo?,
        @JvmField val serializedGroupType: String?
    ) {
        fun encode(): Encoded {
            val map = HashMap<DictionaryKey, Encoded>()
            map.put(DictionaryKey(KEY_ADMINISTRATORS_CHAIN), administratorsChain.encode())
            val encodedGroupMembers: Array<Encoded> = groupMemberIdentityAndPermissionsAndDetailsList
                .map { it.encode() }
                .toTypedArray()
            map.put(
                DictionaryKey(KEY_GROUP_MEMBER_IDENTITY_AND_PERMISSIONS_AND_DETAILS_LIST),
                Encoded.of(encodedGroupMembers)
            )
            map.put(DictionaryKey(KEY_VERSION), Encoded.of(version.toLong()))
            map.put(DictionaryKey(KEY_SERIALIZED_GROUP_DETAILS), Encoded.of(serializedGroupDetails))
            if (serverPhotoInfo != null) {
                map.put(DictionaryKey(KEY_SERVER_PHOTO_INFO), serverPhotoInfo.encode())
            }
            if (serializedGroupType != null) {
                map.put(DictionaryKey(KEY_SERIALIZED_GROUP_TYPE), Encoded.of(serializedGroupType))
            }
            return Encoded.of(map)
        }

        fun consolidateWithLogEntries(
            groupIdentifier: Identifier,
            logEntries: MutableList<ByteArray?>
        ): MutableList<Identity?> {
            val leavers = java.util.HashSet<IdentityAndPermissionsAndDetails?>()
            val out: MutableList<Identity?> = ArrayList<Identity?>()
            for (logEntry in logEntries) {
                for (groupMember in groupMemberIdentityAndPermissionsAndDetailsList) {
                    try {
                        if (Signature.verify(
                                Constants.SignatureContext.GROUP_LEAVE_NONCE,
                                groupIdentifier,
                                groupMember.groupInvitationNonce,
                                null,
                                groupMember.identity,
                                logEntry!!
                            )
                        ) {
                            leavers.add(groupMember)
                            out.add(groupMember.identity)
                            break
                        }
                    } catch (_: Exception) {
                    }
                }
            }

            groupMemberIdentityAndPermissionsAndDetailsList.removeAll(leavers)
            return out
        }

        companion object {
            const val KEY_ADMINISTRATORS_CHAIN: String = "ac"
            const val KEY_GROUP_MEMBER_IDENTITY_AND_PERMISSIONS_AND_DETAILS_LIST: String = "mem"
            const val KEY_VERSION: String = "v"
            const val KEY_SERIALIZED_GROUP_DETAILS: String = "det"
            const val KEY_SERVER_PHOTO_INFO: String = "ph"
            const val KEY_SERIALIZED_GROUP_TYPE: String = "t"

            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): ServerBlob {
                val map: HashMap<DictionaryKey, Encoded> = encoded.decodeDictionary()
                var value: Encoded?
                value = map.get(DictionaryKey(KEY_ADMINISTRATORS_CHAIN))
                if (value == null) {
                    throw DecodingException()
                }
                val administratorsChain = AdministratorsChain.of(value)

                value = map.get(
                    DictionaryKey(
                        KEY_GROUP_MEMBER_IDENTITY_AND_PERMISSIONS_AND_DETAILS_LIST
                    )
                )
                if (value == null) {
                    throw DecodingException()
                }
                val encodedGroupMembers = value.decodeList()
                val groupMemberIdentityAndPermissionsAndDetailsList =
                    java.util.HashSet<IdentityAndPermissionsAndDetails>()
                for (encodedGroupMember in encodedGroupMembers) {
                    groupMemberIdentityAndPermissionsAndDetailsList.add(
                        IdentityAndPermissionsAndDetails.of(encodedGroupMember)
                    )
                }

                value = map.get(DictionaryKey(KEY_VERSION))
                if (value == null) {
                    throw DecodingException()
                }
                val version = value.decodeLong().toInt()

                value = map.get(DictionaryKey(KEY_SERIALIZED_GROUP_DETAILS))
                if (value == null) {
                    throw DecodingException()
                }
                val serializedGroupDetails = value.decodeString()

                value = map.get(DictionaryKey(KEY_SERVER_PHOTO_INFO))
                val serverPhotoInfo =
                    if (value == null) null else ServerPhotoInfo.of(value)

                value = map.get(DictionaryKey(KEY_SERIALIZED_GROUP_TYPE))
                val serializedGroupType = if (value == null) null else value.decodeString()

                return ServerBlob(
                    administratorsChain,
                    groupMemberIdentityAndPermissionsAndDetailsList,
                    version,
                    serializedGroupDetails,
                    serverPhotoInfo,
                    serializedGroupType
                )
            }
        }
        fun getAdministratorsChain(): AdministratorsChain = administratorsChain
        fun getGroupMemberIdentityAndPermissionsAndDetailsList(): java.util.HashSet<IdentityAndPermissionsAndDetails> = groupMemberIdentityAndPermissionsAndDetailsList
        fun getVersion(): Int = version
        fun getServerPhotoInfo(): ServerPhotoInfo? = serverPhotoInfo
    }

    class ServerPhotoInfo(// null for keycloak group photo info
        @JvmField val serverPhotoIdentity: Identity?,
        @JvmField val serverPhotoLabel: UID,
        @JvmField val serverPhotoKey: AuthEncKey
    ) {
        fun encode(): Encoded {
            if (serverPhotoIdentity == null) {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(serverPhotoLabel),
                        Encoded.of(serverPhotoKey),
                    )
                )
            } else {
                return Encoded.of(
                    arrayOf<Encoded>(
                        Encoded.of(serverPhotoIdentity),
                        Encoded.of(serverPhotoLabel),
                        Encoded.of(serverPhotoKey),
                    )
                )
            }
        }

        override fun equals(other: Any?): Boolean {
            val o = (other as? ServerPhotoInfo) ?: return false
            return serverPhotoIdentity == o.serverPhotoIdentity && serverPhotoLabel == o.serverPhotoLabel && serverPhotoKey == o.serverPhotoKey
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): ServerPhotoInfo {
                val encodeds = encoded.decodeList()
                if (encodeds.size == 2) {
                    return ServerPhotoInfo(
                        null,
                        encodeds[0].decodeUid(),
                        (encodeds[1].decodeSymmetricKey() as AuthEncKey?)!!
                    )
                } else if (encodeds.size == 3) {
                    return ServerPhotoInfo(
                        encodeds[0].decodeIdentity(),
                        encodeds[1].decodeUid(),
                        (encodeds[2].decodeSymmetricKey() as AuthEncKey?)!!
                    )
                }
                throw DecodingException()
            }
        }
        fun getServerPhotoIdentity(): Identity? = serverPhotoIdentity
        fun getServerPhotoLabel(): UID = serverPhotoLabel
    }

    class BlobKeys(// may be null when sent through an asymmetric channel
        @JvmField val blobMainSeed: Seed?, // not null
        @JvmField val blobVersionSeed: Seed?, // may be null when you are not admin/they are not the admin
        @JvmField val groupAdminServerAuthenticationPrivateKey: ServerAuthenticationPrivateKey?
    ) {
        fun encode(): Encoded {
            val map = HashMap<DictionaryKey, Encoded>()
            if (blobMainSeed != null) {
                map.put(DictionaryKey(KEY_MAIN_SEED), Encoded.of(blobMainSeed))
            }
            map.put(DictionaryKey(KEY_VERSION_SEED), Encoded.of(blobVersionSeed!!))
            if (groupAdminServerAuthenticationPrivateKey != null) {
                map.put(
                    DictionaryKey(KEY_GROUP_ADMIN_PRIVATE_KEY),
                    Encoded.of(groupAdminServerAuthenticationPrivateKey)
                )
            }
            return Encoded.of(map)
        }

        companion object {
            const val KEY_MAIN_SEED: String = "ms"
            const val KEY_VERSION_SEED: String = "vs"
            const val KEY_GROUP_ADMIN_PRIVATE_KEY: String = "ga"


            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): BlobKeys {
                val map: HashMap<DictionaryKey, Encoded> = encoded.decodeDictionary()
                var value: Encoded?
                value = map.get(DictionaryKey(KEY_MAIN_SEED))
                val blobMainSeed = if (value == null) null else value.decodeSeed()

                value = map.get(DictionaryKey(KEY_VERSION_SEED))
                if (value == null) {
                    throw DecodingException()
                }
                val blobVersionSeed = value.decodeSeed()

                value = map.get(DictionaryKey(KEY_GROUP_ADMIN_PRIVATE_KEY))
                val groupAdminServerAuthenticationPrivateKey =
                    if (value == null) null else value.decodePrivateKey() as ServerAuthenticationPrivateKey?

                return BlobKeys(
                    blobMainSeed,
                    blobVersionSeed,
                    groupAdminServerAuthenticationPrivateKey
                )
            }
        }
        fun getGroupAdminServerAuthenticationPrivateKey(): ServerAuthenticationPrivateKey? = groupAdminServerAuthenticationPrivateKey
    }

    class InvitationCollectedData {
        @JvmField val inviterIdentityAndBlobMainSeedCandidates: HashMap<Identity?, Seed?> // non null
        @JvmField val blobVersionSeedCandidates: java.util.HashSet<Seed> // non null
        @JvmField val groupAdminServerAuthenticationPrivateKeyCandidates: java.util.HashSet<ServerAuthenticationPrivateKey> // non null

        constructor(
            inviterIdentityAndBlobMainSeedCandidates: HashMap<Identity?, Seed?>,
            blobVersionSeedCandidates: java.util.HashSet<Seed>,
            groupAdminServerAuthenticationPrivateKeyCandidates: java.util.HashSet<ServerAuthenticationPrivateKey>
        ) {
            this.inviterIdentityAndBlobMainSeedCandidates = inviterIdentityAndBlobMainSeedCandidates
            this.blobVersionSeedCandidates = blobVersionSeedCandidates
            this.groupAdminServerAuthenticationPrivateKeyCandidates =
                groupAdminServerAuthenticationPrivateKeyCandidates
        }

        constructor() {
            this.inviterIdentityAndBlobMainSeedCandidates = HashMap<Identity?, Seed?>()
            this.blobVersionSeedCandidates = java.util.HashSet<Seed>()
            this.groupAdminServerAuthenticationPrivateKeyCandidates =
                java.util.HashSet<ServerAuthenticationPrivateKey>()
        }

        fun encode(): Encoded {
            val map = HashMap<DictionaryKey, Encoded>()
            var encodeds: MutableList<Encoded> = ArrayList<Encoded>()
            for (entry in inviterIdentityAndBlobMainSeedCandidates.entries) {
                encodeds.add(
                    Encoded.of(
                        arrayOf<Encoded>(
                            Encoded.of(entry.key!!),
                            Encoded.of(entry.value!!),
                        )
                    )
                )
            }
            map.put(
                DictionaryKey(KEY_INVITER_IDENTITY_AND_MAIN_SEED),
                Encoded.of(encodeds.toTypedArray<Encoded>())
            )
            encodeds = ArrayList<Encoded>()
            for (seed in blobVersionSeedCandidates) {
                encodeds.add(Encoded.of(seed))
            }
            map.put(DictionaryKey(KEY_VERSION_SEED), Encoded.of(encodeds.toTypedArray<Encoded>()))
            encodeds = ArrayList<Encoded>()
            for (key in groupAdminServerAuthenticationPrivateKeyCandidates) {
                encodeds.add(Encoded.of(key))
            }
            map.put(
                DictionaryKey(KEY_GROUP_ADMIN_PRIVATE_KEY),
                Encoded.of(encodeds.toTypedArray<Encoded>())
            )
            return Encoded.of(map)
        }

        fun addBlobKeysCandidates(inviterIdentity: Identity?, blobKeys: BlobKeys) {
            if (inviterIdentity != null && blobKeys.blobMainSeed != null) {
                inviterIdentityAndBlobMainSeedCandidates.put(inviterIdentity, blobKeys.blobMainSeed)
            }
            if (blobKeys.blobVersionSeed != null) {
                blobVersionSeedCandidates.add(blobKeys.blobVersionSeed)
            }
            if (blobKeys.groupAdminServerAuthenticationPrivateKey != null) {
                groupAdminServerAuthenticationPrivateKeyCandidates.add(blobKeys.groupAdminServerAuthenticationPrivateKey)
            }
        }

        companion object {
            const val KEY_INVITER_IDENTITY_AND_MAIN_SEED: String = "ms"
            const val KEY_VERSION_SEED: String = "vs"
            const val KEY_GROUP_ADMIN_PRIVATE_KEY: String = "ga"

            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): InvitationCollectedData {
                val map: HashMap<DictionaryKey, Encoded> = encoded.decodeDictionary()
                var value: Encoded?

                val inviterIdentityAndBlobMainSeedCandidates = HashMap<Identity?, Seed?>()
                value = map.get(DictionaryKey(KEY_INVITER_IDENTITY_AND_MAIN_SEED))
                if (value == null) {
                    throw DecodingException()
                }
                for (enc in value.decodeList()) {
                    val list = enc.decodeList()
                    inviterIdentityAndBlobMainSeedCandidates.put(
                        list[0].decodeIdentity(),
                        list[1].decodeSeed()
                    )
                }

                val blobVersionSeedCandidates = java.util.HashSet<Seed>()
                value = map.get(DictionaryKey(KEY_VERSION_SEED))
                if (value == null) {
                    throw DecodingException()
                }
                for (enc in value.decodeList()) {
                    blobVersionSeedCandidates.add(enc.decodeSeed())
                }

                val groupAdminServerAuthenticationPrivateKeyCandidates =
                    java.util.HashSet<ServerAuthenticationPrivateKey>()
                value = map.get(DictionaryKey(KEY_GROUP_ADMIN_PRIVATE_KEY))
                if (value == null) {
                    throw DecodingException()
                }
                for (enc in value.decodeList()) {
                    groupAdminServerAuthenticationPrivateKeyCandidates.add((enc.decodePrivateKey() as ServerAuthenticationPrivateKey?)!!)
                }

                return InvitationCollectedData(
                    inviterIdentityAndBlobMainSeedCandidates,
                    blobVersionSeedCandidates,
                    groupAdminServerAuthenticationPrivateKeyCandidates
                )
            }
        }
    }

    // used when creating a group
    class IdentityAndPermissions(
        @JvmField val identity: Identity,
        @JvmField val permissions: java.util.HashSet<Permission>
    ) {
        fun encode(): Encoded {
            val encodedPermissions: MutableList<Encoded> = ArrayList<Encoded>()
            for (permission in permissions) {
                encodedPermissions.add(Encoded.of(permission.string))
            }

            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(identity),
                    Encoded.of(encodedPermissions.toTypedArray<Encoded>()),
                )
            )
        }

        val isAdmin: Boolean
            get() = permissions.contains(Permission.GROUP_ADMIN)

        // hashcode only uses the Identity to avoid duplicate group members when building sets of IdentityAndGroupPermissions
        override fun hashCode(): Int {
            return identity.hashCode()
        }

        // equals only matches the Identity to avoid duplicate group members when building sets of IdentityAndGroupPermissions
        override fun equals(other: Any?): Boolean {
            if (other !is IdentityAndPermissions) {
                return false
            }
            return identity == other.identity
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): IdentityAndPermissions {
                val encodeds = encoded.decodeList()
                if (encodeds.size != 2) {
                    throw DecodingException()
                }
                val identity = encodeds[0].decodeIdentity()
                val permissions = java.util.HashSet<Permission>()
                for (encodedPermission in encodeds[1].decodeList()) {
                    val permission: Permission? =
                        Permission.fromString(encodedPermission.decodeString())
                    if (permission != null) {
                        permissions.add(permission)
                    }
                }

                return IdentityAndPermissions(identity, permissions)
            }
        }
        fun getIdentity(): Identity = identity
    }


    // stored in the blob on the server
    class IdentityAndPermissionsAndDetails(
        @JvmField val identity: Identity,
        @JvmField val permissionStrings: MutableList<String>,
        @JvmField val serializedIdentityDetails: String,
        @JvmField val groupInvitationNonce: ByteArray
    ) {
        fun encode(): Encoded {
            val encodedPermissions: MutableList<Encoded> = ArrayList<Encoded>()
            for (permissionString in permissionStrings) {
                encodedPermissions.add(Encoded.of(permissionString))
            }

            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(identity),
                    Encoded.of(encodedPermissions.toTypedArray<Encoded>()),
                    Encoded.of(serializedIdentityDetails),
                    Encoded.of(groupInvitationNonce),
                )
            )
        }

        // hashcode only uses the Identity to avoid duplicate group members when building sets of IdentityAndGroupPermissions
        override fun hashCode(): Int {
            return identity.hashCode()
        }

        // equals only matches the Identity to avoid duplicate group members when building sets of IdentityAndGroupPermissions
        override fun equals(other: Any?): Boolean {
            if (other !is IdentityAndPermissionsAndDetails) {
                return false
            }
            return identity.equals(other.identity)
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): IdentityAndPermissionsAndDetails {
                val encodeds = encoded.decodeList()
                if (encodeds.size != 4) {
                    throw DecodingException()
                }
                val identity = encodeds[0].decodeIdentity()
                val permissionStrings: MutableList<String> = ArrayList<String>()
                for (encodedPermission in encodeds[1].decodeList()) {
                    permissionStrings.add(encodedPermission.decodeString())
                }
                val serializedIdentityDetails = encodeds[2].decodeString()
                val groupInvitationNonce = encodeds[3].decodeBytes()

                return IdentityAndPermissionsAndDetails(
                    identity,
                    permissionStrings,
                    serializedIdentityDetails,
                    groupInvitationNonce
                )
            }
        }
        fun getIdentity(): Identity = identity
        fun getPermissionStrings(): MutableList<String> = permissionStrings
        fun getSerializedIdentityDetails(): String = serializedIdentityDetails
    }

    class IdentifierVersionAndKeys {
        @JvmField val groupIdentifier: Identifier
        @JvmField val groupVersion: Int
        @JvmField val blobKeys: BlobKeys

        constructor(groupIdentifier: Identifier, groupVersion: Int, blobKeys: BlobKeys) {
            this.groupIdentifier = groupIdentifier
            this.groupVersion = groupVersion
            this.blobKeys = blobKeys
        }

        constructor(encoded: Encoded) {
            val list = encoded.decodeList()
            if (list.size != 3) {
                throw Exception()
            }
            this.groupIdentifier = Identifier.of(list[0])
            this.groupVersion = list[1].decodeLong().toInt()
            this.blobKeys = BlobKeys.of(list[2])
        }

        fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    groupIdentifier.encode(),
                    Encoded.of(groupVersion.toLong()),
                    blobKeys.encode(),
                )
            )
        }
    }

    class IdentifierAndAdminStatus(@JvmField val groupIdentifier: Identifier?, @JvmField val iAmAdmin: Boolean) {
    fun getGroupIdentifier(): Identifier? = groupIdentifier
    fun getIAmAdmin(): Boolean = iAmAdmin
}
}
