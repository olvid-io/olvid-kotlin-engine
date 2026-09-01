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
package io.olvid.engine.engine.types.identities

import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.Permission.Companion.deserializeKnownPermissions
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.ObvBytesKey

class ObvGroupV2 {
    @JvmField val bytesOwnedIdentity: ByteArray
    @JvmField val groupIdentifier: GroupV2.Identifier
    @JvmField val ownPermissions: HashSet<GroupV2.Permission>
    @JvmField val otherGroupMembers: HashSet<ObvGroupV2Member>?
    @JvmField val pendingGroupMembers: HashSet<ObvGroupV2PendingMember>?
    @JvmField val detailsAndPhotos: ObvGroupV2DetailsAndPhotos
    @JvmField val lastModificationTimestamp: Long // for invitations, this timestamp is set to 0 and should be ignored

    constructor(
        bytesOwnedIdentity: ByteArray,
        groupIdentifier: GroupV2.Identifier,
        ownPermissions: HashSet<GroupV2.Permission>,
        otherGroupMembers: HashSet<ObvGroupV2Member>?,
        pendingGroupMembers: HashSet<ObvGroupV2PendingMember>?,
        serializedGroupDetails: String,
        photoUrl: String?,
        serializedPublishedDetails: String?,
        publishedPhotoUrl: String?,
        lastModificationTimestamp: Long
    ) {
        this.bytesOwnedIdentity = bytesOwnedIdentity
        this.groupIdentifier = groupIdentifier
        this.ownPermissions = ownPermissions
        this.otherGroupMembers = otherGroupMembers
        this.pendingGroupMembers = pendingGroupMembers
        this.detailsAndPhotos = ObvGroupV2DetailsAndPhotos(
            serializedGroupDetails,
            photoUrl,
            serializedPublishedDetails,
            publishedPhotoUrl
        )
        this.lastModificationTimestamp = lastModificationTimestamp
    }

    private constructor(
        bytesOwnedIdentity: ByteArray,
        groupIdentifier: GroupV2.Identifier,
        ownPermissions: HashSet<GroupV2.Permission>,
        otherGroupMembers: HashSet<ObvGroupV2Member>?,
        pendingGroupMembers: HashSet<ObvGroupV2PendingMember>?,
        detailsAndPhotos: ObvGroupV2DetailsAndPhotos
    ) {
        this.bytesOwnedIdentity = bytesOwnedIdentity
        this.groupIdentifier = groupIdentifier
        this.ownPermissions = ownPermissions
        this.otherGroupMembers = otherGroupMembers
        this.pendingGroupMembers = pendingGroupMembers
        this.detailsAndPhotos = detailsAndPhotos
        this.lastModificationTimestamp =
            0 // this constructor is only used when deserializing a group invitation message, so the lastModificationTimestamp is ignored
    }

    fun encode(): Encoded {
        val encodedMembers: MutableList<Encoded> = ArrayList<Encoded>()
        val encodedPendingMembers: MutableList<Encoded> = ArrayList<Encoded>()
        if (otherGroupMembers != null) {
            for (member in otherGroupMembers) {
                encodedMembers.add(member.encode())
            }
        }
        if (pendingGroupMembers != null) {
            for (member in pendingGroupMembers) {
                encodedPendingMembers.add(member.encode())
            }
        }

        return Encoded.of(
            arrayOf<Encoded>(
                Encoded.of(bytesOwnedIdentity),
                groupIdentifier.encode(),
                Encoded.of(GroupV2.Permission.serializePermissions(ownPermissions)!!),
                Encoded.of(encodedMembers.toTypedArray<Encoded>()),
                Encoded.of(encodedPendingMembers.toTypedArray<Encoded>()),
                detailsAndPhotos.encode(),
            )
        )
    }

    class ObvGroupV2Member(
        @JvmField val bytesIdentity: ByteArray,
        @JvmField val permissions: HashSet<GroupV2.Permission>
    ) {
        fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(bytesIdentity),
                    Encoded.of(GroupV2.Permission.serializePermissions(permissions)!!),
                )
            )
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): ObvGroupV2Member {
                val list: Array<Encoded> = encoded.decodeList()
                if (list.size != 2) {
                    throw DecodingException()
                }
                return ObvGroupV2Member(
                    list[0].decodeBytes(),
                    deserializeKnownPermissions(list[1].decodeBytes())
                )
            }
        }
    }

    class ObvGroupV2PendingMember(
        @JvmField val bytesIdentity: ByteArray,
        @JvmField val permissions: HashSet<GroupV2.Permission>,
        @JvmField val serializedDetails: String
    ) {
        fun encode(): Encoded {
            return Encoded.of(
                arrayOf<Encoded>(
                    Encoded.of(bytesIdentity),
                    Encoded.of(GroupV2.Permission.serializePermissions(permissions)!!),
                    Encoded.of(serializedDetails),
                )
            )
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): ObvGroupV2PendingMember {
                val list: Array<Encoded> = encoded.decodeList()
                if (list.size != 3) {
                    throw DecodingException()
                }
                return ObvGroupV2PendingMember(
                    list[0].decodeBytes(),
                    deserializeKnownPermissions(list[1].decodeBytes()),
                    list[2].decodeString()
                )
            }
        }
    }

    class ObvGroupV2DetailsAndPhotos(// non null
        @JvmField val serializedGroupDetails: String, // null if the group does not has a photo, "" if it has a photo but it was not downloaded yet
        @JvmField val photoUrl: String?, // null if same version as serializedGroupDetails
        @JvmField val serializedPublishedDetails: String?, // null if serializedPublishedDetails is null, or if there is no photo, "" if there is a photo and it was not downloaded yet
        @JvmField val publishedPhotoUrl: String?
    ) {
        fun getNullIfEmptyPhotoUrl(): String? {
            if ((photoUrl == null) || (photoUrl.isEmpty())) {
                return null
            } else {
                return photoUrl
            }
        }

        fun getNullIfEmptyPublishedPhotoUrl(): String? {
            if ((publishedPhotoUrl == null) || (publishedPhotoUrl.isEmpty())) {
                return null
            } else {
                return publishedPhotoUrl
            }
        }

        fun encode(): Encoded {
            val map = HashMap<DictionaryKey, Encoded>()
            map.put(DictionaryKey(SERIALIZED_GROUP_DETAILS_KEY), Encoded.of(serializedGroupDetails))
            if (photoUrl != null) {
                map.put(DictionaryKey(PHOTO_URL_KEY), Encoded.of(photoUrl))
            }
            if (serializedPublishedDetails != null) {
                map.put(
                    DictionaryKey(SERIALIZED_PUBLISHED_DETAILS_KEY),
                    Encoded.of(serializedPublishedDetails)
                )
            }
            if (publishedPhotoUrl != null) {
                map.put(DictionaryKey(PUBLISHED_PHOTO_URL_KEY), Encoded.of(publishedPhotoUrl))
            }
            return Encoded.of(map)
        }

        companion object {
            private const val SERIALIZED_GROUP_DETAILS_KEY = "sgd"
            private const val PHOTO_URL_KEY = "pu"
            private const val SERIALIZED_PUBLISHED_DETAILS_KEY = "spd"
            private const val PUBLISHED_PHOTO_URL_KEY = "ppu"

            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): ObvGroupV2DetailsAndPhotos {
                val detailsMap: HashMap<DictionaryKey, Encoded> = encoded.decodeDictionary()
                var enc = detailsMap.get(DictionaryKey(SERIALIZED_GROUP_DETAILS_KEY))
                val serializedGroupDetails = enc!!.decodeString()
                enc = detailsMap.get(DictionaryKey(PHOTO_URL_KEY))
                val photoUrl = if (enc == null) null else enc.decodeString()
                enc = detailsMap.get(DictionaryKey(PHOTO_URL_KEY))
                val serializedPublishedDetails = if (enc == null) null else enc.decodeString()
                enc = detailsMap.get(DictionaryKey(PHOTO_URL_KEY))
                val publishedPhotoUrl = if (enc == null) null else enc.decodeString()

                return ObvGroupV2DetailsAndPhotos(
                    serializedGroupDetails,
                    photoUrl,
                    serializedPublishedDetails,
                    publishedPhotoUrl
                )
            }
        }
    }

    class ObvGroupV2ChangeSet {
        @JvmField val removedMembers: MutableList<ByteArray>
        @JvmField val addedMembersWithPermissions: HashMap<ObvBytesKey?, HashSet<GroupV2.Permission>?>
        @JvmField val permissionChanges: HashMap<ObvBytesKey?, HashSet<GroupV2.Permission>?> // may contain your ownedIdentity

        @JvmField var updatedSerializedGroupDetails: String? = null // null if no change
        @JvmField var updatedJsonGroupType: String? = null // null if no change
        @JvmField var updatedPhotoUrl: String? = null  // null if no change, "" if photo removed

        init {
            removedMembers = ArrayList<ByteArray>()
            addedMembersWithPermissions = HashMap<ObvBytesKey?, HashSet<GroupV2.Permission>?>()
            permissionChanges = HashMap<ObvBytesKey?, HashSet<GroupV2.Permission>?>()
        }

        fun isEmpty(): Boolean {
            return removedMembers.isEmpty() && addedMembersWithPermissions.isEmpty() && permissionChanges.isEmpty() && updatedPhotoUrl == null && updatedSerializedGroupDetails == null && updatedJsonGroupType == null
        }

        fun encode(): Encoded {
            val dic = HashMap<DictionaryKey, Encoded>()
            if (!removedMembers.isEmpty()) {
                val encodeds = ArrayList<Encoded>()
                for (removedMember in removedMembers) {
                    encodeds.add(Encoded.of(removedMember))
                }
                dic.put(DictionaryKey("rm"), Encoded.of(encodeds.toTypedArray<Encoded>()))
            }
            if (!addedMembersWithPermissions.isEmpty()) {
                val encodeds = ArrayList<Encoded>()
                for (entry in addedMembersWithPermissions.entries) {
                    val serializedPermissions = GroupV2.Permission.serializePermissions(entry.value!!)
                    if (serializedPermissions != null) {
                        encodeds.add(Encoded.of(entry.key!!.getBytes()))
                        encodeds.add(Encoded.of(serializedPermissions))
                    }
                }
                dic.put(DictionaryKey("am"), Encoded.of(encodeds.toTypedArray<Encoded>()))
            }
            if (!permissionChanges.isEmpty()) {
                val encodeds = ArrayList<Encoded>()
                for (entry in permissionChanges.entries) {
                    val serializedPermissions = GroupV2.Permission.serializePermissions(entry.value!!)
                    if (serializedPermissions != null) {
                        encodeds.add(Encoded.of(entry.key!!.getBytes()))
                        encodeds.add(Encoded.of(serializedPermissions))
                    }
                }
                dic.put(DictionaryKey("pc"), Encoded.of(encodeds.toTypedArray<Encoded>()))
            }
            if (updatedSerializedGroupDetails != null) {
                dic.put(DictionaryKey("gd"), Encoded.of(updatedSerializedGroupDetails!!))
            }
            if (updatedJsonGroupType != null) {
                dic.put(DictionaryKey("gt"), Encoded.of(updatedJsonGroupType!!))
            }
            if (updatedPhotoUrl != null) {
                dic.put(DictionaryKey("pu"), Encoded.of(updatedPhotoUrl!!))
            }
            return Encoded.of(dic)
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): ObvGroupV2ChangeSet {
                val dic: HashMap<DictionaryKey, Encoded> = encoded.decodeDictionary()

                val changeSet = ObvGroupV2ChangeSet()
                var enc = dic.get(DictionaryKey("rm"))
                if (enc != null) {
                    for (encodedGroupMember in enc.decodeList()) {
                        changeSet.removedMembers.add(encodedGroupMember.decodeBytes())
                    }
                }
                enc = dic.get(DictionaryKey("am"))
                if (enc != null) {
                    val encodeds: Array<Encoded> = enc.decodeList()
                    var i = 0
                    while (i < encodeds.size) {
                        changeSet.addedMembersWithPermissions.put(
                            ObvBytesKey(encodeds[i].decodeBytes()),
                            deserializeKnownPermissions(encodeds[i + 1].decodeBytes())
                        )
                        i += 2
                    }
                }
                enc = dic.get(DictionaryKey("pc"))
                if (enc != null) {
                    val encodeds: Array<Encoded> = enc.decodeList()
                    var i = 0
                    while (i < encodeds.size) {
                        changeSet.permissionChanges.put(
                            ObvBytesKey(encodeds[i].decodeBytes()),
                            deserializeKnownPermissions(encodeds[i + 1].decodeBytes())
                        )
                        i += 2
                    }
                }
                enc = dic.get(DictionaryKey("gd"))
                if (enc != null) {
                    changeSet.updatedSerializedGroupDetails = enc.decodeString()
                }
                enc = dic.get(DictionaryKey("gt"))
                if (enc != null) {
                    changeSet.updatedJsonGroupType = enc.decodeString()
                }
                enc = dic.get(DictionaryKey("pu"))
                if (enc != null) {
                    changeSet.updatedPhotoUrl = enc.decodeString()
                }

                return changeSet
            }
        }
    }

    companion object {
        @JvmStatic
        @Throws(DecodingException::class)
        fun of(encoded: Encoded): ObvGroupV2 {
            val list: Array<Encoded> = encoded.decodeList()
            if (list.size != 6) {
                throw DecodingException()
            }
            val otherGroupMembers = HashSet<ObvGroupV2Member>()
            val pendingGroupMembers = HashSet<ObvGroupV2PendingMember>()
            for (encodedMember in list[3].decodeList()) {
                otherGroupMembers.add(ObvGroupV2Member.of(encodedMember))
            }
            for (encodedMember in list[4].decodeList()) {
                pendingGroupMembers.add(ObvGroupV2PendingMember.of(encodedMember))
            }

            return ObvGroupV2(
                list[0].decodeBytes(),
                GroupV2.Identifier.of(list[1]),
                deserializeKnownPermissions(list[2].decodeBytes()),
                otherGroupMembers,
                pendingGroupMembers,
                ObvGroupV2DetailsAndPhotos.of(list[5])
            )
        }
    }
}
