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
package io.olvid.engine.engine.types.sync

import io.olvid.engine.datatypes.DictionaryKey
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import java.util.UUID

class ObvSyncAtom private constructor(
    @JvmField val syncType: Int,
    @JvmField val contactIdentity: Identity?,
    @JvmField val bytesGroupOwnerAndUid: ByteArray?,
    @JvmField val bytesGroupIdentifier: ByteArray?,
    @JvmField val stringValue: String?,
    @JvmField val integerValue: Int?,
    @JvmField val booleanValue: Boolean?,
    @JvmField val discussionIdentifiers: List<DiscussionIdentifier>?,
    @JvmField val messageIdentifier: MessageIdentifier?,
    @JvmField val muteNotification: MuteNotification?
) {
    val isAppSyncItem: Boolean
        get() {
            return when (syncType) {
                TYPE_CONTACT_NICKNAME_CHANGE, TYPE_GROUP_V1_NICKNAME_CHANGE, TYPE_GROUP_V2_NICKNAME_CHANGE, TYPE_CONTACT_PERSONAL_NOTE_CHANGE, TYPE_GROUP_V1_PERSONAL_NOTE_CHANGE, TYPE_GROUP_V2_PERSONAL_NOTE_CHANGE, TYPE_OWN_PROFILE_NICKNAME_CHANGE, TYPE_CONTACT_CUSTOM_HUE_CHANGE, TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE, TYPE_GROUP_V1_SEND_READ_RECEIPT_CHANGE, TYPE_GROUP_V2_SEND_READ_RECEIPT_CHANGE, TYPE_PINNED_DISCUSSIONS_CHANGE, TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS, TYPE_SETTING_AUTO_JOIN_GROUPS, TYPE_BOOKMARKED_MESSAGE_CHANGE, TYPE_ARCHIVED_DISCUSSIONS_CHANGE, TYPE_DISCUSSIONS_MUTE_CHANGE, TYPE_SETTING_LAST_RATING, TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION, TYPE_STOP_SUGGESTING_CONTACT -> true

                TYPE_TRUST_CONTACT_DETAILS, TYPE_TRUST_GROUP_V1_DETAILS, TYPE_TRUST_GROUP_V2_DETAILS -> false
                else -> false
            }
        }

    val bytesContactIdentity: ByteArray?
        get() = contactIdentity?.getBytes()

    @get:Throws(DecodingException::class)
    val groupIdentifier: GroupV2.Identifier?
        get() = bytesGroupIdentifier?.let { GroupV2.Identifier.of(it) }

    fun getStringValue(): String? {
        if (stringValue == null) {
            return null
        }
        val out = stringValue.trim { it <= ' ' }
        if (out.isEmpty()) {
            return null
        }
        return out
    }

    fun encode(): Encoded? {
        val encodeds = ArrayList<Encoded>()
        encodeds.add(Encoded.of(syncType.toLong()))
        when (syncType) {
            TYPE_CONTACT_NICKNAME_CHANGE, TYPE_CONTACT_PERSONAL_NOTE_CHANGE -> {
                encodeds.add(Encoded.of(contactIdentity!!))
                if (stringValue != null) {
                    encodeds.add(Encoded.of(stringValue))
                }
            }

            TYPE_GROUP_V1_NICKNAME_CHANGE, TYPE_GROUP_V1_PERSONAL_NOTE_CHANGE -> {
                encodeds.add(
                    Encoded.of(
                        this.bytesGroupOwnerAndUid!!.copyOfRange(
                            0,
                            bytesGroupOwnerAndUid.size - UID.UID_LENGTH
                        )
                    )
                )
                encodeds.add(
                    Encoded.of(
                        this.bytesGroupOwnerAndUid.copyOfRange(
                            bytesGroupOwnerAndUid.size - UID.UID_LENGTH,
                            bytesGroupOwnerAndUid.size
                        )
                    )
                )
                if (stringValue != null) {
                    encodeds.add(Encoded.of(stringValue))
                }
            }

            TYPE_GROUP_V2_NICKNAME_CHANGE, TYPE_GROUP_V2_PERSONAL_NOTE_CHANGE -> {
                encodeds.add(Encoded.of(bytesGroupIdentifier!!))
                if (stringValue != null) {
                    encodeds.add(Encoded.of(stringValue))
                }
            }

            TYPE_OWN_PROFILE_NICKNAME_CHANGE -> {
                if (stringValue != null) {
                    encodeds.add(Encoded.of(stringValue))
                }
            }

            TYPE_CONTACT_CUSTOM_HUE_CHANGE -> {
                encodeds.add(Encoded.of(contactIdentity!!))
                if (integerValue != null) {
                    encodeds.add(Encoded.of(integerValue.toLong()))
                }
            }

            TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE -> {
                encodeds.add(Encoded.of(contactIdentity!!))
                if (booleanValue != null) {
                    encodeds.add(Encoded.of(booleanValue))
                }
            }

            TYPE_GROUP_V1_SEND_READ_RECEIPT_CHANGE -> {
                encodeds.add(
                    Encoded.of(
                        this.bytesGroupOwnerAndUid!!.copyOfRange(
                            0,
                            bytesGroupOwnerAndUid.size - UID.UID_LENGTH
                        )
                    )
                )
                encodeds.add(
                    Encoded.of(
                        this.bytesGroupOwnerAndUid.copyOfRange(
                            bytesGroupOwnerAndUid.size - UID.UID_LENGTH,
                            bytesGroupOwnerAndUid.size
                        )
                    )
                )
                if (booleanValue != null) {
                    encodeds.add(Encoded.of(booleanValue))
                }
            }

            TYPE_GROUP_V2_SEND_READ_RECEIPT_CHANGE -> {
                encodeds.add(Encoded.of(bytesGroupIdentifier!!))
                if (booleanValue != null) {
                    encodeds.add(Encoded.of(booleanValue))
                }
            }

            TYPE_PINNED_DISCUSSIONS_CHANGE, TYPE_ARCHIVED_DISCUSSIONS_CHANGE -> {
                val encodedDiscussionIdentifiers = ArrayList<Encoded>()
                for (discussionIdentifier in discussionIdentifiers!!) {
                    encodedDiscussionIdentifiers.add(discussionIdentifier.encode()!!)
                }
                encodeds.add(Encoded.of(encodedDiscussionIdentifiers.toTypedArray<Encoded>()))
                encodeds.add(Encoded.of(booleanValue!!))
            }

            TYPE_TRUST_CONTACT_DETAILS -> {
                encodeds.add(Encoded.of(contactIdentity!!))
                encodeds.add(Encoded.of(stringValue!!))
            }

            TYPE_TRUST_GROUP_V1_DETAILS -> {
                encodeds.add(
                    Encoded.of(
                        this.bytesGroupOwnerAndUid!!.copyOfRange(
                            0,
                            bytesGroupOwnerAndUid.size - UID.UID_LENGTH
                        )
                    )
                )
                encodeds.add(
                    Encoded.of(
                        this.bytesGroupOwnerAndUid.copyOfRange(
                            bytesGroupOwnerAndUid.size - UID.UID_LENGTH,
                            bytesGroupOwnerAndUid.size
                        )
                    )
                )
                encodeds.add(Encoded.of(stringValue!!))
            }

            TYPE_TRUST_GROUP_V2_DETAILS -> {
                encodeds.add(Encoded.of(bytesGroupIdentifier!!))
                encodeds.add(Encoded.of(integerValue!!.toLong()))
            }

            TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS, TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION -> {
                encodeds.add(Encoded.of(booleanValue!!))
            }

            TYPE_SETTING_AUTO_JOIN_GROUPS -> {
                encodeds.add(Encoded.of(stringValue!!))
            }

            TYPE_BOOKMARKED_MESSAGE_CHANGE -> {
                encodeds.add(messageIdentifier!!.encode())
                encodeds.add(Encoded.of(booleanValue!!))
            }

            TYPE_DISCUSSIONS_MUTE_CHANGE -> {
                val encodedDiscussionIdentifiers = ArrayList<Encoded>()
                for (discussionIdentifier in discussionIdentifiers!!) {
                    encodedDiscussionIdentifiers.add(discussionIdentifier.encode()!!)
                }
                encodeds.add(Encoded.of(encodedDiscussionIdentifiers.toTypedArray<Encoded>()))
                encodeds.add(muteNotification!!.encode())
            }

            TYPE_SETTING_LAST_RATING -> {
                encodeds.add(Encoded.of(integerValue!!.toLong()))
                encodeds.add(Encoded.of(stringValue!!))
            }

            TYPE_STOP_SUGGESTING_CONTACT -> {
                encodeds.add(Encoded.of(contactIdentity!!))
            }

            else -> {
                return null
            }
        }
        return Encoded.of(encodeds.toTypedArray<Encoded>())
    }

    class MuteNotification(
        @JvmField val muted: Boolean,
        @JvmField val muteTimestamp: Long?,
        @JvmField val exceptMentioned: Boolean
    ) {
        fun encode(): Encoded {
            val map = HashMap<DictionaryKey, Encoded>()
            map[DictionaryKey(MUTED)] = Encoded.of(muted)
            if (muteTimestamp != null) {
                map[DictionaryKey(MUTE_TIMESTAMP)] = Encoded.of(muteTimestamp)
            }
            map[DictionaryKey(EXCEPT_MENTIONED)] = Encoded.of(exceptMentioned)
            return Encoded.of(map)
        }

        companion object {
            const val MUTED: String = "m"
            const val MUTE_TIMESTAMP: String = "t"
            const val EXCEPT_MENTIONED: String = "e"

            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): MuteNotification {
                val map: HashMap<DictionaryKey, Encoded> = encoded.decodeDictionary()
                val muted = map[DictionaryKey(MUTED)]!!.decodeBoolean()
                val encodedTimestamp = map[DictionaryKey(MUTE_TIMESTAMP)]
                val muteTimestamp = encodedTimestamp?.decodeLong()
                val encodedMentions = map[DictionaryKey(EXCEPT_MENTIONED)]
                val exceptMentioned = encodedMentions == null || encodedMentions.decodeBoolean()
                return MuteNotification(muted, muteTimestamp, exceptMentioned)
            }
        }
    }

    class MessageIdentifier(
        @JvmField val discussionIdentifier: DiscussionIdentifier,
        @JvmField val senderIdentifier: ByteArray,
        @JvmField val senderThreadIdentifier: UUID?,
        @JvmField val senderSequenceNumber: Long
    ) {
        fun encode(): Encoded {
            return Encoded.of(
                arrayOf(
                    discussionIdentifier.encode()!!,
                    Encoded.of(senderIdentifier),
                    Encoded.of(senderThreadIdentifier),
                    Encoded.of(senderSequenceNumber)
                )
            )
        }

        companion object {
            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): MessageIdentifier {
                val encodeds: Array<Encoded> = encoded.decodeList()
                if (encodeds.size != 4) {
                    throw DecodingException()
                }
                return MessageIdentifier(
                    DiscussionIdentifier.of(encodeds[0]),
                    encodeds[1].decodeBytes(),
                    encodeds[2].decodeUuid(),
                    encodeds[3].decodeLong()
                )
            }
        }
    }

    class DiscussionIdentifier(@JvmField val type: Int, @JvmField val bytesDiscussionIdentifier: ByteArray) {
        fun encode(): Encoded? {
            val encodeds: MutableList<Encoded> = ArrayList()
            encodeds.add(Encoded.of(type.toLong()))
            when (type) {
                CONTACT, GROUP_V2 -> {
                    encodeds.add(Encoded.of(bytesDiscussionIdentifier))
                }

                GROUP_V1 -> {
                    encodeds.add(
                        Encoded.of(
                            bytesDiscussionIdentifier.copyOfRange(
                                0,
                                bytesDiscussionIdentifier.size - UID.UID_LENGTH
                            )
                        )
                    )
                    encodeds.add(
                        Encoded.of(
                            bytesDiscussionIdentifier.copyOfRange(
                                bytesDiscussionIdentifier.size - UID.UID_LENGTH,
                                bytesDiscussionIdentifier.size
                            )
                        )
                    )
                }

                else -> return null
            }
            return Encoded.of(encodeds.toTypedArray<Encoded>())
        }


        companion object {
            const val CONTACT: Int = 0
            const val GROUP_V1: Int = 1
            const val GROUP_V2: Int = 2

            @JvmStatic
            @Throws(DecodingException::class)
            fun of(encoded: Encoded): DiscussionIdentifier {
                val encodeds: Array<Encoded> = encoded.decodeList()
                if (encodeds.isEmpty()) {
                    throw DecodingException()
                }
                when (val type = encodeds[0].decodeLong().toInt()) {
                    CONTACT, GROUP_V2 -> {
                        return DiscussionIdentifier(type, encodeds[1].decodeBytes())
                    }

                    GROUP_V1 -> {
                        return DiscussionIdentifier(
                            type,
                            joinArrays(encodeds[1].decodeBytes(), encodeds[2].decodeBytes())
                        )
                    }
                }
                throw DecodingException()
            }
        }
    }

    companion object {
        const val TYPE_CONTACT_NICKNAME_CHANGE: Int = 0
        const val TYPE_GROUP_V1_NICKNAME_CHANGE: Int = 1
        const val TYPE_GROUP_V2_NICKNAME_CHANGE: Int = 2
        const val TYPE_CONTACT_PERSONAL_NOTE_CHANGE: Int = 3
        const val TYPE_GROUP_V1_PERSONAL_NOTE_CHANGE: Int = 4
        const val TYPE_GROUP_V2_PERSONAL_NOTE_CHANGE: Int = 5
        const val TYPE_OWN_PROFILE_NICKNAME_CHANGE: Int = 6
        const val TYPE_CONTACT_CUSTOM_HUE_CHANGE: Int = 7
        const val TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE: Int = 8
        const val TYPE_GROUP_V1_SEND_READ_RECEIPT_CHANGE: Int = 9
        const val TYPE_GROUP_V2_SEND_READ_RECEIPT_CHANGE: Int = 10
        const val TYPE_PINNED_DISCUSSIONS_CHANGE: Int = 11
        const val TYPE_TRUST_CONTACT_DETAILS: Int = 12
        const val TYPE_TRUST_GROUP_V1_DETAILS: Int = 13
        const val TYPE_TRUST_GROUP_V2_DETAILS: Int = 14
        const val TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS: Int = 15
        const val TYPE_SETTING_AUTO_JOIN_GROUPS: Int = 16
        const val TYPE_BOOKMARKED_MESSAGE_CHANGE: Int = 17
        const val TYPE_ARCHIVED_DISCUSSIONS_CHANGE: Int = 18
        const val TYPE_DISCUSSIONS_MUTE_CHANGE: Int = 19
        const val TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION: Int = 20
        const val TYPE_SETTING_LAST_RATING: Int = 21
        const val TYPE_STOP_SUGGESTING_CONTACT: Int = 22

        @JvmStatic @Throws(DecodingException::class)
        fun createContactNicknameChange(
            bytesContactIdentity: ByteArray,
            nickname: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_CONTACT_NICKNAME_CHANGE,
                Identity.of(bytesContactIdentity),
                null,
                null,
                nickname,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createGroupV1NicknameChange(
            bytesGroupOwnerAndUid: ByteArray,
            nickname: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_GROUP_V1_NICKNAME_CHANGE,
                null,
                bytesGroupOwnerAndUid,
                null,
                nickname,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createGroupV2NicknameChange(
            bytesGroupV2Identifier: ByteArray,
            nickname: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_GROUP_V2_NICKNAME_CHANGE,
                null,
                null,
                bytesGroupV2Identifier,
                nickname,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic @Throws(DecodingException::class)
        fun createContactPersonalNoteChange(
            bytesContactIdentity: ByteArray,
            personalNote: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_CONTACT_PERSONAL_NOTE_CHANGE,
                Identity.of(bytesContactIdentity),
                null,
                null,
                personalNote,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createGroupV1PersonalNoteChange(
            bytesGroupOwnerAndUid: ByteArray,
            nickname: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_GROUP_V1_PERSONAL_NOTE_CHANGE,
                null,
                bytesGroupOwnerAndUid,
                null,
                nickname,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createGroupV2PersonalNoteChange(
            bytesGroupV2Identifier: ByteArray,
            nickname: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_GROUP_V2_PERSONAL_NOTE_CHANGE,
                null,
                null,
                bytesGroupV2Identifier,
                nickname,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createOwnProfileNicknameChange(nickname: String?): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_OWN_PROFILE_NICKNAME_CHANGE,
                null,
                null,
                null,
                nickname,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic @Throws(DecodingException::class)
        fun createContactCustomHueChange(
            bytesContactIdentity: ByteArray,
            customHue: Int?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_CONTACT_CUSTOM_HUE_CHANGE,
                Identity.of(bytesContactIdentity),
                null,
                null,
                null,
                customHue,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic @Throws(DecodingException::class)
        fun createContactSendReadReceiptChange(
            bytesContactIdentity: ByteArray,
            sendReadReceipt: Boolean?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE,
                Identity.of(bytesContactIdentity),
                null,
                null,
                null,
                null,
                sendReadReceipt,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createGroupV1SendReadReceiptChange(
            bytesGroupOwnerAndUid: ByteArray,
            sendReadReceipt: Boolean?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_GROUP_V1_SEND_READ_RECEIPT_CHANGE,
                null,
                bytesGroupOwnerAndUid,
                null,
                null,
                null,
                sendReadReceipt,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createGroupV2SendReadReceiptChange(
            bytesGroupV2Identifier: ByteArray,
            sendReadReceipt: Boolean?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_GROUP_V2_SEND_READ_RECEIPT_CHANGE,
                null,
                null,
                bytesGroupV2Identifier,
                null,
                null,
                sendReadReceipt,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createPinnedDiscussionsChange(
            discussionIdentifiers: List<DiscussionIdentifier>,
            ordered: Boolean
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_PINNED_DISCUSSIONS_CHANGE,
                null,
                null,
                null,
                null,
                null,
                ordered,
                discussionIdentifiers,
                null,
                null
            )
        }

        // we send the complete details to trust in the ObvSyncAtom as the version may be meaningless (after a channel creation, published details may require a version number downgrade)
        @JvmStatic fun createTrustContactDetails(
            contactIdentity: Identity,
            serializedIdentityDetailsWithVersionAndPhoto: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_TRUST_CONTACT_DETAILS,
                contactIdentity,
                null,
                null,
                serializedIdentityDetailsWithVersionAndPhoto,
                null,
                null,
                null,
                null,
                null
            )
        }

        // we send the complete details to trust in the ObvSyncAtom as the version may be meaningless (after a channel creation, published details may require a version number downgrade)
        @JvmStatic fun createTrustGroupV1Details(
            bytesGroupOwnerAndUid: ByteArray,
            serializedGroupDetailsWithVersionAndPhoto: String?
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_TRUST_GROUP_V1_DETAILS,
                null,
                bytesGroupOwnerAndUid,
                null,
                serializedGroupDetailsWithVersionAndPhoto,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createTrustGroupV2Details(
            groupIdentifier: GroupV2.Identifier,
            version: Int
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_TRUST_GROUP_V2_DETAILS,
                null,
                null,
                groupIdentifier.encode().bytes,
                null,
                version,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createSettingDefaultSendReadReceipts(sendReadReceipt: Boolean): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS,
                null,
                null,
                null,
                null,
                null,
                sendReadReceipt,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createSettingAutoJoinGroups(autoJoinGroupsType: String?): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_SETTING_AUTO_JOIN_GROUPS,
                null,
                null,
                null,
                autoJoinGroupsType,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createBookmarkedMessageChange(
            messageIdentifier: MessageIdentifier,
            bookmarked: Boolean
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_BOOKMARKED_MESSAGE_CHANGE,
                null,
                null,
                null,
                null,
                null,
                bookmarked,
                null,
                messageIdentifier,
                null
            )
        }

        @JvmStatic fun createArchivedDiscussionsChange(
            discussionIdentifiers: List<DiscussionIdentifier>,
            archived: Boolean
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_ARCHIVED_DISCUSSIONS_CHANGE,
                null,
                null,
                null,
                null,
                null,
                archived,
                discussionIdentifiers,
                null,
                null
            )
        }

        @JvmStatic fun createDiscussionsMuteChange(
            discussionIdentifiers: List<DiscussionIdentifier>,
            muteNotification: MuteNotification
        ): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_DISCUSSIONS_MUTE_CHANGE,
                null,
                null,
                null,
                null,
                null,
                null,
                discussionIdentifiers,
                null,
                muteNotification
            )
        }

        @JvmStatic fun createSettingUnarchiveOnNotification(unarchiveOnNotification: Boolean?): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION,
                null,
                null,
                null,
                null,
                null,
                unarchiveOnNotification,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createSettingLastRating(lastRating: Int, lastRatingTimestamp: Long): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_SETTING_LAST_RATING,
                null,
                null,
                null,
                lastRatingTimestamp.toString(),
                lastRating,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic fun createStopSuggestingContact(bytesContactIdentity: ByteArray): ObvSyncAtom {
            return ObvSyncAtom(
                TYPE_STOP_SUGGESTING_CONTACT,
                Identity.of(bytesContactIdentity),
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
            )
        }

        @JvmStatic @Throws(DecodingException::class)
        fun of(encoded: Encoded): ObvSyncAtom {
            val encodeds: Array<Encoded> = encoded.decodeList()
            if (encodeds.isEmpty()) {
                throw DecodingException()
            }
            when (val syncType = encodeds[0].decodeLong().toInt()) {
                TYPE_CONTACT_NICKNAME_CHANGE, TYPE_CONTACT_PERSONAL_NOTE_CHANGE -> {
                    if (encodeds.size == 2) {
                        return ObvSyncAtom(
                            syncType,
                            encodeds[1].decodeIdentity(),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 3) {
                        return ObvSyncAtom(
                            syncType,
                            encodeds[1].decodeIdentity(),
                            null,
                            null,
                            encodeds[2].decodeString(),
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_GROUP_V1_NICKNAME_CHANGE, TYPE_GROUP_V1_PERSONAL_NOTE_CHANGE -> {
                    if (encodeds.size == 3) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            joinArrays(encodeds[1].decodeBytes(), encodeds[2].decodeBytes()),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 4) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            joinArrays(encodeds[1].decodeBytes(), encodeds[2].decodeBytes()),
                            null,
                            encodeds[3].decodeString(),
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_GROUP_V2_NICKNAME_CHANGE, TYPE_GROUP_V2_PERSONAL_NOTE_CHANGE -> {
                    if (encodeds.size == 2) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            null,
                            encodeds[1].decodeBytes(),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 3) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            null,
                            encodeds[1].decodeBytes(),
                            encodeds[2].decodeString(),
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_OWN_PROFILE_NICKNAME_CHANGE -> {
                    if (encodeds.size == 1) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 2) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            null,
                            null,
                            encodeds[1].decodeString(),
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_CONTACT_CUSTOM_HUE_CHANGE -> {
                    if (encodeds.size == 2) {
                        return ObvSyncAtom(
                            syncType,
                            encodeds[1].decodeIdentity(),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 3) {
                        return ObvSyncAtom(
                            syncType,
                            encodeds[1].decodeIdentity(),
                            null,
                            null,
                            null,
                            encodeds[2].decodeLong().toInt(),
                            null,
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE -> {
                    if (encodeds.size == 2) {
                        return ObvSyncAtom(
                            syncType,
                            encodeds[1].decodeIdentity(),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 3) {
                        return ObvSyncAtom(
                            syncType,
                            encodeds[1].decodeIdentity(),
                            null,
                            null,
                            null,
                            null,
                            encodeds[2].decodeBoolean(),
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_GROUP_V1_SEND_READ_RECEIPT_CHANGE -> {
                    if (encodeds.size == 3) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            joinArrays(encodeds[1].decodeBytes(), encodeds[2].decodeBytes()),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 4) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            joinArrays(encodeds[1].decodeBytes(), encodeds[2].decodeBytes()),
                            null,
                            null,
                            null,
                            encodeds[3].decodeBoolean(),
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_GROUP_V2_SEND_READ_RECEIPT_CHANGE -> {
                    if (encodeds.size == 2) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            null,
                            encodeds[1].decodeBytes(),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null
                        )
                    } else if (encodeds.size == 3) {
                        return ObvSyncAtom(
                            syncType,
                            null,
                            null,
                            encodeds[1].decodeBytes(),
                            null,
                            null,
                            encodeds[2].decodeBoolean(),
                            null,
                            null,
                            null
                        )
                    }
                }

                TYPE_PINNED_DISCUSSIONS_CHANGE, TYPE_ARCHIVED_DISCUSSIONS_CHANGE -> {
                    val discussionIdentifiers: MutableList<DiscussionIdentifier> = ArrayList()
                    for (encodedDiscussionIdentifier in encodeds[1].decodeList()) {
                        discussionIdentifiers.add(
                            DiscussionIdentifier.of(
                                encodedDiscussionIdentifier
                            )
                        )
                    }
                    return ObvSyncAtom(
                        syncType,
                        null,
                        null,
                        null,
                        null,
                        null,
                        encodeds[2].decodeBoolean(),
                        discussionIdentifiers,
                        null,
                        null
                    )
                }

                TYPE_TRUST_CONTACT_DETAILS -> {
                    return ObvSyncAtom(
                        syncType,
                        encodeds[1].decodeIdentity(),
                        null,
                        null,
                        encodeds[2].decodeString(),
                        null,
                        null,
                        null,
                        null,
                        null
                    )
                }

                TYPE_TRUST_GROUP_V1_DETAILS -> {
                    return ObvSyncAtom(
                        syncType,
                        null,
                        joinArrays(encodeds[1].decodeBytes(), encodeds[2].decodeBytes()),
                        null,
                        encodeds[3].decodeString(),
                        null,
                        null,
                        null,
                        null,
                        null
                    )
                }

                TYPE_TRUST_GROUP_V2_DETAILS -> {
                    return ObvSyncAtom(
                        syncType,
                        null,
                        null,
                        encodeds[1].decodeBytes(),
                        null,
                        encodeds[2].decodeLong().toInt(),
                        null,
                        null,
                        null,
                        null
                    )
                }

                TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS, TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION -> {
                    return ObvSyncAtom(
                        syncType,
                        null,
                        null,
                        null,
                        null,
                        null,
                        encodeds[1].decodeBoolean(),
                        null,
                        null,
                        null
                    )
                }

                TYPE_SETTING_AUTO_JOIN_GROUPS -> {
                    return ObvSyncAtom(
                        syncType,
                        null,
                        null,
                        null,
                        encodeds[1].decodeString(),
                        null,
                        null,
                        null,
                        null,
                        null
                    )
                }

                TYPE_BOOKMARKED_MESSAGE_CHANGE -> {
                    return ObvSyncAtom(
                        syncType,
                        null,
                        null,
                        null,
                        null,
                        null,
                        encodeds[2].decodeBoolean(),
                        null,
                        MessageIdentifier.of(encodeds[1]),
                        null
                    )
                }

                TYPE_DISCUSSIONS_MUTE_CHANGE -> {
                    val discussionIdentifiers: MutableList<DiscussionIdentifier> = ArrayList()
                    for (encodedDiscussionIdentifier in encodeds[1].decodeList()) {
                        discussionIdentifiers.add(
                            DiscussionIdentifier.of(
                                encodedDiscussionIdentifier
                            )
                        )
                    }
                    return ObvSyncAtom(
                        syncType,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        discussionIdentifiers,
                        null,
                        MuteNotification.of(encodeds[2])
                    )
                }

                TYPE_SETTING_LAST_RATING -> {
                    return ObvSyncAtom(
                        syncType,
                        null,
                        null,
                        null,
                        encodeds[2].decodeString(),
                        encodeds[1].decodeLong().toInt(),
                        null,
                        null,
                        null,
                        null
                    )
                }

                TYPE_STOP_SUGGESTING_CONTACT -> {
                    return ObvSyncAtom(
                        syncType,
                        encodeds[1].decodeIdentity(),
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null,
                        null
                    )
                }
            }
            throw DecodingException()
        }

        private fun joinArrays(a: ByteArray, b: ByteArray): ByteArray {
            val out = ByteArray(a.size + b.size)
            System.arraycopy(a, 0, out, 0, a.size)
            System.arraycopy(b, 0, out, a.size, b.size)
            return out
        }
    }
}
