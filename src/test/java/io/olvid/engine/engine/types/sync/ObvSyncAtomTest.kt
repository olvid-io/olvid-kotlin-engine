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

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.sync.ObvSyncAtom.DiscussionIdentifier
import io.olvid.engine.engine.types.sync.ObvSyncAtom.MessageIdentifier
import io.olvid.engine.engine.types.sync.ObvSyncAtom.MuteNotification
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.UUID

/**
 * Characterization tests for [ObvSyncAtom].
 *
 * The TYPE_* integer constants are WIRE FORMAT — encoded into Encoded bytes that are persisted
 * on-device and exchanged across devices during sync. Any change to these values silently
 * corrupts sync state. A Kotlin migration that renumbers any constant breaks real user data.
 *
 * Groups:
 *  1. Wire-format TYPE_* constant pin — 22 tests
 *  2. Static factory field population contracts — ~22 tests
 *  3. isAppSyncItem() dispatch — 22 tests
 *  4. Encode/decode round-trips for 6 representative types — 6 tests
 *  5. of() error paths — 3 tests
 *  6. encode() layout pin — 2 tests
 *  7. Wire-format golden-hex pin — 1 test
 *  8. DiscussionIdentifier nested class — 6 tests
 *  9. MessageIdentifier nested class — 3 tests
 * 10. MuteNotification nested class — 5 tests
 * 11. No custom equals/hashCode: reference identity — 1 test
 */
class ObvSyncAtomTest {

    // ─── Test fixtures ─────────────────────────────────────────────────────────

    private lateinit var contactIdentity: Identity
    private lateinit var contactIdentity2: Identity
    private lateinit var bytesContactIdentity: ByteArray
    private lateinit var bytesContactIdentity2: ByteArray

    /** groupOwnerAndUid = owner identity bytes + 32-byte UID */
    private lateinit var bytesGroupOwnerAndUid: ByteArray

    /** A realistic GroupV2.Identifier for server category */
    private lateinit var groupV2Identifier: GroupV2.Identifier
    private lateinit var bytesGroupV2Identifier: ByteArray

    @Before
    fun setUp() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })
        Logger.setOutputLogLevel(Logger.DEBUG)

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))

        val serverAuthKeyPair1 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKeyPair1 = EncryptionEciesCurve25519KeyPair.generate(prng)
        contactIdentity = Identity(
            "test.olvid.io",
            serverAuthKeyPair1.publicKey as ServerAuthenticationPublicKey,
            encKeyPair1.publicKey as EncryptionPublicKey,
        )
        bytesContactIdentity = contactIdentity.getBytes()

        val serverAuthKeyPair2 = ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng)
        val encKeyPair2 = EncryptionEciesCurve25519KeyPair.generate(prng)
        contactIdentity2 = Identity(
            "test.olvid.io",
            serverAuthKeyPair2.publicKey as ServerAuthenticationPublicKey,
            encKeyPair2.publicKey as EncryptionPublicKey,
        )
        bytesContactIdentity2 = contactIdentity2.getBytes()

        // groupOwnerAndUid: owner identity bytes followed by a 32-byte UID
        val groupUid = UID(ByteArray(UID.UID_LENGTH) { (it + 1).toByte() })
        bytesGroupOwnerAndUid = bytesContactIdentity + groupUid.bytes

        // GroupV2 identifier
        val gv2Uid = UID(ByteArray(UID.UID_LENGTH) { (it + 7).toByte() })
        groupV2Identifier = GroupV2.Identifier(gv2Uid, "test.olvid.io", GroupV2.Identifier.CATEGORY_SERVER)
        bytesGroupV2Identifier = groupV2Identifier.bytes
    }

    // ─── Group 1: Wire-format TYPE_* constant pins ────────────────────────────
    //
    // These integer values are persisted on-device and sent over the wire. Any
    // accidental renumbering silently corrupts sync state on every device. Each
    // test pins the exact value.

    @Test fun testTypeConstant_CONTACT_NICKNAME_CHANGE_is0() =
        assertEquals(0, ObvSyncAtom.TYPE_CONTACT_NICKNAME_CHANGE)

    @Test fun testTypeConstant_GROUP_V1_NICKNAME_CHANGE_is1() =
        assertEquals(1, ObvSyncAtom.TYPE_GROUP_V1_NICKNAME_CHANGE)

    @Test fun testTypeConstant_GROUP_V2_NICKNAME_CHANGE_is2() =
        assertEquals(2, ObvSyncAtom.TYPE_GROUP_V2_NICKNAME_CHANGE)

    @Test fun testTypeConstant_CONTACT_PERSONAL_NOTE_CHANGE_is3() =
        assertEquals(3, ObvSyncAtom.TYPE_CONTACT_PERSONAL_NOTE_CHANGE)

    @Test fun testTypeConstant_GROUP_V1_PERSONAL_NOTE_CHANGE_is4() =
        assertEquals(4, ObvSyncAtom.TYPE_GROUP_V1_PERSONAL_NOTE_CHANGE)

    @Test fun testTypeConstant_GROUP_V2_PERSONAL_NOTE_CHANGE_is5() =
        assertEquals(5, ObvSyncAtom.TYPE_GROUP_V2_PERSONAL_NOTE_CHANGE)

    @Test fun testTypeConstant_OWN_PROFILE_NICKNAME_CHANGE_is6() =
        assertEquals(6, ObvSyncAtom.TYPE_OWN_PROFILE_NICKNAME_CHANGE)

    @Test fun testTypeConstant_CONTACT_CUSTOM_HUE_CHANGE_is7() =
        assertEquals(7, ObvSyncAtom.TYPE_CONTACT_CUSTOM_HUE_CHANGE)

    @Test fun testTypeConstant_CONTACT_SEND_READ_RECEIPT_CHANGE_is8() =
        assertEquals(8, ObvSyncAtom.TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE)

    @Test fun testTypeConstant_GROUP_V1_SEND_READ_RECEIPT_CHANGE_is9() =
        assertEquals(9, ObvSyncAtom.TYPE_GROUP_V1_SEND_READ_RECEIPT_CHANGE)

    @Test fun testTypeConstant_GROUP_V2_SEND_READ_RECEIPT_CHANGE_is10() =
        assertEquals(10, ObvSyncAtom.TYPE_GROUP_V2_SEND_READ_RECEIPT_CHANGE)

    @Test fun testTypeConstant_PINNED_DISCUSSIONS_CHANGE_is11() =
        assertEquals(11, ObvSyncAtom.TYPE_PINNED_DISCUSSIONS_CHANGE)

    @Test fun testTypeConstant_TRUST_CONTACT_DETAILS_is12() =
        assertEquals(12, ObvSyncAtom.TYPE_TRUST_CONTACT_DETAILS)

    @Test fun testTypeConstant_TRUST_GROUP_V1_DETAILS_is13() =
        assertEquals(13, ObvSyncAtom.TYPE_TRUST_GROUP_V1_DETAILS)

    @Test fun testTypeConstant_TRUST_GROUP_V2_DETAILS_is14() =
        assertEquals(14, ObvSyncAtom.TYPE_TRUST_GROUP_V2_DETAILS)

    @Test fun testTypeConstant_SETTING_DEFAULT_SEND_READ_RECEIPTS_is15() =
        assertEquals(15, ObvSyncAtom.TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS)

    @Test fun testTypeConstant_SETTING_AUTO_JOIN_GROUPS_is16() =
        assertEquals(16, ObvSyncAtom.TYPE_SETTING_AUTO_JOIN_GROUPS)

    @Test fun testTypeConstant_BOOKMARKED_MESSAGE_CHANGE_is17() =
        assertEquals(17, ObvSyncAtom.TYPE_BOOKMARKED_MESSAGE_CHANGE)

    @Test fun testTypeConstant_ARCHIVED_DISCUSSIONS_CHANGE_is18() =
        assertEquals(18, ObvSyncAtom.TYPE_ARCHIVED_DISCUSSIONS_CHANGE)

    @Test fun testTypeConstant_DISCUSSIONS_MUTE_CHANGE_is19() =
        assertEquals(19, ObvSyncAtom.TYPE_DISCUSSIONS_MUTE_CHANGE)

    @Test fun testTypeConstant_SETTING_UNARCHIVE_ON_NOTIFICATION_is20() =
        assertEquals(20, ObvSyncAtom.TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION)

    @Test fun testTypeConstant_SETTING_LAST_RATING_is21() =
        assertEquals(21, ObvSyncAtom.TYPE_SETTING_LAST_RATING)

    // ─── Group 2: Static factory field population contracts ───────────────────
    //
    // Each factory must set syncType to the matching TYPE_* constant, populate
    // exactly the right value field, and leave all other value fields null.
    // These tests pin the field-population contract used by dispatch code.

    @Test
    fun testFactory_createContactNicknameChange_populatesTypeAndStringAndIdentity() {
        val atom = ObvSyncAtom.createContactNicknameChange(bytesContactIdentity, "Alice")
        assertEquals(ObvSyncAtom.TYPE_CONTACT_NICKNAME_CHANGE, atom.syncType)
        assertEquals("Alice", atom.getStringValue())
        assertNotNull(atom.contactIdentity)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
        assertNull(atom.discussionIdentifiers)
        assertNull(atom.messageIdentifier)
        assertNull(atom.muteNotification)
    }

    @Test
    fun testFactory_createContactNicknameChange_nullNickname() {
        val atom = ObvSyncAtom.createContactNicknameChange(bytesContactIdentity, null)
        assertEquals(ObvSyncAtom.TYPE_CONTACT_NICKNAME_CHANGE, atom.syncType)
        // getStringValue() trims and returns null for null
        assertNull(atom.getStringValue())
    }

    @Test
    fun testFactory_createGroupV1NicknameChange_populatesType() {
        val atom = ObvSyncAtom.createGroupV1NicknameChange(bytesGroupOwnerAndUid, "My Group")
        assertEquals(ObvSyncAtom.TYPE_GROUP_V1_NICKNAME_CHANGE, atom.syncType)
        assertEquals("My Group", atom.getStringValue())
        assertNotNull(atom.bytesGroupOwnerAndUid)
        assertNull(atom.contactIdentity)
        assertNull(atom.bytesGroupIdentifier)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createGroupV2NicknameChange_populatesType() {
        val atom = ObvSyncAtom.createGroupV2NicknameChange(bytesGroupV2Identifier, "V2 Group")
        assertEquals(ObvSyncAtom.TYPE_GROUP_V2_NICKNAME_CHANGE, atom.syncType)
        assertEquals("V2 Group", atom.getStringValue())
        assertNotNull(atom.bytesGroupIdentifier)
        assertNull(atom.contactIdentity)
        assertNull(atom.bytesGroupOwnerAndUid)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createContactPersonalNoteChange_populatesType() {
        val atom = ObvSyncAtom.createContactPersonalNoteChange(bytesContactIdentity, "Note here")
        assertEquals(ObvSyncAtom.TYPE_CONTACT_PERSONAL_NOTE_CHANGE, atom.syncType)
        assertEquals("Note here", atom.getStringValue())
        assertNotNull(atom.contactIdentity)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createGroupV1PersonalNoteChange_populatesType() {
        val atom = ObvSyncAtom.createGroupV1PersonalNoteChange(bytesGroupOwnerAndUid, "Group note")
        assertEquals(ObvSyncAtom.TYPE_GROUP_V1_PERSONAL_NOTE_CHANGE, atom.syncType)
        assertEquals("Group note", atom.getStringValue())
        assertNotNull(atom.bytesGroupOwnerAndUid)
        assertNull(atom.contactIdentity)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createGroupV2PersonalNoteChange_populatesType() {
        val atom = ObvSyncAtom.createGroupV2PersonalNoteChange(bytesGroupV2Identifier, "V2 note")
        assertEquals(ObvSyncAtom.TYPE_GROUP_V2_PERSONAL_NOTE_CHANGE, atom.syncType)
        assertEquals("V2 note", atom.getStringValue())
        assertNotNull(atom.bytesGroupIdentifier)
        assertNull(atom.contactIdentity)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createOwnProfileNicknameChange_populatesType() {
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("MyAlias")
        assertEquals(ObvSyncAtom.TYPE_OWN_PROFILE_NICKNAME_CHANGE, atom.syncType)
        assertEquals("MyAlias", atom.getStringValue())
        assertNull(atom.contactIdentity)
        assertNull(atom.bytesGroupOwnerAndUid)
        assertNull(atom.bytesGroupIdentifier)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createContactCustomHueChange_populatesIntegerAndIdentity() {
        val atom = ObvSyncAtom.createContactCustomHueChange(bytesContactIdentity, 42)
        assertEquals(ObvSyncAtom.TYPE_CONTACT_CUSTOM_HUE_CHANGE, atom.syncType)
        assertEquals(42, atom.integerValue)
        assertNotNull(atom.contactIdentity)
        assertNull(atom.getStringValue())
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createContactCustomHueChange_nullHue() {
        val atom = ObvSyncAtom.createContactCustomHueChange(bytesContactIdentity, null)
        assertEquals(ObvSyncAtom.TYPE_CONTACT_CUSTOM_HUE_CHANGE, atom.syncType)
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createContactSendReadReceiptChange_populatesBooleanAndIdentity() {
        val atom = ObvSyncAtom.createContactSendReadReceiptChange(bytesContactIdentity, true)
        assertEquals(ObvSyncAtom.TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE, atom.syncType)
        assertEquals(true, atom.booleanValue)
        assertNotNull(atom.contactIdentity)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createGroupV1SendReadReceiptChange_populatesType() {
        val atom = ObvSyncAtom.createGroupV1SendReadReceiptChange(bytesGroupOwnerAndUid, false)
        assertEquals(ObvSyncAtom.TYPE_GROUP_V1_SEND_READ_RECEIPT_CHANGE, atom.syncType)
        assertEquals(false, atom.booleanValue)
        assertNotNull(atom.bytesGroupOwnerAndUid)
        assertNull(atom.contactIdentity)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createGroupV2SendReadReceiptChange_populatesType() {
        val atom = ObvSyncAtom.createGroupV2SendReadReceiptChange(bytesGroupV2Identifier, true)
        assertEquals(ObvSyncAtom.TYPE_GROUP_V2_SEND_READ_RECEIPT_CHANGE, atom.syncType)
        assertEquals(true, atom.booleanValue)
        assertNotNull(atom.bytesGroupIdentifier)
        assertNull(atom.contactIdentity)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createPinnedDiscussionsChange_populatesListAndBoolean() {
        val id = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val atom = ObvSyncAtom.createPinnedDiscussionsChange(listOf(id), true)
        assertEquals(ObvSyncAtom.TYPE_PINNED_DISCUSSIONS_CHANGE, atom.syncType)
        assertEquals(true, atom.booleanValue)
        assertNotNull(atom.discussionIdentifiers)
        assertEquals(1, atom.discussionIdentifiers!!.size)
        assertNull(atom.contactIdentity)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createTrustContactDetails_populatesIdentityAndString() {
        val atom = ObvSyncAtom.createTrustContactDetails(contactIdentity, "{\"details\":\"v1\"}")
        assertEquals(ObvSyncAtom.TYPE_TRUST_CONTACT_DETAILS, atom.syncType)
        assertEquals("{\"details\":\"v1\"}", atom.getStringValue())
        assertNotNull(atom.contactIdentity)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createTrustGroupV1Details_populatesGroupAndString() {
        val atom = ObvSyncAtom.createTrustGroupV1Details(bytesGroupOwnerAndUid, "{\"v\":1}")
        assertEquals(ObvSyncAtom.TYPE_TRUST_GROUP_V1_DETAILS, atom.syncType)
        assertEquals("{\"v\":1}", atom.getStringValue())
        assertNotNull(atom.bytesGroupOwnerAndUid)
        assertNull(atom.contactIdentity)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createTrustGroupV2Details_populatesGroupAndVersion() {
        val atom = ObvSyncAtom.createTrustGroupV2Details(groupV2Identifier, 5)
        assertEquals(ObvSyncAtom.TYPE_TRUST_GROUP_V2_DETAILS, atom.syncType)
        assertEquals(5, atom.integerValue)
        assertNotNull(atom.bytesGroupIdentifier)
        assertNull(atom.contactIdentity)
        assertNull(atom.bytesGroupOwnerAndUid)
        assertNull(atom.getStringValue())
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createSettingDefaultSendReadReceipts_populatesBoolean() {
        val atom = ObvSyncAtom.createSettingDefaultSendReadReceipts(false)
        assertEquals(ObvSyncAtom.TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS, atom.syncType)
        assertEquals(false, atom.booleanValue)
        assertNull(atom.contactIdentity)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createSettingAutoJoinGroups_populatesString() {
        val atom = ObvSyncAtom.createSettingAutoJoinGroups("everyone")
        assertEquals(ObvSyncAtom.TYPE_SETTING_AUTO_JOIN_GROUPS, atom.syncType)
        assertEquals("everyone", atom.getStringValue())
        assertNull(atom.contactIdentity)
        assertNull(atom.integerValue)
        assertNull(atom.booleanValue)
    }

    @Test
    fun testFactory_createBookmarkedMessageChange_populatesMessageIdentifierAndBoolean() {
        val discId = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val msgId = MessageIdentifier(discId, bytesContactIdentity2, UUID.randomUUID(), 1L)
        val atom = ObvSyncAtom.createBookmarkedMessageChange(msgId, true)
        assertEquals(ObvSyncAtom.TYPE_BOOKMARKED_MESSAGE_CHANGE, atom.syncType)
        assertEquals(true, atom.booleanValue)
        assertNotNull(atom.messageIdentifier)
        assertNull(atom.contactIdentity)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
        assertNull(atom.discussionIdentifiers)
    }

    @Test
    fun testFactory_createArchivedDiscussionsChange_populatesListAndBoolean() {
        val id = DiscussionIdentifier(DiscussionIdentifier.GROUP_V2, bytesGroupV2Identifier)
        val atom = ObvSyncAtom.createArchivedDiscussionsChange(listOf(id), true)
        assertEquals(ObvSyncAtom.TYPE_ARCHIVED_DISCUSSIONS_CHANGE, atom.syncType)
        assertEquals(true, atom.booleanValue)
        assertNotNull(atom.discussionIdentifiers)
        assertNull(atom.muteNotification)
    }

    @Test
    fun testFactory_createDiscussionsMuteChange_populatesListAndMuteNotification() {
        val id = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val mute = MuteNotification(true, 1234567890L, false)
        val atom = ObvSyncAtom.createDiscussionsMuteChange(listOf(id), mute)
        assertEquals(ObvSyncAtom.TYPE_DISCUSSIONS_MUTE_CHANGE, atom.syncType)
        assertNotNull(atom.discussionIdentifiers)
        assertNotNull(atom.muteNotification)
        assertNull(atom.booleanValue)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createSettingUnarchiveOnNotification_populatesBoolean() {
        val atom = ObvSyncAtom.createSettingUnarchiveOnNotification(true)
        assertEquals(ObvSyncAtom.TYPE_SETTING_UNARCHIVE_ON_NOTIFICATION, atom.syncType)
        assertEquals(true, atom.booleanValue)
        assertNull(atom.getStringValue())
        assertNull(atom.integerValue)
    }

    @Test
    fun testFactory_createSettingLastRating_populatesRatingAndTimestamp() {
        val atom = ObvSyncAtom.createSettingLastRating(4, 1700000000L)
        assertEquals(ObvSyncAtom.TYPE_SETTING_LAST_RATING, atom.syncType)
        // lastRating stored in integerValue, timestamp stored as stringValue
        assertEquals(4, atom.integerValue)
        assertEquals("1700000000", atom.getStringValue())
        assertNull(atom.contactIdentity)
        assertNull(atom.booleanValue)
    }

    // ─── Group 3: isAppSyncItem() dispatch ────────────────────────────────────
    //
    // Engine-level types (TRUST_*) must return false; all app types must return true.
    // This dispatch is used to route atoms to the correct handler.

    @Test
    fun testIsAppSyncItem_contactNicknameChange_isTrue() =
        assertTrue(ObvSyncAtom.createContactNicknameChange(bytesContactIdentity, "x").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_groupV1NicknameChange_isTrue() =
        assertTrue(ObvSyncAtom.createGroupV1NicknameChange(bytesGroupOwnerAndUid, "x").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_groupV2NicknameChange_isTrue() =
        assertTrue(ObvSyncAtom.createGroupV2NicknameChange(bytesGroupV2Identifier, "x").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_contactPersonalNoteChange_isTrue() =
        assertTrue(ObvSyncAtom.createContactPersonalNoteChange(bytesContactIdentity, "x").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_groupV1PersonalNoteChange_isTrue() =
        assertTrue(ObvSyncAtom.createGroupV1PersonalNoteChange(bytesGroupOwnerAndUid, "x").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_groupV2PersonalNoteChange_isTrue() =
        assertTrue(ObvSyncAtom.createGroupV2PersonalNoteChange(bytesGroupV2Identifier, "x").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_ownProfileNicknameChange_isTrue() =
        assertTrue(ObvSyncAtom.createOwnProfileNicknameChange("x").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_contactCustomHueChange_isTrue() =
        assertTrue(ObvSyncAtom.createContactCustomHueChange(bytesContactIdentity, 1).isAppSyncItem)

    @Test
    fun testIsAppSyncItem_contactSendReadReceiptChange_isTrue() =
        assertTrue(ObvSyncAtom.createContactSendReadReceiptChange(bytesContactIdentity, true).isAppSyncItem)

    @Test
    fun testIsAppSyncItem_groupV1SendReadReceiptChange_isTrue() =
        assertTrue(ObvSyncAtom.createGroupV1SendReadReceiptChange(bytesGroupOwnerAndUid, true).isAppSyncItem)

    @Test
    fun testIsAppSyncItem_groupV2SendReadReceiptChange_isTrue() =
        assertTrue(ObvSyncAtom.createGroupV2SendReadReceiptChange(bytesGroupV2Identifier, true).isAppSyncItem)

    @Test
    fun testIsAppSyncItem_pinnedDiscussionsChange_isTrue() {
        val id = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        assertTrue(ObvSyncAtom.createPinnedDiscussionsChange(listOf(id), true).isAppSyncItem)
    }

    @Test
    fun testIsAppSyncItem_trustContactDetails_isFalse() =
        assertFalse(ObvSyncAtom.createTrustContactDetails(contactIdentity, "{}").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_trustGroupV1Details_isFalse() =
        assertFalse(ObvSyncAtom.createTrustGroupV1Details(bytesGroupOwnerAndUid, "{}").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_trustGroupV2Details_isFalse() =
        assertFalse(ObvSyncAtom.createTrustGroupV2Details(groupV2Identifier, 1).isAppSyncItem)

    @Test
    fun testIsAppSyncItem_settingDefaultSendReadReceipts_isTrue() =
        assertTrue(ObvSyncAtom.createSettingDefaultSendReadReceipts(true).isAppSyncItem)

    @Test
    fun testIsAppSyncItem_settingAutoJoinGroups_isTrue() =
        assertTrue(ObvSyncAtom.createSettingAutoJoinGroups("nobody").isAppSyncItem)

    @Test
    fun testIsAppSyncItem_bookmarkedMessageChange_isTrue() {
        val discId = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val msgId = MessageIdentifier(discId, bytesContactIdentity2, UUID.randomUUID(), 1L)
        assertTrue(ObvSyncAtom.createBookmarkedMessageChange(msgId, true).isAppSyncItem)
    }

    @Test
    fun testIsAppSyncItem_archivedDiscussionsChange_isTrue() {
        val id = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        assertTrue(ObvSyncAtom.createArchivedDiscussionsChange(listOf(id), false).isAppSyncItem)
    }

    @Test
    fun testIsAppSyncItem_discussionsMuteChange_isTrue() {
        val id = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val mute = MuteNotification(true, null, false)
        assertTrue(ObvSyncAtom.createDiscussionsMuteChange(listOf(id), mute).isAppSyncItem)
    }

    @Test
    fun testIsAppSyncItem_settingUnarchiveOnNotification_isTrue() =
        assertTrue(ObvSyncAtom.createSettingUnarchiveOnNotification(true).isAppSyncItem)

    @Test
    fun testIsAppSyncItem_settingLastRating_isTrue() =
        assertTrue(ObvSyncAtom.createSettingLastRating(5, 9999L).isAppSyncItem)

    // ─── Group 4: Encode/decode round-trips ───────────────────────────────────
    //
    // For each representative type: build via factory → encode() → of() and
    // assert field-by-field equality. Covers the five data shapes in the source.

    @Test
    fun testRoundTrip_contactNicknameChange_stringValued() {
        val original = ObvSyncAtom.createContactNicknameChange(bytesContactIdentity, "RoundTripNick")
        val encoded = original.encode()
        val decoded = ObvSyncAtom.of(encoded!!)

        assertEquals(ObvSyncAtom.TYPE_CONTACT_NICKNAME_CHANGE, decoded.syncType)
        assertEquals("RoundTripNick", decoded.getStringValue())
        assertArrayEquals(bytesContactIdentity, decoded.bytesContactIdentity)
    }

    @Test
    fun testRoundTrip_contactSendReadReceiptChange_booleanValued() {
        val original = ObvSyncAtom.createContactSendReadReceiptChange(bytesContactIdentity, false)
        val encoded = original.encode()
        val decoded = ObvSyncAtom.of(encoded!!)

        assertEquals(ObvSyncAtom.TYPE_CONTACT_SEND_READ_RECEIPT_CHANGE, decoded.syncType)
        assertEquals(false, decoded.booleanValue)
        assertArrayEquals(bytesContactIdentity, decoded.bytesContactIdentity)
    }

    @Test
    fun testRoundTrip_contactCustomHueChange_integerValued() {
        val original = ObvSyncAtom.createContactCustomHueChange(bytesContactIdentity, 180)
        val encoded = original.encode()
        val decoded = ObvSyncAtom.of(encoded!!)

        assertEquals(ObvSyncAtom.TYPE_CONTACT_CUSTOM_HUE_CHANGE, decoded.syncType)
        assertEquals(180, decoded.integerValue)
        assertArrayEquals(bytesContactIdentity, decoded.bytesContactIdentity)
    }

    @Test
    fun testRoundTrip_trustContactDetails_identityKeyed() {
        val serialized = "{\"version\":2,\"name\":\"Bob\"}"
        val original = ObvSyncAtom.createTrustContactDetails(contactIdentity, serialized)
        val encoded = original.encode()
        val decoded = ObvSyncAtom.of(encoded!!)

        assertEquals(ObvSyncAtom.TYPE_TRUST_CONTACT_DETAILS, decoded.syncType)
        assertEquals(serialized, decoded.getStringValue())
        assertEquals(contactIdentity, decoded.contactIdentity)
    }

    @Test
    fun testRoundTrip_groupV2NicknameChange_groupKeyed() {
        val original = ObvSyncAtom.createGroupV2NicknameChange(bytesGroupV2Identifier, "V2Nick")
        val encoded = original.encode()
        val decoded = ObvSyncAtom.of(encoded!!)

        assertEquals(ObvSyncAtom.TYPE_GROUP_V2_NICKNAME_CHANGE, decoded.syncType)
        assertEquals("V2Nick", decoded.getStringValue())
        assertArrayEquals(bytesGroupV2Identifier, decoded.bytesGroupIdentifier)
    }

    @Test
    fun testRoundTrip_settingLastRating_twoFields() {
        val original = ObvSyncAtom.createSettingLastRating(3, 1699999999L)
        val encoded = original.encode()
        val decoded = ObvSyncAtom.of(encoded!!)

        assertEquals(ObvSyncAtom.TYPE_SETTING_LAST_RATING, decoded.syncType)
        assertEquals(3, decoded.integerValue)
        // Timestamp round-trips via stringValue; getStringValue() returns it trimmed
        assertEquals("1699999999", decoded.getStringValue())
    }

    // ─── Group 5: of() error paths ────────────────────────────────────────────

    @Test(expected = DecodingException::class)
    fun testOf_emptyList_throwsDecodingException() {
        // The outer list must have at least 1 element (the type)
        ObvSyncAtom.of(Encoded.of(arrayOf<Encoded>()))
    }

    @Test(expected = DecodingException::class)
    fun testOf_unknownSyncType999_throwsDecodingException() {
        // syncType=999 is not a known TYPE_*, so of() must throw
        val unknownType = Encoded.of(arrayOf(Encoded.of(999L)))
        ObvSyncAtom.of(unknownType)
    }

    @Test(expected = DecodingException::class)
    fun testOf_negativeSyncType_throwsDecodingException() {
        val negType = Encoded.of(arrayOf(Encoded.of(-1L)))
        ObvSyncAtom.of(negType)
    }

    // ─── Group 6: encode() layout pin ─────────────────────────────────────────
    //
    // encode() must produce an outer list where the first element encodes the
    // syncType integer. This structural contract is the parse anchor for of().

    @Test
    fun testEncodeLayout_firstElementIsSyncType_forContactNicknameChange() {
        val atom = ObvSyncAtom.createContactNicknameChange(bytesContactIdentity, "Nick")
        val outer = atom.encode()!!.decodeList()
        // [0] = syncType, [1] = identity, [2] = nickname
        assertTrue("outer list must have at least 1 element", outer.isNotEmpty())
        assertEquals(
            ObvSyncAtom.TYPE_CONTACT_NICKNAME_CHANGE.toLong(),
            outer[0].decodeLong(),
        )
    }

    @Test
    fun testEncodeLayout_settingDefaultSendReadReceipts_has2Elements() {
        val atom = ObvSyncAtom.createSettingDefaultSendReadReceipts(true)
        val outer = atom.encode()!!.decodeList()
        // [0] = syncType(15), [1] = boolean
        assertEquals(2, outer.size)
        assertEquals(ObvSyncAtom.TYPE_SETTING_DEFAULT_SEND_READ_RECEIPTS.toLong(), outer[0].decodeLong())
        assertTrue(outer[1].decodeBoolean())
    }

    // ─── Group 7: Wire-format golden-hex pin ──────────────────────────────────
    //
    // Pin the exact byte output of encode() for createOwnProfileNicknameChange("Hi").
    // This is a simple, deterministic case (no identity bytes, one string).
    // If the encoding format ever changes, this test fails with a clear diff.
    //
    // Structure of encode() for TYPE_OWN_PROFILE_NICKNAME_CHANGE(6) with nickname="Hi":
    //   Encoded.of(6L):
    //     BYTE_IDS_INT(01) + uint32(8) + 8-byte big-endian 6
    //     = 01 00 00 00 08  00 00 00 00 00 00 00 06  (13 bytes)
    //   Encoded.of("Hi"):
    //     "Hi".toByteArray(UTF-8) = [0x48, 0x69] (2 bytes)
    //     BYTE_IDS_BYTE_ARRAY(00) + uint32(2) + data
    //     = 00 00 00 00 02  48 69  (7 bytes)
    //   Outer list of [Encoded.of(6L), Encoded.of("Hi")]:
    //     content length = 13 + 7 = 20 = 0x14
    //     03 00 00 00 14  <13 bytes>  <7 bytes>
    //   Total = 5 + 13 + 7 = 25 bytes

    @Test
    fun testGoldenHex_ownProfileNicknameChange_Hi() {
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("Hi")
        val hex = atom.encode()!!.bytes.joinToString("") { "%02x".format(it) }
        // 25 bytes total:
        //   outer list header (5):      03 00 00 00 14   (content = 13+7 = 20 = 0x14)
        //   Encoded.of(6L) (13):        01 00 00 00 08   00 00 00 00 00 00 00 06
        //   Encoded.of("Hi") (7):       00 00 00 00 02   48 69
        //     (BYTE_IDS_BYTE_ARRAY=0x00, length=2, "Hi"=0x48 0x69)
        assertEquals(
            "03000000140100000008000000000000000600000000024869",
            hex,
        )
    }

    // ─── Group 8: DiscussionIdentifier nested class ───────────────────────────

    @Test
    fun testDiscussionIdentifier_typeConstants() {
        assertEquals(0, DiscussionIdentifier.CONTACT)
        assertEquals(1, DiscussionIdentifier.GROUP_V1)
        assertEquals(2, DiscussionIdentifier.GROUP_V2)
    }

    @Test
    fun testDiscussionIdentifier_contactRoundTrip() {
        val original = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val encoded = original.encode()
        val decoded = DiscussionIdentifier.of(encoded!!)

        assertEquals(DiscussionIdentifier.CONTACT, decoded.type)
        assertArrayEquals(bytesContactIdentity, decoded.bytesDiscussionIdentifier)
    }

    @Test
    fun testDiscussionIdentifier_groupV1RoundTrip() {
        val original = DiscussionIdentifier(DiscussionIdentifier.GROUP_V1, bytesGroupOwnerAndUid)
        val encoded = original.encode()
        val decoded = DiscussionIdentifier.of(encoded!!)

        assertEquals(DiscussionIdentifier.GROUP_V1, decoded.type)
        assertArrayEquals(bytesGroupOwnerAndUid, decoded.bytesDiscussionIdentifier)
    }

    @Test
    fun testDiscussionIdentifier_groupV2RoundTrip() {
        val original = DiscussionIdentifier(DiscussionIdentifier.GROUP_V2, bytesGroupV2Identifier)
        val encoded = original.encode()
        val decoded = DiscussionIdentifier.of(encoded!!)

        assertEquals(DiscussionIdentifier.GROUP_V2, decoded.type)
        assertArrayEquals(bytesGroupV2Identifier, decoded.bytesDiscussionIdentifier)
    }

    @Test(expected = DecodingException::class)
    fun testDiscussionIdentifier_emptyList_throwsDecodingException() {
        DiscussionIdentifier.of(Encoded.of(arrayOf<Encoded>()))
    }

    @Test(expected = DecodingException::class)
    fun testDiscussionIdentifier_unknownType_throwsDecodingException() {
        // type=99 is not CONTACT, GROUP_V1, or GROUP_V2
        val encoded = Encoded.of(arrayOf(Encoded.of(99L), Encoded.of(bytesContactIdentity)))
        DiscussionIdentifier.of(encoded)
    }

    // ─── Group 9: MessageIdentifier nested class ──────────────────────────────

    @Test
    fun testMessageIdentifier_roundTrip() {
        val discId = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val threadId = UUID.fromString("12345678-1234-1234-1234-123456789abc")
        val original = MessageIdentifier(discId, bytesContactIdentity2, threadId, 42L)

        val encoded = original.encode()
        val decoded = MessageIdentifier.of(encoded)

        assertEquals(DiscussionIdentifier.CONTACT, decoded.discussionIdentifier.type)
        assertArrayEquals(bytesContactIdentity, decoded.discussionIdentifier.bytesDiscussionIdentifier)
        assertArrayEquals(bytesContactIdentity2, decoded.senderIdentifier)
        assertEquals(threadId, decoded.senderThreadIdentifier)
        assertEquals(42L, decoded.senderSequenceNumber)
    }

    @Test
    fun testMessageIdentifier_groupV2Discussion_roundTrip() {
        val discId = DiscussionIdentifier(DiscussionIdentifier.GROUP_V2, bytesGroupV2Identifier)
        val threadId = UUID.randomUUID()
        val original = MessageIdentifier(discId, bytesContactIdentity, threadId, 1L)

        val encoded = original.encode()
        val decoded = MessageIdentifier.of(encoded)

        assertEquals(DiscussionIdentifier.GROUP_V2, decoded.discussionIdentifier.type)
        assertArrayEquals(bytesGroupV2Identifier, decoded.discussionIdentifier.bytesDiscussionIdentifier)
        assertEquals(1L, decoded.senderSequenceNumber)
    }

    @Test(expected = DecodingException::class)
    fun testMessageIdentifier_wrongArity_throwsDecodingException() {
        // MessageIdentifier.of() requires exactly 4 inner elements; provide 3
        val encoded = Encoded.of(arrayOf(Encoded.of(1L), Encoded.of(2L), Encoded.of(3L)))
        MessageIdentifier.of(encoded)
    }

    // ─── Group 10: MuteNotification nested class ──────────────────────────────

    @Test
    fun testMuteNotification_keyConstants() {
        assertEquals("m", MuteNotification.MUTED)
        assertEquals("t", MuteNotification.MUTE_TIMESTAMP)
        assertEquals("e", MuteNotification.EXCEPT_MENTIONED)
    }

    @Test
    fun testMuteNotification_roundTrip_withTimestamp() {
        val original = MuteNotification(true, 1700000000L, false)
        val decoded = MuteNotification.of(original.encode())

        assertTrue(decoded.muted)
        assertEquals(1700000000L, decoded.muteTimestamp)
        assertFalse(decoded.exceptMentioned)
    }

    @Test
    fun testMuteNotification_roundTrip_noTimestamp() {
        val original = MuteNotification(false, null, true)
        val decoded = MuteNotification.of(original.encode())

        assertFalse(decoded.muted)
        assertNull(decoded.muteTimestamp)
        // When EXCEPT_MENTIONED key is present with true, it decodes as true
        assertTrue(decoded.exceptMentioned)
    }

    @Test
    fun testMuteNotification_missingExceptMentioned_defaultsToTrue() {
        // The source: `encodedMentions == null || encodedMentions.decodeBoolean()`
        // So if the key is absent, exceptMentioned defaults to true.
        val original = MuteNotification(true, null, true)
        // Manually encode without the EXCEPT_MENTIONED key to simulate an older sender
        val map = HashMap<io.olvid.engine.datatypes.DictionaryKey, Encoded>()
        map[io.olvid.engine.datatypes.DictionaryKey(MuteNotification.MUTED)] = Encoded.of(true)
        // Omit EXCEPT_MENTIONED intentionally
        val encodedWithoutExceptMentioned = Encoded.of(map)
        val decoded = MuteNotification.of(encodedWithoutExceptMentioned)

        assertTrue("missing EXCEPT_MENTIONED must default to true", decoded.exceptMentioned)
    }

    @Test
    fun testMuteNotification_roundTrip_insideDiscussionsMuteChange() {
        val discId = DiscussionIdentifier(DiscussionIdentifier.CONTACT, bytesContactIdentity)
        val mute = MuteNotification(true, 9999L, false)
        val atom = ObvSyncAtom.createDiscussionsMuteChange(listOf(discId), mute)
        val encoded = atom.encode()
        val decoded = ObvSyncAtom.of(encoded!!)

        assertEquals(ObvSyncAtom.TYPE_DISCUSSIONS_MUTE_CHANGE, decoded.syncType)
        val decodedMute = decoded.muteNotification
        assertNotNull(decodedMute)
        assertTrue(decodedMute!!.muted)
        assertEquals(9999L, decodedMute.muteTimestamp)
        assertFalse(decodedMute.exceptMentioned)
    }

    // ─── Group 11: No custom equals/hashCode — reference identity ─────────────
    //
    // ObvSyncAtom does not override equals() or hashCode(). Two independently
    // constructed atoms with the same data are not equal by value; only the same
    // reference is equal to itself.

    @Test
    fun testNoCustomEquals_twoInstancesWithSameDataAreNotEqual() {
        val a1 = ObvSyncAtom.createOwnProfileNicknameChange("Same")
        val a2 = ObvSyncAtom.createOwnProfileNicknameChange("Same")
        // Object.equals → reference equality only
        assertFalse("Two distinct ObvSyncAtom instances must not be equal by value", a1 == a2)
        assertTrue("An instance must equal itself", a1 == a1)
    }

    // ─── Group 12: getStringValue() trim/null contract ────────────────────────
    //
    // getStringValue() returns null for null and for blank/empty strings.
    // This is a behavioral contract separate from the raw stringValue field.

    @Test
    fun testGetStringValue_blankString_returnsNull() {
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("   ")
        assertNull("getStringValue() must return null for blank input", atom.getStringValue())
    }

    @Test
    fun testGetStringValue_stringWithPadding_returnsTrimmed() {
        val atom = ObvSyncAtom.createOwnProfileNicknameChange("  hello  ")
        assertEquals("hello", atom.getStringValue())
    }

    @Test
    fun testGetStringValue_normalString_returnsAsIs() {
        val atom = ObvSyncAtom.createSettingAutoJoinGroups("nobody")
        assertEquals("nobody", atom.getStringValue())
    }
}
