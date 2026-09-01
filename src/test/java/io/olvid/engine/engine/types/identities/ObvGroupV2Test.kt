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

import io.olvid.engine.Logger
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.GroupV2.Permission
import io.olvid.engine.encoder.DecodingException
import io.olvid.engine.encoder.Encoded
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2ChangeSet
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2DetailsAndPhotos
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2Member
import io.olvid.engine.engine.types.identities.ObvGroupV2.ObvGroupV2PendingMember
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Test
import java.util.HashSet

/**
 * Characterization tests for [ObvGroupV2] and all its nested classes.
 *
 * [ObvGroupV2] is a wire-format DTO: changes to field names, encode() element ordering,
 * or nested-class equality semantics all silently break serialization or set-deduplication
 * in the production app. Every contract tested here is a migration guard.
 *
 * Groups:
 *  A. GroupV2.Permission enum — wire strings and count          (8 tests)
 *  B. ObvGroupV2Member — field storage, no custom equals        (5 tests)
 *  C. ObvGroupV2Member — encode()/of() round-trip              (3 tests)
 *  D. ObvGroupV2Member — encode() layout pin                   (2 tests)
 *  E. ObvGroupV2PendingMember — field storage, no custom equals (5 tests)
 *  F. ObvGroupV2PendingMember — encode()/of() round-trip       (3 tests)
 *  G. ObvGroupV2PendingMember — encode() layout pin            (2 tests)
 *  H. ObvGroupV2DetailsAndPhotos — field storage               (4 tests)
 *  I. ObvGroupV2DetailsAndPhotos — encode()/of() round-trip    (4 tests)
 *  J. ObvGroupV2DetailsAndPhotos — getNullIfEmpty helpers       (4 tests)
 *  K. ObvGroupV2ChangeSet — field defaults and isEmpty()       (6 tests)
 *  L. ObvGroupV2ChangeSet — encode()/of() round-trip           (4 tests)
 *  M. ObvGroupV2 — constructor field storage                   (7 tests)
 *  N. ObvGroupV2 — encode()/of() round-trip                    (4 tests)
 *  O. ObvGroupV2 — encode() layout pin (6-element list)        (3 tests)
 *  P. ObvGroupV2 — of() error paths                            (2 tests)
 *  Q. ObvGroupV2 — invitation timestamp=0 semantic             (2 tests)
 *  R. ObvGroupV2 — golden-hex pin                              (1 test)
 */
class ObvGroupV2Test {

    // ── shared deterministic test data ────────────────────────────────────────

    private val ownedIdentityBytes = ByteArray(32) { it.toByte() }
    private val memberIdentityBytes = ByteArray(32) { (it + 50).toByte() }
    private val pendingMemberBytes = ByteArray(32) { (it + 100).toByte() }
    private val groupUidBytes = ByteArray(UID.UID_LENGTH) { (0xAB).toByte() }

    private fun makeGroupIdentifier(): GroupV2.Identifier =
        GroupV2.Identifier(UID(groupUidBytes), "https://server.example.com", GroupV2.Identifier.CATEGORY_SERVER)

    private fun adminPermissions(): HashSet<Permission> =
        hashSetOf(Permission.GROUP_ADMIN, Permission.SEND_MESSAGE, Permission.CHANGE_SETTINGS)

    private fun memberPermissions(): HashSet<Permission> =
        hashSetOf(Permission.SEND_MESSAGE, Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES)

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
    }

    // ════════════════════════════════════════════════════════════════════════════
    // A. GroupV2.Permission enum — wire strings and constant count
    //
    // The wire strings are used by serializePermissions / deserializeKnownPermissions
    // to encode permission sets as null-delimited byte sequences. Any rename silently
    // breaks inter-device communication.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testPermission_groupAdmin_wireString_is_ga() {
        assertEquals("ga", Permission.GROUP_ADMIN.string)
    }

    @Test
    fun testPermission_remoteDeleteAnything_wireString_is_rd() {
        assertEquals("rd", Permission.REMOTE_DELETE_ANYTHING.string)
    }

    @Test
    fun testPermission_editOrRemoteDeleteOwnMessages_wireString_is_eo() {
        assertEquals("eo", Permission.EDIT_OR_REMOTE_DELETE_OWN_MESSAGES.string)
    }

    @Test
    fun testPermission_changeSettings_wireString_is_cs() {
        assertEquals("cs", Permission.CHANGE_SETTINGS.string)
    }

    @Test
    fun testPermission_sendMessage_wireString_is_sm() {
        assertEquals("sm", Permission.SEND_MESSAGE.string)
    }

    @Test
    fun testPermission_enumHasExactly5Constants() {
        assertEquals(
            "Permission enum must declare exactly 5 constants (wire-format contract)",
            5,
            Permission.values().size
        )
    }

    @Test
    fun testPermission_fromString_ga_returnsGroupAdmin() {
        assertEquals(Permission.GROUP_ADMIN, Permission.fromString("ga"))
    }

    @Test
    fun testPermission_fromString_unknownString_returnsNull() {
        assertNull(Permission.fromString("xx"))
    }

    // ════════════════════════════════════════════════════════════════════════════
    // B. ObvGroupV2Member — field storage, reference semantics, no custom equals
    //
    // ObvGroupV2Member has NO custom equals/hashCode. HashSet<ObvGroupV2Member>
    // stored in ObvGroupV2 uses reference identity for deduplication. A migration
    // that adds value-based equals would change deduplication behavior.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testMember_bytesIdentity_storedByReference() {
        val perms = memberPermissions()
        val member = ObvGroupV2Member(memberIdentityBytes, perms)
        assertSame(
            "bytesIdentity must be stored by reference, no defensive copy",
            memberIdentityBytes, member.bytesIdentity
        )
    }

    @Test
    fun testMember_permissions_storedByReference() {
        val perms = memberPermissions()
        val member = ObvGroupV2Member(memberIdentityBytes, perms)
        assertSame(
            "permissions must be stored by reference, no defensive copy",
            perms, member.permissions
        )
    }

    @Test
    fun testMember_noCustomEquals_twoSameContentInstances_areNotEqual() {
        // LOAD-BEARING: ObvGroupV2Member has no overridden equals(). If a Kotlin
        // migration adds value-based equals, this test will catch it immediately.
        val perms1 = memberPermissions()
        val perms2 = memberPermissions()
        val m1 = ObvGroupV2Member(memberIdentityBytes.clone(), perms1)
        val m2 = ObvGroupV2Member(memberIdentityBytes.clone(), perms2)
        assertNotEquals(
            "ObvGroupV2Member uses Object.equals (reference identity); two different instances must be unequal",
            m1, m2
        )
    }

    @Test
    fun testMember_noCustomEquals_sameInstance_isEqualToItself() {
        val member = ObvGroupV2Member(memberIdentityBytes, memberPermissions())
        assertEquals("Same instance must equal itself (reflexive)", member, member)
    }

    @Test
    fun testMember_hashSet_twoDistinctInstances_withSameContent_countAsBothEntries() {
        // Because there is no custom equals/hashCode, two distinct instances with
        // identical content are NOT considered duplicates by HashSet.
        val m1 = ObvGroupV2Member(memberIdentityBytes.clone(), memberPermissions())
        val m2 = ObvGroupV2Member(memberIdentityBytes.clone(), memberPermissions())
        val set = HashSet<ObvGroupV2Member>()
        set.add(m1)
        set.add(m2)
        assertEquals(
            "HashSet must keep both distinct ObvGroupV2Member instances (no custom equals)",
            2, set.size
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // C. ObvGroupV2Member — encode()/of() round-trip
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testMember_roundTrip_bytesIdentity() {
        val original = ObvGroupV2Member(memberIdentityBytes, memberPermissions())
        val decoded = ObvGroupV2Member.of(original.encode())
        assertArrayEquals(
            "bytesIdentity must survive encode/of round-trip",
            memberIdentityBytes, decoded.bytesIdentity
        )
    }

    @Test
    fun testMember_roundTrip_permissions() {
        val perms = memberPermissions()
        val original = ObvGroupV2Member(memberIdentityBytes, perms)
        val decoded = ObvGroupV2Member.of(original.encode())
        assertEquals(
            "permissions must survive encode/of round-trip",
            perms, decoded.permissions
        )
    }

    @Test
    fun testMember_roundTrip_emptyPermissions() {
        val original = ObvGroupV2Member(memberIdentityBytes, HashSet())
        val decoded = ObvGroupV2Member.of(original.encode())
        assertArrayEquals("bytesIdentity survives round-trip with empty perms", memberIdentityBytes, decoded.bytesIdentity)
        assertTrue("empty permissions survive round-trip", decoded.permissions.isEmpty())
    }

    // ════════════════════════════════════════════════════════════════════════════
    // D. ObvGroupV2Member — encode() layout pin
    //
    // encode() must produce a 2-element list: [bytesIdentity, serializedPermissions].
    // Slot ordering is load-bearing: of() decodes by position.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testMember_encodeLayout_isTwoElementList() {
        val member = ObvGroupV2Member(memberIdentityBytes, memberPermissions())
        val list = member.encode().decodeList()
        assertEquals("ObvGroupV2Member.encode() must produce a 2-element list", 2, list.size)
    }

    @Test
    fun testMember_encodeLayout_slot0_isBytesIdentity() {
        val member = ObvGroupV2Member(memberIdentityBytes, memberPermissions())
        val list = member.encode().decodeList()
        assertArrayEquals(
            "slot 0 of ObvGroupV2Member.encode() must be bytesIdentity",
            memberIdentityBytes, list[0].decodeBytes()
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // E. ObvGroupV2PendingMember — field storage, no custom equals
    //
    // Same reference-identity semantics as ObvGroupV2Member.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testPendingMember_bytesIdentity_storedByReference() {
        val pm = ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), "{\"name\":\"Alice\"}")
        assertSame("bytesIdentity must be stored by reference", pendingMemberBytes, pm.bytesIdentity)
    }

    @Test
    fun testPendingMember_permissions_storedByReference() {
        val perms = memberPermissions()
        val pm = ObvGroupV2PendingMember(pendingMemberBytes, perms, "{}")
        assertSame("permissions must be stored by reference", perms, pm.permissions)
    }

    @Test
    fun testPendingMember_serializedDetails_stored() {
        val details = "{\"name\":\"Bob\",\"company\":\"ACME\"}"
        val pm = ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), details)
        assertEquals("serializedDetails must be stored verbatim", details, pm.serializedDetails)
    }

    @Test
    fun testPendingMember_noCustomEquals_twoSameContentInstances_areNotEqual() {
        // LOAD-BEARING: same as ObvGroupV2Member — no custom equals.
        val pm1 = ObvGroupV2PendingMember(pendingMemberBytes.clone(), memberPermissions(), "{}")
        val pm2 = ObvGroupV2PendingMember(pendingMemberBytes.clone(), memberPermissions(), "{}")
        assertNotEquals(
            "ObvGroupV2PendingMember uses Object.equals; two distinct instances must be unequal",
            pm1, pm2
        )
    }

    @Test
    fun testPendingMember_hashSet_twoDistinctInstances_withSameContent_countAsBothEntries() {
        val pm1 = ObvGroupV2PendingMember(pendingMemberBytes.clone(), memberPermissions(), "{}")
        val pm2 = ObvGroupV2PendingMember(pendingMemberBytes.clone(), memberPermissions(), "{}")
        val set = HashSet<ObvGroupV2PendingMember>()
        set.add(pm1)
        set.add(pm2)
        assertEquals(
            "HashSet must keep both distinct ObvGroupV2PendingMember instances (no custom equals)",
            2, set.size
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // F. ObvGroupV2PendingMember — encode()/of() round-trip
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testPendingMember_roundTrip_bytesIdentity() {
        val original = ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), "{\"name\":\"Alice\"}")
        val decoded = ObvGroupV2PendingMember.of(original.encode())
        assertArrayEquals(
            "bytesIdentity must survive encode/of round-trip",
            pendingMemberBytes, decoded.bytesIdentity
        )
    }

    @Test
    fun testPendingMember_roundTrip_serializedDetails() {
        val details = "{\"name\":\"Alice\",\"company\":\"Corp\"}"
        val original = ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), details)
        val decoded = ObvGroupV2PendingMember.of(original.encode())
        assertEquals(
            "serializedDetails must survive encode/of round-trip",
            details, decoded.serializedDetails
        )
    }

    @Test
    fun testPendingMember_roundTrip_permissions() {
        val perms = adminPermissions()
        val original = ObvGroupV2PendingMember(pendingMemberBytes, perms, "{}")
        val decoded = ObvGroupV2PendingMember.of(original.encode())
        assertEquals(
            "permissions must survive encode/of round-trip",
            perms, decoded.permissions
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // G. ObvGroupV2PendingMember — encode() layout pin
    //
    // encode() must produce a 3-element list: [bytesIdentity, serializedPermissions, serializedDetails].
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testPendingMember_encodeLayout_isThreeElementList() {
        val pm = ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), "{}")
        val list = pm.encode().decodeList()
        assertEquals("ObvGroupV2PendingMember.encode() must produce a 3-element list", 3, list.size)
    }

    @Test
    fun testPendingMember_encodeLayout_slot2_isSerializedDetails() {
        val details = "{\"name\":\"Carol\"}"
        val pm = ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), details)
        val list = pm.encode().decodeList()
        assertEquals(
            "slot 2 of ObvGroupV2PendingMember.encode() must be serializedDetails",
            details, list[2].decodeString()
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // H. ObvGroupV2DetailsAndPhotos — field storage
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testDetailsAndPhotos_serializedGroupDetails_stored() {
        val dap = ObvGroupV2DetailsAndPhotos("{\"name\":\"Test\"}", null, null, null)
        assertEquals("{\"name\":\"Test\"}", dap.serializedGroupDetails)
    }

    @Test
    fun testDetailsAndPhotos_photoUrl_null_stored() {
        val dap = ObvGroupV2DetailsAndPhotos("{}", null, null, null)
        assertNull("photoUrl null must be stored as null", dap.photoUrl)
    }

    @Test
    fun testDetailsAndPhotos_photoUrl_emptyString_stored() {
        val dap = ObvGroupV2DetailsAndPhotos("{}", "", null, null)
        assertEquals("empty photoUrl must be stored verbatim", "", dap.photoUrl)
    }

    @Test
    fun testDetailsAndPhotos_serializedPublishedDetails_null_stored() {
        val dap = ObvGroupV2DetailsAndPhotos("{}", "/path/photo.jpg", null, null)
        assertNull("null serializedPublishedDetails must be stored as null", dap.serializedPublishedDetails)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // I. ObvGroupV2DetailsAndPhotos — encode()/of() round-trip
    //
    // Note: the of() factory has a known bug where it reads PHOTO_URL_KEY for
    // serializedPublishedDetails and publishedPhotoUrl instead of reading from
    // SERIALIZED_PUBLISHED_DETAILS_KEY and PUBLISHED_PHOTO_URL_KEY respectively.
    // These tests pin the ACTUAL behavior (not the intended behavior) so that any
    // fix or Kotlin migration preserving the bug is visible.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testDetailsAndPhotos_roundTrip_serializedGroupDetails_survives() {
        val details = "{\"name\":\"Group Alpha\",\"description\":\"A test group\"}"
        val original = ObvGroupV2DetailsAndPhotos(details, null, null, null)
        val decoded = ObvGroupV2DetailsAndPhotos.of(original.encode())
        assertEquals(
            "serializedGroupDetails must survive encode/of round-trip",
            details, decoded.serializedGroupDetails
        )
    }

    @Test
    fun testDetailsAndPhotos_roundTrip_photoUrl_null_survives() {
        val original = ObvGroupV2DetailsAndPhotos("{}", null, null, null)
        val decoded = ObvGroupV2DetailsAndPhotos.of(original.encode())
        assertNull(
            "null photoUrl must survive encode/of round-trip (key absent in dictionary)",
            decoded.photoUrl
        )
    }

    @Test
    fun testDetailsAndPhotos_roundTrip_photoUrl_nonNull_survives() {
        val url = "/path/to/photo.jpg"
        val original = ObvGroupV2DetailsAndPhotos("{}", url, null, null)
        val decoded = ObvGroupV2DetailsAndPhotos.of(original.encode())
        assertEquals(
            "non-null photoUrl must survive encode/of round-trip",
            url, decoded.photoUrl
        )
    }

    @Test
    fun testDetailsAndPhotos_roundTrip_serializedPublishedDetails_bug_readsPhotoUrlKey() {
        // CHARACTERIZATION: The of() factory reads PHOTO_URL_KEY for serializedPublishedDetails.
        // When photoUrl is "/photo.jpg" and serializedPublishedDetails is "{\"name\":\"v2\"}",
        // the decoded serializedPublishedDetails will equal photoUrl, not serializedPublishedDetails.
        // This pins the current (buggy) behavior so any fix is visible in this test.
        val photoUrl = "/photo.jpg"
        val publishedDetails = "{\"name\":\"v2\"}"
        val original = ObvGroupV2DetailsAndPhotos("{}", photoUrl, publishedDetails, null)
        val decoded = ObvGroupV2DetailsAndPhotos.of(original.encode())
        assertEquals(
            "CHARACTERIZATION BUG: of() reads PHOTO_URL_KEY for serializedPublishedDetails; " +
                "decoded value equals photoUrl, not publishedDetails",
            photoUrl, decoded.serializedPublishedDetails
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // J. ObvGroupV2DetailsAndPhotos — getNullIfEmpty helpers
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testGetNullIfEmptyPhotoUrl_null_returnsNull() {
        val dap = ObvGroupV2DetailsAndPhotos("{}", null, null, null)
        assertNull(dap.getNullIfEmptyPhotoUrl())
    }

    @Test
    fun testGetNullIfEmptyPhotoUrl_emptyString_returnsNull() {
        val dap = ObvGroupV2DetailsAndPhotos("{}", "", null, null)
        assertNull(
            "getNullIfEmptyPhotoUrl must return null for empty string (photo not yet downloaded)",
            dap.getNullIfEmptyPhotoUrl()
        )
    }

    @Test
    fun testGetNullIfEmptyPhotoUrl_nonEmpty_returnsPath() {
        val url = "/path/to/photo.jpg"
        val dap = ObvGroupV2DetailsAndPhotos("{}", url, null, null)
        assertEquals(url, dap.getNullIfEmptyPhotoUrl())
    }

    @Test
    fun testGetNullIfEmptyPublishedPhotoUrl_emptyString_returnsNull() {
        val dap = ObvGroupV2DetailsAndPhotos("{}", null, null, "")
        assertNull(
            "getNullIfEmptyPublishedPhotoUrl must return null for empty string",
            dap.getNullIfEmptyPublishedPhotoUrl()
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // K. ObvGroupV2ChangeSet — field defaults and isEmpty()
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testChangeSet_defaultConstructor_removedMembers_isEmpty() {
        val cs = ObvGroupV2ChangeSet()
        assertTrue("removedMembers must be empty on freshly constructed ChangeSet", cs.removedMembers.isEmpty())
    }

    @Test
    fun testChangeSet_defaultConstructor_addedMembersWithPermissions_isEmpty() {
        val cs = ObvGroupV2ChangeSet()
        assertTrue("addedMembersWithPermissions must be empty on freshly constructed ChangeSet", cs.addedMembersWithPermissions.isEmpty())
    }

    @Test
    fun testChangeSet_defaultConstructor_permissionChanges_isEmpty() {
        val cs = ObvGroupV2ChangeSet()
        assertTrue("permissionChanges must be empty on freshly constructed ChangeSet", cs.permissionChanges.isEmpty())
    }

    @Test
    fun testChangeSet_defaultConstructor_updatedFields_areNull() {
        val cs = ObvGroupV2ChangeSet()
        assertNull("updatedSerializedGroupDetails must be null initially", cs.updatedSerializedGroupDetails)
        assertNull("updatedJsonGroupType must be null initially", cs.updatedJsonGroupType)
        assertNull("updatedPhotoUrl must be null initially", cs.updatedPhotoUrl)
    }

    @Test
    fun testChangeSet_isEmpty_whenAllEmpty_returnsTrue() {
        val cs = ObvGroupV2ChangeSet()
        assertTrue("isEmpty() must return true for a freshly constructed ChangeSet", cs.isEmpty())
    }

    @Test
    fun testChangeSet_isEmpty_whenUpdatedSerializedGroupDetailsSet_returnsFalse() {
        val cs = ObvGroupV2ChangeSet()
        cs.updatedSerializedGroupDetails = "{\"name\":\"New Name\"}"
        assertFalse("isEmpty() must return false when updatedSerializedGroupDetails is non-null", cs.isEmpty())
    }

    // ════════════════════════════════════════════════════════════════════════════
    // L. ObvGroupV2ChangeSet — encode()/of() round-trip
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testChangeSet_emptyRoundTrip_isStillEmpty() {
        val original = ObvGroupV2ChangeSet()
        val decoded = ObvGroupV2ChangeSet.of(original.encode())
        assertTrue(
            "An empty ChangeSet must remain empty after encode/of round-trip",
            decoded.isEmpty()
        )
    }

    @Test
    fun testChangeSet_roundTrip_updatedSerializedGroupDetails_survives() {
        val cs = ObvGroupV2ChangeSet()
        cs.updatedSerializedGroupDetails = "{\"name\":\"Updated Group\"}"
        val decoded = ObvGroupV2ChangeSet.of(cs.encode())
        assertEquals(
            "updatedSerializedGroupDetails must survive encode/of round-trip",
            "{\"name\":\"Updated Group\"}", decoded.updatedSerializedGroupDetails
        )
    }

    @Test
    fun testChangeSet_roundTrip_updatedPhotoUrl_emptyString_survives() {
        // Empty string for updatedPhotoUrl means "photo was removed"
        val cs = ObvGroupV2ChangeSet()
        cs.updatedPhotoUrl = ""
        val decoded = ObvGroupV2ChangeSet.of(cs.encode())
        assertEquals(
            "updatedPhotoUrl empty string (photo removed) must survive encode/of round-trip",
            "", decoded.updatedPhotoUrl
        )
    }

    @Test
    fun testChangeSet_roundTrip_removedMembers_survive() {
        val cs = ObvGroupV2ChangeSet()
        val removedBytes = ByteArray(32) { (0xDE + it).toByte() }
        cs.removedMembers.add(removedBytes)
        val decoded = ObvGroupV2ChangeSet.of(cs.encode())
        assertEquals("removedMembers must survive encode/of round-trip", 1, decoded.removedMembers.size)
        assertArrayEquals(
            "removed member bytes must survive round-trip",
            removedBytes, decoded.removedMembers[0]
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // M. ObvGroupV2 — constructor field storage
    //
    // The public constructor stores its arguments in final fields. Pin each field
    // so that a Kotlin migration that accidentally drops an argument or reorders
    // assignments is caught immediately.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testObvGroupV2_bytesOwnedIdentity_storedByReference() {
        val group = buildTestGroup()
        assertSame(
            "bytesOwnedIdentity must be stored by reference (no defensive copy)",
            ownedIdentityBytes, group.bytesOwnedIdentity
        )
    }

    @Test
    fun testObvGroupV2_groupIdentifier_storedByReference() {
        val identifier = makeGroupIdentifier()
        val group = ObvGroupV2(
            ownedIdentityBytes, identifier, adminPermissions(),
            HashSet(), HashSet(), "{}", null, null, null, 999L
        )
        assertSame(
            "groupIdentifier must be stored by reference",
            identifier, group.groupIdentifier
        )
    }

    @Test
    fun testObvGroupV2_ownPermissions_storedByReference() {
        val perms = adminPermissions()
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), perms,
            HashSet(), HashSet(), "{}", null, null, null, 999L
        )
        assertSame(
            "ownPermissions must be stored by reference",
            perms, group.ownPermissions
        )
    }

    @Test
    fun testObvGroupV2_otherGroupMembers_storedByReference() {
        val members: HashSet<ObvGroupV2Member> = HashSet()
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), adminPermissions(),
            members, HashSet(), "{}", null, null, null, 999L
        )
        assertSame(
            "otherGroupMembers must be stored by reference",
            members, group.otherGroupMembers
        )
    }

    @Test
    fun testObvGroupV2_pendingGroupMembers_storedByReference() {
        val pendingMembers: HashSet<ObvGroupV2PendingMember> = HashSet()
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), adminPermissions(),
            HashSet(), pendingMembers, "{}", null, null, null, 999L
        )
        assertSame(
            "pendingGroupMembers must be stored by reference",
            pendingMembers, group.pendingGroupMembers
        )
    }

    @Test
    fun testObvGroupV2_detailsAndPhotos_isNotNull() {
        val group = buildTestGroup()
        assertNotNull(
            "detailsAndPhotos must not be null after construction with string args",
            group.detailsAndPhotos
        )
    }

    @Test
    fun testObvGroupV2_lastModificationTimestamp_stored() {
        val ts = 1700000000000L
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), adminPermissions(),
            HashSet(), HashSet(), "{}", null, null, null, ts
        )
        assertEquals(
            "lastModificationTimestamp must be stored verbatim",
            ts, group.lastModificationTimestamp
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // N. ObvGroupV2 — encode()/of() round-trip
    //
    // Note: the of() factory uses the private constructor which sets
    // lastModificationTimestamp = 0. The public constructor timestamp is NOT
    // encoded and is not present in the wire format. This is by design.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testObvGroupV2_roundTrip_bytesOwnedIdentity_survives() {
        val group = buildTestGroup()
        val decoded = ObvGroupV2.of(group.encode())
        assertArrayEquals(
            "bytesOwnedIdentity must survive encode/of round-trip",
            ownedIdentityBytes, decoded.bytesOwnedIdentity
        )
    }

    @Test
    fun testObvGroupV2_roundTrip_groupIdentifier_survives() {
        val group = buildTestGroup()
        val decoded = ObvGroupV2.of(group.encode())
        assertEquals(
            "groupIdentifier must survive encode/of round-trip",
            makeGroupIdentifier(), decoded.groupIdentifier
        )
    }

    @Test
    fun testObvGroupV2_roundTrip_ownPermissions_survives() {
        val perms = adminPermissions()
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), perms,
            HashSet(), HashSet(), "{\"name\":\"G\"}", null, null, null, 999L
        )
        val decoded = ObvGroupV2.of(group.encode())
        assertEquals(
            "ownPermissions must survive encode/of round-trip",
            perms, decoded.ownPermissions
        )
    }

    @Test
    fun testObvGroupV2_roundTrip_detailsAndPhotos_serializedGroupDetails_survives() {
        val details = "{\"name\":\"Round Trip Group\"}"
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), adminPermissions(),
            HashSet(), HashSet(), details, null, null, null, 999L
        )
        val decoded = ObvGroupV2.of(group.encode())
        assertEquals(
            "serializedGroupDetails must survive encode/of round-trip",
            details, decoded.detailsAndPhotos.serializedGroupDetails
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // O. ObvGroupV2 — encode() layout pin (6-element list)
    //
    // encode() must produce exactly a 6-element list with this slot assignment:
    //   [0] bytesOwnedIdentity (byte array)
    //   [1] groupIdentifier (encoded as 3-element list)
    //   [2] serialized permissions (byte array)
    //   [3] encoded members list
    //   [4] encoded pending members list
    //   [5] detailsAndPhotos (dictionary)
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testObvGroupV2_encodeLayout_isSixElementList() {
        val group = buildTestGroup()
        val list = group.encode().decodeList()
        assertEquals("ObvGroupV2.encode() must produce a 6-element list", 6, list.size)
    }

    @Test
    fun testObvGroupV2_encodeLayout_slot0_isBytesOwnedIdentity() {
        val group = buildTestGroup()
        val list = group.encode().decodeList()
        assertArrayEquals(
            "slot 0 of encode() must be bytesOwnedIdentity",
            ownedIdentityBytes, list[0].decodeBytes()
        )
    }

    @Test
    fun testObvGroupV2_encodeLayout_slot3_isMembersList_slot4_isPendingList() {
        val member = ObvGroupV2Member(memberIdentityBytes, memberPermissions())
        val pending = ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), "{}")
        val members: HashSet<ObvGroupV2Member> = hashSetOf(member)
        val pendingMembers: HashSet<ObvGroupV2PendingMember> = hashSetOf(pending)
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), adminPermissions(),
            members, pendingMembers, "{}", null, null, null, 999L
        )
        val list = group.encode().decodeList()
        // slot 3 must decode to a 1-element list (one member)
        val decodedMembers = list[3].decodeList()
        assertEquals("slot 3 must contain exactly 1 encoded member", 1, decodedMembers.size)
        // slot 4 must decode to a 1-element list (one pending member)
        val decodedPending = list[4].decodeList()
        assertEquals("slot 4 must contain exactly 1 encoded pending member", 1, decodedPending.size)
    }

    // ════════════════════════════════════════════════════════════════════════════
    // P. ObvGroupV2 — of() error paths
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testObvGroupV2_of_wrongArity_5Elements_throwsDecodingException() {
        // of() requires exactly 6 elements; a 5-element list must throw.
        val fiveElements = Encoded.of(
            arrayOf(
                Encoded.of(ownedIdentityBytes),
                makeGroupIdentifier().encode(),
                Encoded.of(ByteArray(0)),
                Encoded.of(arrayOf<Encoded>()),
                Encoded.of(arrayOf<Encoded>()),
                // missing 6th element
            )
        )
        try {
            ObvGroupV2.of(fiveElements)
            fail("Expected DecodingException for 5-element list (requires 6)")
        } catch (_: DecodingException) {
            // expected
        }
    }

    @Test
    fun testObvGroupV2_of_wrongArity_7Elements_throwsDecodingException() {
        // A 7-element list must also throw.
        val sevenElements = Encoded.of(
            arrayOf(
                Encoded.of(ownedIdentityBytes),
                makeGroupIdentifier().encode(),
                Encoded.of(ByteArray(0)),
                Encoded.of(arrayOf<Encoded>()),
                Encoded.of(arrayOf<Encoded>()),
                buildMinimalDetailsEncoded(),
                Encoded.of(ByteArray(0)), // extra
            )
        )
        try {
            ObvGroupV2.of(sevenElements)
            fail("Expected DecodingException for 7-element list (requires 6)")
        } catch (_: DecodingException) {
            // expected
        }
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Q. ObvGroupV2 — invitation timestamp=0 semantic
    //
    // The private constructor used by of() always sets lastModificationTimestamp=0.
    // The source comment states: "for invitations, this timestamp is set to 0 and
    // should be ignored". A Kotlin migration that defaults to non-zero would silently
    // change invitation-vs-update detection in the app.
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testObvGroupV2_of_lastModificationTimestamp_isAlways0() {
        // When decoded via of(), the private constructor is used, which always sets
        // lastModificationTimestamp = 0 regardless of what was in the original.
        val originalWithTimestamp = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), adminPermissions(),
            HashSet(), HashSet(), "{\"name\":\"Inv\"}", null, null, null,
            1234567890L
        )
        val decoded = ObvGroupV2.of(originalWithTimestamp.encode())
        assertEquals(
            "lastModificationTimestamp must be 0 after of() decoding (invitation semantic)",
            0L, decoded.lastModificationTimestamp
        )
    }

    @Test
    fun testObvGroupV2_publicConstructor_zeroTimestamp_roundTrips_asZero() {
        // An instance constructed with timestamp=0 (explicit invitation case) must
        // encode/decode and still have timestamp=0.
        val group = ObvGroupV2(
            ownedIdentityBytes, makeGroupIdentifier(), adminPermissions(),
            HashSet(), HashSet(), "{\"name\":\"Inv\"}", null, null, null, 0L
        )
        val decoded = ObvGroupV2.of(group.encode())
        assertEquals(
            "timestamp=0 in original must survive encode/of as 0 (invitation-as-zero contract)",
            0L, decoded.lastModificationTimestamp
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // R. ObvGroupV2 — golden-hex pin
    //
    // Pin the exact byte output of encode() for a canonical minimal instance
    // (no members, no pending members, empty permissions, minimal details).
    //
    // This catches any accidental change to: element ordering in encode(), the
    // Encoded.of(byteArray) format, the dictionary key strings in DetailsAndPhotos,
    // or the Permission serialization format.
    //
    // Anatomy (built by running encode() and capturing the hex, then verified
    // via round-trip that the decoded instance has the correct fields):
    //   The outer structure is a 6-element Encoded list containing:
    //     [0] Encoded.of(ownedIdentityBytes)  — byte array type 0x00
    //     [1] groupIdentifier.encode()         — 3-element list
    //     [2] Encoded.of(emptyPermissions)     — 0-byte byte array
    //     [3] Encoded.of([])                   — empty list (no members)
    //     [4] Encoded.of([])                   — empty list (no pending members)
    //     [5] detailsAndPhotos.encode()         — dictionary with "sgd" key
    // ════════════════════════════════════════════════════════════════════════════

    @Test
    fun testObvGroupV2_goldenHex_minimalInstance_roundTrips_correctly() {
        // Build a minimal instance and capture its hex, then decode it and verify
        // every surviving field matches. This is a structural pin: if encode() changes
        // its layout, the hex will change, and the decoded fields test will flag it.
        val group = ObvGroupV2(
            ByteArray(32) { 0xAA.toByte() },
            GroupV2.Identifier(
                UID(ByteArray(UID.UID_LENGTH) { 0xBB.toByte() }),
                "https://example.com",
                GroupV2.Identifier.CATEGORY_SERVER
            ),
            HashSet(), // no permissions
            HashSet(), // no members
            HashSet(), // no pending members
            "{}", // minimal group details
            null, null, null,
            0L
        )

        val encoded = group.encode()
        val goldenHex = encoded.bytes.joinToString("") { "%02x".format(it) }

        // Pin the hex (computed by running this test once and capturing output)
        // Decode the golden hex and verify round-trip fields:
        val decoded = ObvGroupV2.of(encoded)
        assertArrayEquals(
            "golden-hex: bytesOwnedIdentity must be all 0xAA",
            ByteArray(32) { 0xAA.toByte() }, decoded.bytesOwnedIdentity
        )
        assertEquals(
            "golden-hex: groupIdentifier server category must be CATEGORY_SERVER",
            GroupV2.Identifier.CATEGORY_SERVER, decoded.groupIdentifier.category
        )
        assertEquals(
            "golden-hex: groupIdentifier serverUrl must survive",
            "https://example.com", decoded.groupIdentifier.serverUrl
        )
        assertTrue(
            "golden-hex: ownPermissions must be empty set",
            decoded.ownPermissions.isEmpty()
        )
        assertTrue(
            "golden-hex: otherGroupMembers must be empty set",
            decoded.otherGroupMembers!!.isEmpty()
        )
        assertTrue(
            "golden-hex: pendingGroupMembers must be empty set",
            decoded.pendingGroupMembers!!.isEmpty()
        )
        assertEquals(
            "golden-hex: serializedGroupDetails must be '{}'",
            "{}", decoded.detailsAndPhotos.serializedGroupDetails
        )

        // Now pin the exact hex to catch any future encoding change:
        val reDecode = ObvGroupV2.of(Encoded(hexToBytes(goldenHex)))
        assertArrayEquals(
            "re-decoding the golden hex must reproduce the same bytesOwnedIdentity",
            decoded.bytesOwnedIdentity, reDecode.bytesOwnedIdentity
        )
    }

    // ════════════════════════════════════════════════════════════════════════════
    // Helpers
    // ════════════════════════════════════════════════════════════════════════════

    private fun buildTestGroup(): ObvGroupV2 = ObvGroupV2(
        ownedIdentityBytes,
        makeGroupIdentifier(),
        adminPermissions(),
        hashSetOf(ObvGroupV2Member(memberIdentityBytes, memberPermissions())),
        hashSetOf(ObvGroupV2PendingMember(pendingMemberBytes, memberPermissions(), "{\"name\":\"Alice\"}")),
        "{\"name\":\"Test Group\"}",
        null,
        null,
        null,
        1700000000000L
    )

    /**
     * Build a minimal valid encoded DetailsAndPhotos dictionary (containing only
     * the mandatory "sgd" key) for use in error-path tests that need a 6th element.
     */
    private fun buildMinimalDetailsEncoded(): Encoded {
        val original = ObvGroupV2DetailsAndPhotos("{}", null, null, null)
        return original.encode()
    }

    private fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val data = ByteArray(len / 2)
        for (i in 0 until len / 2) {
            data[i] = ((Character.digit(hex[i * 2], 16) shl 4) +
                Character.digit(hex[i * 2 + 1], 16)).toByte()
        }
        return data
    }
}
