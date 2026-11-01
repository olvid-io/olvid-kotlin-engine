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
package io.olvid.engine.identity.databases

import io.olvid.engine.Logger
import io.olvid.engine.crypto.Suite
import io.olvid.engine.datatypes.Constants
import io.olvid.engine.datatypes.Identity
import io.olvid.engine.datatypes.Seed
import io.olvid.engine.datatypes.Session
import io.olvid.engine.datatypes.UID
import io.olvid.engine.datatypes.containers.GroupV2
import io.olvid.engine.datatypes.containers.UserData
import io.olvid.engine.datatypes.key.asymmetric.EncryptionEciesCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.EncryptionPublicKey
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationECSdsaCurve25519KeyPair
import io.olvid.engine.datatypes.key.asymmetric.ServerAuthenticationPublicKey
import io.olvid.engine.datatypes.key.symmetric.AuthEncKey
import io.olvid.engine.datatypes.notifications.IdentityNotifications
import io.olvid.engine.engine.types.sync.ObvSyncAtom.DiscussionIdentifier
import io.olvid.engine.identity.databases.sync.CustomPhotoSyncSnapshot
import io.olvid.engine.identity.datatypes.IdentityManagerSession
import io.olvid.engine.metamanager.NotificationPostingDelegate
import io.olvid.engine.storage.PlainFileIo
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files

/**
 * Tests of the [CustomPhoto] table on a real (temporary) SQLite database and engine directory.
 */
class CustomPhotoTest {
    private lateinit var dbFile: File
    private lateinit var baseDirectory: File
    private lateinit var session: Session
    private lateinit var identityManagerSession: IdentityManagerSession
    private val postedNotifications = ArrayList<Pair<String, Map<String, Any>>>()

    private lateinit var ownedIdentity: Identity
    private lateinit var contactTarget: DiscussionIdentifier
    private lateinit var key: AuthEncKey
    private lateinit var serverPhotoInfo: GroupV2.ServerPhotoInfo
    private val label = UID(ByteArray(UID.UID_LENGTH) { 3 })
    private val photoBytes = ByteArray(1000) { it.toByte() }

    @Before
    fun setUp() {
        Logger.setOutputter(object : Logger.LogOutputter {
            override fun d(tag: String, message: String) {}
            override fun i(tag: String, message: String) {}
            override fun w(tag: String, message: String) {}
            override fun e(tag: String, message: String) {}
            override fun x(tag: String, throwable: Throwable) {}
        })

        val prng = Suite.getDefaultPRNGService(0)
        prng.reseed(Seed(ByteArray(32)))
        ownedIdentity = Identity(
            "test.olvid.io",
            ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng).publicKey as ServerAuthenticationPublicKey,
            EncryptionEciesCurve25519KeyPair.generate(prng).publicKey as EncryptionPublicKey,
        )
        val contactIdentity = Identity(
            "test.olvid.io",
            ServerAuthenticationECSdsaCurve25519KeyPair.generate(prng).publicKey as ServerAuthenticationPublicKey,
            EncryptionEciesCurve25519KeyPair.generate(prng).publicKey as EncryptionPublicKey,
        )
        contactTarget = DiscussionIdentifier(DiscussionIdentifier.CONTACT, contactIdentity.getBytes())
        key = Suite.getDefaultAuthEnc(0).generateKey(prng) as AuthEncKey
        serverPhotoInfo = GroupV2.ServerPhotoInfo(ownedIdentity, label, key)

        dbFile = File.createTempFile("custom_photo_test_", ".sqlite")
        baseDirectory = Files.createTempDirectory("custom_photo_test_").toFile()
        File(baseDirectory, Constants.IDENTITY_PHOTOS_DIRECTORY).mkdir()
        session = Session.getSession(dbFile.absolutePath, null)
        val notificationPostingDelegate = object : NotificationPostingDelegate {
            override fun postNotification(notificationName: String, userInfo: Map<String, Any>) {
                postedNotifications.add(Pair(notificationName, userInfo))
            }
        }
        identityManagerSession = IdentityManagerSession(session, notificationPostingDelegate, null, baseDirectory.absolutePath, PlainFileIo(), null, null)

        ServerUserData.createTable(session)
        CustomPhoto.createTable(session)
    }

    @After
    fun tearDown() {
        try { session.close() } catch (_: Exception) {}
        dbFile.delete()
        baseDirectory.deleteRecursively()
    }

    private fun localPhoto(): File {
        val file = File(baseDirectory, "app_photo.jpg")
        file.writeBytes(photoBytes)
        return file
    }

    @Test
    fun createFromLocalPhoto_copiesThePhotoAndRegistersItsServerUserData() {
        val source = localPhoto()
        val customPhoto = CustomPhoto.createFromLocalPhoto(identityManagerSession, ownedIdentity, contactTarget, serverPhotoInfo, source.absolutePath)

        // the engine keeps its own copy: the app may delete or move its file
        source.delete()
        assertArrayEquals(photoBytes, File(baseDirectory, customPhoto.photoUrl!!).readBytes())

        val userData = ServerUserData.get(identityManagerSession, ownedIdentity, label)!!.userData!!
        assertEquals(UserData.Type.CUSTOM_PHOTO, userData.type)
        val expectedRefresh = System.currentTimeMillis() + Constants.CUSTOM_PHOTO_USER_DATA_REFRESH_INTERVAL
        assertTrue(Math.abs(userData.nextRefreshTimestamp - expectedRefresh) < 60_000)

        assertEquals(serverPhotoInfo, CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.serverPhotoInfo)
        assertEquals(customPhoto.photoUrl, CustomPhoto.getByLabel(identityManagerSession, ownedIdentity, label)!!.photoUrl)
    }

    @Test
    fun createToDownload_thenDownloaded_notifiesTheAppAfterCommit() {
        session.startTransaction()
        val customPhoto = CustomPhoto.createToDownload(identityManagerSession, ownedIdentity, contactTarget, serverPhotoInfo)
        assertNull(customPhoto.photoUrl)
        assertEquals(1, CustomPhoto.getAllWithMissingPhotoUrl(identityManagerSession).size)
        assertNotNull(ServerUserData.get(identityManagerSession, ownedIdentity, label))

        customPhoto.setDownloadedPhoto(photoBytes)
        assertTrue(postedNotifications.isEmpty())
        session.commit()

        assertTrue(CustomPhoto.getAllWithMissingPhotoUrl(identityManagerSession).isEmpty())
        val photoUrl = CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.photoUrl!!
        assertArrayEquals(photoBytes, File(baseDirectory, photoUrl).readBytes())
        assertEquals(listOf(photoUrl), CustomPhoto.getAllPhotoUrl(identityManagerSession))

        val (name, userInfo) = postedNotifications.single()
        assertEquals(IdentityNotifications.NOTIFICATION_CUSTOM_PHOTO_UPDATED, name)
        val target = userInfo[IdentityNotifications.NOTIFICATION_CUSTOM_PHOTO_UPDATED_TARGET_KEY] as DiscussionIdentifier
        assertArrayEquals(contactTarget.bytesDiscussionIdentifier, target.bytesDiscussionIdentifier)
    }

    @Test
    fun deleteAndReleaseServerCopy_releasesTheLabelAndNotifiesTheApp() {
        CustomPhoto.createFromLocalPhoto(identityManagerSession, ownedIdentity, contactTarget, serverPhotoInfo, localPhoto().absolutePath)

        session.startTransaction()
        CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.deleteAndReleaseServerCopy(true)
        session.commit()

        assertNull(CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget))
        assertNull(ServerUserData.get(identityManagerSession, ownedIdentity, label))

        val notifications = postedNotifications.associate { it.first to it.second }
        assertEquals(label, notifications[IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED]!![IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED_LABEL_KEY])
        assertTrue(notifications.containsKey(IdentityNotifications.NOTIFICATION_CUSTOM_PHOTO_UPDATED))
    }

    @Test
    fun hidden_hasNothingToUploadOrDownload() {
        session.startTransaction()
        val hidden = CustomPhoto.createHidden(identityManagerSession, ownedIdentity, contactTarget, true)
        session.commit()

        assertTrue(hidden.isHidden)
        assertNull(hidden.serverPhotoInfo)
        assertTrue(CustomPhoto.getAllWithMissingPhotoUrl(identityManagerSession).isEmpty())
        assertTrue(CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.isHidden)
        assertEquals(listOf(IdentityNotifications.NOTIFICATION_CUSTOM_PHOTO_UPDATED), postedNotifications.map { it.first })

        // removing it has no server copy to release
        postedNotifications.clear()
        session.startTransaction()
        CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.deleteAndReleaseServerCopy(false)
        session.commit()
        assertTrue(postedNotifications.isEmpty())
    }

    @Test
    fun syncSnapshot_restoresAHiddenPhoto() {
        CustomPhoto.createHidden(identityManagerSession, ownedIdentity, contactTarget, false)
        val snapshot = CustomPhotoSyncSnapshot.of(identityManagerSession, ownedIdentity, contactTarget)!!
        assertNull(snapshot.photo_server_label)

        CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.delete()
        snapshot.restore(identityManagerSession, ownedIdentity, contactTarget)
        assertTrue(CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.isHidden)
    }

    @Test
    fun deleteAndReleaseServerCopy_withoutNotifyApp_onlyReleasesTheLabel() {
        CustomPhoto.createFromLocalPhoto(identityManagerSession, ownedIdentity, contactTarget, serverPhotoInfo, localPhoto().absolutePath)

        session.startTransaction()
        CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.deleteAndReleaseServerCopy(false)
        session.commit()

        assertEquals(listOf(IdentityNotifications.NOTIFICATION_SERVER_USER_DATA_CAN_BE_DELETED), postedNotifications.map { it.first })
    }

    @Test
    fun syncSnapshot_restoresTheLabelAndKeyForDownload() {
        CustomPhoto.createFromLocalPhoto(identityManagerSession, ownedIdentity, contactTarget, serverPhotoInfo, localPhoto().absolutePath)
        val snapshot = CustomPhotoSyncSnapshot.of(identityManagerSession, ownedIdentity, contactTarget)!!

        // restore on a fresh device
        CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!.delete()
        ServerUserData.get(identityManagerSession, ownedIdentity, label)!!.delete()
        snapshot.restore(identityManagerSession, ownedIdentity, contactTarget)

        val restored = CustomPhoto.get(identityManagerSession, ownedIdentity, contactTarget)!!
        assertEquals(serverPhotoInfo, restored.serverPhotoInfo)
        assertNull(restored.photoUrl)
        assertEquals(UserData.Type.CUSTOM_PHOTO, ServerUserData.get(identityManagerSession, ownedIdentity, label)!!.userData!!.type)
    }

    @Test
    fun syncSnapshot_isNullWithoutCustomPhoto() {
        assertNull(CustomPhotoSyncSnapshot.of(identityManagerSession, ownedIdentity, contactTarget))
    }

    @Test
    fun upgradeFrom53_createsTheTable() {
        val upgradeDbFile = File.createTempFile("custom_photo_upgrade_test_", ".sqlite")
        try {
            Session.getSession(upgradeDbFile.absolutePath, null).use { upgradeSession ->
                CustomPhoto.upgradeTable(upgradeSession, 53, 54)
                upgradeSession.createStatement().use { statement ->
                    statement.executeQuery("SELECT name FROM sqlite_master WHERE type = 'table' AND name = '" + CustomPhoto.TABLE_NAME + "';").use { res ->
                        assertTrue(res.next())
                    }
                }
            }
        } finally {
            upgradeDbFile.delete()
        }
    }
}
