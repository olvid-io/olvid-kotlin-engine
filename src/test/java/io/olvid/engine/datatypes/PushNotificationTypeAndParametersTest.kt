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

package io.olvid.engine.datatypes

import org.junit.Assert.*
import org.junit.Test

class PushNotificationTypeAndParametersTest {

    @Test
    fun testFactoriesAndConstructors() {
        val identityMaskingUid = UID.fromLong(12345L)
        val deviceUidToReplace = UID.fromLong(67890L)
        val token = byteArrayOf(1, 2, 3)

        // Web websocket only android
        val wsAndroid = PushNotificationTypeAndParameters.createWebsocketOnlyAndroid(true, deviceUidToReplace)
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID, wsAndroid.pushNotificationType)
        assertNull(wsAndroid.token)
        assertNull(wsAndroid.identityMaskingUid)
        assertTrue(wsAndroid.reactivateCurrentDevice)
        assertEquals(deviceUidToReplace, wsAndroid.deviceUidToReplace)

        // Windows
        val wsWindows = PushNotificationTypeAndParameters.createWindows(false, null)
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS, wsWindows.pushNotificationType)
        assertNull(wsWindows.token)
        assertNull(wsWindows.identityMaskingUid)
        assertFalse(wsWindows.reactivateCurrentDevice)
        assertNull(wsWindows.deviceUidToReplace)

        // Linux
        val wsLinux = PushNotificationTypeAndParameters.createLinux(true, deviceUidToReplace)
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX, wsLinux.pushNotificationType)
        assertNull(wsLinux.token)
        assertNull(wsLinux.identityMaskingUid)
        assertTrue(wsLinux.reactivateCurrentDevice)
        assertEquals(deviceUidToReplace, wsLinux.deviceUidToReplace)

        // Daemon
        val wsDaemon = PushNotificationTypeAndParameters.createDaemon(false, null)
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON, wsDaemon.pushNotificationType)
        assertNull(wsDaemon.token)
        assertNull(wsDaemon.identityMaskingUid)
        assertFalse(wsDaemon.reactivateCurrentDevice)
        assertNull(wsDaemon.deviceUidToReplace)

        // Firebase Android
        val firebaseAndroid = PushNotificationTypeAndParameters.createFirebaseAndroid(token, identityMaskingUid, true, deviceUidToReplace)
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_ANDROID, firebaseAndroid.pushNotificationType)
        assertArrayEquals(token, firebaseAndroid.token)
        assertEquals(identityMaskingUid, firebaseAndroid.identityMaskingUid)
        assertTrue(firebaseAndroid.reactivateCurrentDevice)
        assertEquals(deviceUidToReplace, firebaseAndroid.deviceUidToReplace)
    }

    @Test
    fun testSameTypeAndToken() {
        val token1 = byteArrayOf(1, 2, 3)
        val token2 = byteArrayOf(1, 2, 3)
        val token3 = byteArrayOf(4, 5, 6)

        val deviceUid = UID.fromLong(1L)
        val maskUid = UID.fromLong(2L)

        val firebase1 = PushNotificationTypeAndParameters.createFirebaseAndroid(token1, maskUid, true, deviceUid)
        val firebase2 = PushNotificationTypeAndParameters.createFirebaseAndroid(token2, maskUid, false, null)
        val firebase3 = PushNotificationTypeAndParameters.createFirebaseAndroid(token3, maskUid, true, deviceUid)

        // Same type and token for Android
        assertTrue(firebase1.sameTypeAndToken(firebase2))
        // Same type but different token
        assertFalse(firebase1.sameTypeAndToken(firebase3))

        // Websocket types compared with themselves
        val wsAndroid1 = PushNotificationTypeAndParameters.createWebsocketOnlyAndroid(true, deviceUid)
        val wsAndroid2 = PushNotificationTypeAndParameters.createWebsocketOnlyAndroid(false, null)
        assertTrue(wsAndroid1.sameTypeAndToken(wsAndroid2))

        val wsWindows1 = PushNotificationTypeAndParameters.createWindows(true, deviceUid)
        val wsWindows2 = PushNotificationTypeAndParameters.createWindows(false, null)
        assertTrue(wsWindows1.sameTypeAndToken(wsWindows2))

        val wsLinux1 = PushNotificationTypeAndParameters.createLinux(true, deviceUid)
        val wsLinux2 = PushNotificationTypeAndParameters.createLinux(false, null)
        assertTrue(wsLinux1.sameTypeAndToken(wsLinux2))

        val wsDaemon1 = PushNotificationTypeAndParameters.createDaemon(true, deviceUid)
        val wsDaemon2 = PushNotificationTypeAndParameters.createDaemon(false, null)
        assertTrue(wsDaemon1.sameTypeAndToken(wsDaemon2))

        // Different types
        assertFalse(wsAndroid1.sameTypeAndToken(wsWindows1))
        assertFalse(firebase1.sameTypeAndToken(wsAndroid1))

        // Null comparison check
        assertFalse(firebase1.sameTypeAndToken(null))

        // Default / Unknown types
        val unknownType1 = PushNotificationTypeAndParameters(0x99.toByte(), null, null, false, null)
        val unknownType2 = PushNotificationTypeAndParameters(0x99.toByte(), null, null, false, null)
        assertFalse(unknownType1.sameTypeAndToken(unknownType2))
    }

    @Test
    fun testJavaStaticDelegation() {
        val clazz = PushNotificationTypeAndParameters::class.java
        
        val createWebsocketOnlyAndroidMethod = clazz.getMethod("createWebsocketOnlyAndroid", Boolean::class.javaPrimitiveType, UID::class.java)
        val wsAndroid = createWebsocketOnlyAndroidMethod.invoke(null, true, null) as PushNotificationTypeAndParameters
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_ANDROID, wsAndroid.pushNotificationType)

        val createWindowsMethod = clazz.getMethod("createWindows", Boolean::class.javaPrimitiveType, UID::class.java)
        val wsWindows = createWindowsMethod.invoke(null, false, null) as PushNotificationTypeAndParameters
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_WINDOWS, wsWindows.pushNotificationType)

        val createLinuxMethod = clazz.getMethod("createLinux", Boolean::class.javaPrimitiveType, UID::class.java)
        val wsLinux = createLinuxMethod.invoke(null, true, null) as PushNotificationTypeAndParameters
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_LINUX, wsLinux.pushNotificationType)

        val createDaemonMethod = clazz.getMethod("createDaemon", Boolean::class.javaPrimitiveType, UID::class.java)
        val wsDaemon = createDaemonMethod.invoke(null, false, null) as PushNotificationTypeAndParameters
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_WEBSOCKET_DAEMON, wsDaemon.pushNotificationType)

        val createFirebaseAndroidMethod = clazz.getMethod("createFirebaseAndroid", ByteArray::class.java, UID::class.java, Boolean::class.javaPrimitiveType, UID::class.java)
        val token = byteArrayOf(9)
        val firebase = createFirebaseAndroidMethod.invoke(null, token, null, true, null) as PushNotificationTypeAndParameters
        assertEquals(PushNotificationTypeAndParameters.PUSH_NOTIFICATION_TYPE_ANDROID, firebase.pushNotificationType)
    }
}
