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

package io.olvid.engine.secure_io

import io.olvid.engine.Logger
import io.olvid.engine.crypto.PRNG.Companion.PRNG_HMAC_SHA256
import io.olvid.engine.crypto.Suite
import io.olvid.engine.secure_io.SecureFileOutputStream.AccessMode
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

// Kotlin port of the feature_cipher_solid characterization suite. Runs against the
// (still Java) secure_io impl in phase 1b; will keep passing once the impl is Kotlin.
class SecureFileIOStreamTest {

    private val dataSet = ByteArray(12000)

    // PRNGService.bytes()/bigInt() are nullable in the Kotlin engine but never return null
    // for a valid PRNG; wrap them so the test body stays free of !! noise.
    private fun rngBytes(length: Int): ByteArray =
        Suite.getPRNGService(PRNG_HMAC_SHA256).bytes(length)

    private fun rngBigInt(bound: BigInteger): BigInteger =
        Suite.getPRNGService(PRNG_HMAC_SHA256).bigInt(bound)

    @get:Rule
    val testingFolder = TemporaryFolder()

    @get:Rule
    val secureFileTestingFolder = TemporaryFolder()

    @get:Rule
    val directoryListingTestingFolder = TemporaryFolder()

    init {
        // generate data for non random tests
        val input = rngBytes(12000)
        System.arraycopy(input, 0, dataSet, 0, input.size)
        // create temporary folder
        testingFolder.create()
        testingFolder.newFolder("secure_io_test_folder")
        secureFileTestingFolder.create()
        directoryListingTestingFolder.create()
        KeyManagerSingleton.getInstance().tryToInitKeyManagement("data/security/", "toto")
    }

    /**
     * Security property the File->SecureFile migration exists to provide: content written through
     * SecureFileOutputStream is encrypted at rest. Distinct from the round-trip tests — here we read
     * the raw on-disk (FS-named) bytes directly and assert the plaintext marker never appears.
     */
    @Test
    fun test_data_is_encrypted_at_rest() {
        val marker = "OLVID_SENSITIVE_PLAINTEXT_MARKER_DO_NOT_LEAK"
        val input = marker.repeat(200).toByteArray() // spans multiple payload blocks
        val fileName = rngBytes(32)
        val secureFileWrite = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))
        SecureFileOutputStream(secureFileWrite).use { it.write(input) }

        // read the actual on-disk (FS-named, MAC-named) file bytes, bypassing SecureFile decryption
        val onDisk = File(secureFileWrite.fsNameFile!!.path).readBytes()

        // a full header block is always written
        assertTrue(onDisk.size >= SecureIOHelper.BLOCK_SIZE)
        // the plaintext marker must NOT appear anywhere on disk
        assertFalse(String(onDisk, Charsets.ISO_8859_1).contains(marker))

        // and it still decrypts back to the original plaintext
        val readBack = ByteArray(input.size)
        SecureFileInputStream(SecureFile(testingFolder.root.path, Logger.toHexString(fileName))).use {
            it.read(readBack, 0, input.size)
        }
        assertArrayEquals(input, readBack)
    }

    @Test
    fun test_write_15bytes_to_secure_file() {
        val input = rngBytes(15)
        val fileName = rngBytes(32)
        val secureFileWrite = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val secureFileOutputStream = SecureFileOutputStream(secureFileWrite)
        secureFileOutputStream.write(input)
        secureFileOutputStream.close()
        assertEquals(secureFileOutputStream.secureFileHeader!!.fileSize, input.size.toLong())

        val secureFileRead = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val readBuf = ByteArray(4096)
        val secureFileInputStream = SecureFileInputStream(secureFileRead)
        secureFileInputStream.read(readBuf)

        val result = readBuf.copyOfRange(0, input.size)
        assertArrayEquals(input, result)
    }

    /**
     * Testing to write 10000 bytes into secure file then read them back
     */
    @Test
    fun test_write_10ko_byte_array_to_secure_file() {
        val input = rngBytes(10000)
        val fileName = rngBytes(32)
        val secureFileWrite = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val secureFileOutputStream = SecureFileOutputStream(secureFileWrite)
        secureFileOutputStream.write(input)
        secureFileOutputStream.close()
        // Assert header is consistent with what was written
        assertEquals(secureFileOutputStream.secureFileHeader!!.fileSize, input.size.toLong())

        val secureFileRead = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val readBuf = ByteArray(9000)
        SecureFileInputStream(secureFileRead).use { secureFileInputStream ->
            secureFileInputStream.read(readBuf, 0, 4500)
            secureFileInputStream.read(readBuf, 4500, 4500)
        }

        val result = input.copyOfRange(0, readBuf.size)
        assertArrayEquals(readBuf, result)
    }

    /**
     * Testing to write 12ko bytes in chunks of 3ko into secure file then read them back in one read
     */
    @Test
    fun test_multiple_write_and_read_12ko_byte_array() {
        val fileName = rngBytes(32)
        val secureFileWrite = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val secureFileOutputStream = SecureFileOutputStream(secureFileWrite)
        // write all dataset in chunks of 3ko
        secureFileOutputStream.write(dataSet.copyOfRange(0, 3000))
        secureFileOutputStream.write(dataSet.copyOfRange(3000, 6000))
        secureFileOutputStream.write(dataSet.copyOfRange(6000, 9000))
        secureFileOutputStream.write(dataSet.copyOfRange(9000, 12000))
        secureFileOutputStream.close()
        // Assert header is consistent with what was written
        assertEquals(secureFileOutputStream.secureFileHeader!!.fileSize, dataSet.size.toLong())

        val readBuf = ByteArray(12000)
        val secureFileRead = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        SecureFileInputStream(secureFileRead).use { secureFileInputStream ->
            secureFileInputStream.read(readBuf, 0, 12000)
        }

        val result = dataSet.copyOfRange(0, readBuf.size)
        assertArrayEquals(readBuf, result)
    }

    /**
     * Testing to write 12ko bytes in chunks of 3ko into secure file then read them back
     * manually with arbitrary chunk length
     */
    @Test
    fun test_multiple_write_and_multiple_read_12ko_byte_array() {
        val fileName = rngBytes(32)
        val secureFileWrite = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val secureFileOutputStream = SecureFileOutputStream(secureFileWrite)
        secureFileOutputStream.write(dataSet.copyOfRange(0, 3000))
        secureFileOutputStream.write(dataSet.copyOfRange(3000, 6000))
        secureFileOutputStream.write(dataSet.copyOfRange(6000, 9000))
        secureFileOutputStream.write(dataSet.copyOfRange(9000, 12000))
        secureFileOutputStream.close()
        // Assert header is consistent with what was written
        assertEquals(secureFileOutputStream.secureFileHeader!!.fileSize, dataSet.size.toLong())

        val secureFileRead = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val readBuf = ByteArray(12000)
        SecureFileInputStream(secureFileRead).use { secureFileInputStream ->
            secureFileInputStream.read(readBuf, 0, 10)
            secureFileInputStream.read(readBuf, 10, 10)
            secureFileInputStream.read(readBuf, 20, 13)
            secureFileInputStream.read(readBuf, 33, 16)
            secureFileInputStream.read(readBuf, 49, 2000)
            secureFileInputStream.read(readBuf, 2049, 5000)
            secureFileInputStream.read(readBuf, 7049, 3000)
            secureFileInputStream.read(readBuf, 10049, 3000)
        }
        val result = dataSet.copyOfRange(0, readBuf.size)
        assertArrayEquals(readBuf, result)
    }

    /**
     * Testing to write random number of bytes (100Mo max) one shot into secure file then
     * read them back with random number of read call (max 30) using random length
     */
    @Test
    fun test_random_bytes_one_shot_write_random_read_number() {
        val fileName = rngBytes(32)

        val fileSize = rngBigInt(BigInteger("100000000"))
        val bytesToWrite = rngBytes(fileSize.toInt())
        val secureFileWrite = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val secureFileOutputStream = SecureFileOutputStream(secureFileWrite)
        secureFileOutputStream.write(bytesToWrite)
        secureFileOutputStream.close()
        // Assert header is consistent with what was written
        assertEquals(secureFileOutputStream.secureFileHeader!!.fileSize, bytesToWrite.size.toLong())

        val secureFileRead = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        val readNumber = rngBigInt(BigInteger("30"))
        val readLengthValues = arrayOfNulls<BigInteger>(readNumber.toInt())
        var max = BigInteger(bytesToWrite.size.toString())
        for (i in 0 until readLengthValues.size - 1) {
            readLengthValues[i] = rngBigInt(max)
            max = max.subtract(readLengthValues[i]!!)
        }
        if (max > BigInteger.ZERO && readLengthValues.isNotEmpty()) {
            readLengthValues[readLengthValues.size - 1] = max
        }
        // result
        val resultBuf = ByteArray(bytesToWrite.size)
        var off = 0
        // read loop
        SecureFileInputStream(secureFileRead).use { secureFileInputStream ->
            for (readLengthValue in readLengthValues) {
                secureFileInputStream.read(resultBuf, off, readLengthValue!!.toInt())
                off += readLengthValue.toInt()
            }
        }
        assertArrayEquals(bytesToWrite, resultBuf)
    }

    /**
     * Testing to write random number of bytes (100Mo max) in random number of writes then
     * read them back with random number of read calls using random length
     */
    @Test
    fun test_random_bytes_random_writes_random_read_number() {
        val fileName = rngBytes(32)

        val fileSize = rngBigInt(BigInteger("100000000"))

        // the final byte array output stream that will be filled along the secure file with same bytes
        val bytesToWrite = ByteArrayOutputStream(fileSize.toInt())
        val secureFileWrite = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        // defining a random number of write calls
        val writeNumber = rngBigInt(BigInteger("30"))

        // all the bytes length values that will be written will be stored here
        val writeLengthValues = arrayOfNulls<BigInteger>(writeNumber.toInt())

        var maxBytesWrite = BigInteger(fileSize.toInt().toString())

        // defining length values for every write call, leaving an extra slot for the remainder
        for (i in 0 until writeLengthValues.size - 1) {
            writeLengthValues[i] = rngBigInt(maxBytesWrite)
            maxBytesWrite = maxBytesWrite.subtract(writeLengthValues[i]!!)
        }
        // if we didn't hit the max, assign it to the dedicated last slot
        if (maxBytesWrite > BigInteger.ZERO && writeLengthValues.isNotEmpty()) {
            writeLengthValues[writeLengthValues.size - 1] = maxBytesWrite
        }

        var writeOff = 0
        for (writeLengthValue in writeLengthValues) {
            SecureFileOutputStream(secureFileWrite, AccessMode.TRUNCATE, writeOff.toLong()).use { discreteSecureOutputStream ->
                val toWrite = rngBytes(writeLengthValue!!.toInt())
                bytesToWrite.writeBytes(toWrite)
                discreteSecureOutputStream.write(toWrite)
                writeOff += writeLengthValue.toInt()
            }
        }

        SecureFileOutputStream(secureFileWrite).use { secureFileOutputStream ->
            // Assert header is consistent with what was written
            assertEquals(secureFileOutputStream.secureFileHeader!!.fileSize, bytesToWrite.toByteArray().size.toLong())
        }

        val secureFileRead = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        // same mechanism to generate a random number of read calls with random read length per call
        val readNumber = rngBigInt(BigInteger("30"))

        val readLengthValues = arrayOfNulls<BigInteger>(readNumber.toInt())

        var max = BigInteger(bytesToWrite.toByteArray().size.toString())
        for (i in 0 until readLengthValues.size - 1) {
            readLengthValues[i] = rngBigInt(max)
            max = max.subtract(readLengthValues[i]!!)
        }

        if (max > BigInteger.ZERO && readLengthValues.isNotEmpty()) {
            readLengthValues[readLengthValues.size - 1] = max
        }

        SecureFileInputStream(secureFileRead).use { secureFileInputStream ->
            // result
            val resultBuf = ByteArray(bytesToWrite.toByteArray().size)
            var off = 0
            // read loop
            for (readLengthValue in readLengthValues) {
                secureFileInputStream.read(resultBuf, off, readLengthValue!!.toInt())
                off += readLengthValue.toInt()
            }
            assertArrayEquals(bytesToWrite.toByteArray(), resultBuf)
        }
    }

    /**
     * Testing renameTo() method implemented in SecureFile to move and/or rename SecureFile
     */
    @Test
    fun test_create_and_move_secure_file() {
        secureFileTestingFolder.newFolder("source_dir")
        secureFileTestingFolder.newFolder("dest_dir")

        val input = rngBytes(10000)
        val fileName = "toto.txt"
        val newFileName = "toto1.txt"

        val secureFile = SecureFile(secureFileTestingFolder.root.path + "/source_dir/", fileName)
        SecureFileOutputStream(secureFile).use { secureFileOutputStream ->
            secureFileOutputStream.write(input)
        }
        secureFile.renameTo(secureFileTestingFolder.root.path + "/dest_dir/", newFileName)
        val destSecureFile = SecureFile(secureFileTestingFolder.root.path + "/dest_dir/", newFileName)
        val result = ByteArray(input.size)
        SecureFileInputStream(destSecureFile).use { secureFileInputStream ->
            secureFileInputStream.read(result, 0, 10000)
        }
        assertArrayEquals(input, result)
    }

    /**
     * Testing delete() method implemented in SecureFile
     */
    @Test
    fun test_create_and_delete_file() {
        secureFileTestingFolder.newFolder("source_dir")

        val input = rngBytes(10000)
        val fileName = "toto.txt"
        val secureFile = SecureFile(secureFileTestingFolder.root.path + "/source_dir/", fileName)
        SecureFileOutputStream(secureFile).use { secureFileOutputStream ->
            secureFileOutputStream.write(input)
        }
        secureFile.delete()
        assertFalse(secureFile.exists())
    }

    /**
     * Testing listDirectory() method implemented in SecureFile
     */
    @Test
    fun test_list_directory() {
        val directory = SecureFile(directoryListingTestingFolder.newFolder("directory").absolutePath)

        val input = rngBytes(10000)
        val secureFileCount = rngBigInt(BigInteger("15"))
        val fileCount = rngBigInt(BigInteger("15"))
        val dirCount = rngBigInt(BigInteger("15"))

        val plainSecureFileNames = ArrayList<String>(secureFileCount.toInt())
        val plainFileNames = ArrayList<String>(secureFileCount.toInt())
        val dirNames = ArrayList<String>(secureFileCount.toInt())

        for (i in 0 until secureFileCount.toInt()) {
            val randomFileName = Logger.toHexString(rngBytes(16))
            val secureFile = SecureFile(directory.fsNameFile!!.absolutePath, randomFileName)
            plainSecureFileNames.add(randomFileName)
            SecureFileOutputStream(secureFile).use { secureFileOutputStream ->
                secureFileOutputStream.write(input)
            }
        }

        for (i in 0 until fileCount.toInt()) {
            val randomFileName = Logger.toHexString(rngBytes(16))
            val file = File(directory.fsNameFile!!.absolutePath, randomFileName)
            plainFileNames.add(randomFileName)
            FileOutputStream(file).use { fileOutputStream ->
                fileOutputStream.write(input)
            }
        }

        for (i in 0 until dirCount.toInt()) {
            val dirName = Logger.toHexString(rngBytes(16))
            val file = File(directory.fsNameFile!!.absolutePath, dirName)
            if (file.mkdir()) {
                dirNames.add(dirName)
            }
        }

        val directoryListingResult = directory.listDirectory()!!

        assertNotNull(directoryListingResult.managedFileList)
        assertEquals(directoryListingResult.managedFileList.size, secureFileCount.toInt())

        assertNotNull(directoryListingResult.fileList)
        assertEquals(directoryListingResult.fileList.size, fileCount.toInt())

        assertNotNull(directoryListingResult.dirList)
        assertEquals(directoryListingResult.dirList.size, dirCount.toInt())

        for (secureFile in directoryListingResult.managedFileList) {
            assertTrue(plainSecureFileNames.contains(secureFile.plainNameFile.name))
        }

        for (file in directoryListingResult.fileList) {
            assertTrue(plainFileNames.contains(file.name))
        }

        for (file in directoryListingResult.dirList) {
            assertTrue(file.isDirectory)
            assertTrue(dirNames.contains(file.name))
        }
    }
}
