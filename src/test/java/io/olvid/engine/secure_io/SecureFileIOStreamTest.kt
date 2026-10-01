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
import com.sun.management.UnixOperatingSystemMXBean
import java.io.File
import java.io.FileOutputStream
import java.lang.management.ManagementFactory
import java.math.BigInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
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

    // Splits total into 1 to 30 random lengths summing to it. bigInt(0) never returns, so stop
    // drawing once nothing is left.
    private fun randomSplit(total: Int): List<Int> {
        val parts = rngBigInt(BigInteger("30")).toInt() + 1
        var remaining = total
        return List(parts) { i ->
            val length = if (i == parts - 1 || remaining == 0) remaining
            else rngBigInt(BigInteger.valueOf(remaining.toLong())).toInt()
            remaining -= length
            length
        }
    }

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

        val readLengthValues = randomSplit(bytesToWrite.size)
        // result
        val resultBuf = ByteArray(bytesToWrite.size)
        var off = 0
        // read loop
        SecureFileInputStream(secureFileRead).use { secureFileInputStream ->
            for (readLengthValue in readLengthValues) {
                secureFileInputStream.read(resultBuf, off, readLengthValue)
                off += readLengthValue
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
        val writeLengthValues = randomSplit(fileSize.toInt())

        var writeOff = 0
        for (writeLengthValue in writeLengthValues) {
            SecureFileOutputStream(secureFileWrite, AccessMode.TRUNCATE, writeOff.toLong()).use { discreteSecureOutputStream ->
                val toWrite = rngBytes(writeLengthValue)
                bytesToWrite.writeBytes(toWrite)
                discreteSecureOutputStream.write(toWrite)
                writeOff += writeLengthValue
            }
        }

        SecureFileOutputStream(secureFileWrite).use { secureFileOutputStream ->
            // Assert header is consistent with what was written
            assertEquals(secureFileOutputStream.secureFileHeader!!.fileSize, bytesToWrite.toByteArray().size.toLong())
        }

        val secureFileRead = SecureFile(testingFolder.root.path, Logger.toHexString(fileName))

        // same mechanism to generate a random number of read calls with random read length per call
        val readLengthValues = randomSplit(bytesToWrite.toByteArray().size)

        SecureFileInputStream(secureFileRead).use { secureFileInputStream ->
            // result
            val resultBuf = ByteArray(bytesToWrite.toByteArray().size)
            var off = 0
            // read loop
            for (readLengthValue in readLengthValues) {
                secureFileInputStream.read(resultBuf, off, readLengthValue)
                off += readLengthValue
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

    private fun writeSecureFile(directory: SecureFile, input: ByteArray): SecureFile {
        val secureFile = SecureFile(directory.fsNameFile!!.absolutePath, Logger.toHexString(rngBytes(16)))
        SecureFileOutputStream(secureFile).use { secureFileOutputStream ->
            secureFileOutputStream.write(input)
        }
        return secureFile
    }

    // A leaked handle only breaks delete() on Windows; counting descriptors catches it everywhere else.
    private fun openFileDescriptorCount(): Long {
        val os = ManagementFactory.getOperatingSystemMXBean()
        assumeTrue(os is UnixOperatingSystemMXBean)
        return (os as UnixOperatingSystemMXBean).openFileDescriptorCount
    }

    /**
     * Every caller lists a directory and then deletes some of what it listed, so listDirectory()
     * must not keep a handle open on the files it returns: on Windows that makes delete() fail.
     */
    @Test
    fun test_list_directory_then_delete() {
        val directory = SecureFile(directoryListingTestingFolder.newFolder("deletable").absolutePath)
        val input = rngBytes(1000)
        repeat(5) { writeSecureFile(directory, input) }

        val directoryListingResult = directory.listDirectory()!!
        assertEquals(5, directoryListingResult.managedFileList.size)

        for (secureFile in directoryListingResult.managedFileList) {
            assertTrue("could not delete " + secureFile.plainNameFile.name, secureFile.delete())
        }

        assertEquals(0, directory.listDirectory()!!.managedFileList.size)
    }

    /**
     * A file whose header does not verify must be listed as a plain file, not abort the whole
     * listing: an aborted listing left callers cleaning nothing at all.
     */
    @Test
    fun test_list_directory_with_unverifiable_header() {
        val directory = SecureFile(directoryListingTestingFolder.newFolder("corrupted").absolutePath)
        val input = rngBytes(1000)

        val good = writeSecureFile(directory, input)

        // A valid secure file moved to another hashed name: its header still decodes, but the
        // name MAC no longer matches, which is the mismatch that used to throw out of the loop.
        val stray = writeSecureFile(directory, input)
        val renamedStray = File(directory.fsNameFile!!.absolutePath, Logger.toHexString(rngBytes(32)))
        assertTrue(stray.fsNameFile!!.renameTo(renamedStray))

        val directoryListingResult = directory.listDirectory()

        assertNotNull(directoryListingResult)
        assertEquals(1, directoryListingResult!!.managedFileList.size)
        assertEquals(good.plainNameFile.name, directoryListingResult.managedFileList[0].plainNameFile.name)
        assertTrue(directoryListingResult.fileList.contains(renamedStray))
    }

    @Test
    fun test_header_reads_release_their_handles() {
        val directory = SecureFile(directoryListingTestingFolder.newFolder("handles").absolutePath)
        val input = rngBytes(1000)
        val secureFiles = List(5) { writeSecureFile(directory, input) }
        val corrupted = writeSecureFile(directory, input)
        FileOutputStream(corrupted.fsNameFile!!).use { it.write(rngBytes(1000)) }

        val before = openFileDescriptorCount()
        repeat(20) {
            directory.listDirectory()
            secureFiles.forEach { assertTrue(it.canRead()) }
            assertFalse(corrupted.canRead())
            runCatching { SecureFileInputStream(corrupted) }
        }
        // other tests' leftovers may get closed meanwhile, so only an increase is a leak
        val after = openFileDescriptorCount()
        assertTrue("leaked ${after - before} file descriptors", after <= before)
    }
}
