/*
 * Copyright (C) 2025 ELIXIR ES, Spanish National Bioinformatics Institute (INB)
 * and Barcelona Supercomputing Center (BSC)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package es.bsc.inb.ga4gh.jcrypt4gh.fs;

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghConfig.CRYPT4GH_PASSPHRASE_PROPERTY;
import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghConfig.CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY;
import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghConfig.CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY;
import java.io.IOException;
import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghFileChannelTest {
    
    public final static String UNENCRYPED_FILE = "crypt4gh.pdf";
    public final static String ENCRYPTED_FILE = "crypt4gh.c4gh";
    
    private final static String ALICE_PRIVATE_KEY_FILE = "alice.p8";
    private final static String ALICE_PUBLIC_KEY_FILE = "alice.pem";
    
    private final static String BOB_PRIVATE_KEY_FILE = "bob.p8";

    @BeforeAll
    public static void setLogLevel() {
        // enable logging for debugging
        
//        final Logger logger = Logger.getLogger(Crypt4ghFileChannel.class.getName());
//        final ConsoleHandler handler = new ConsoleHandler();
//        logger.addHandler(handler);
//        logger.setLevel(Level.ALL);
//        handler.setLevel(Level.ALL);
    }
    
    @Test
    public void readCrypt4ghFile() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(BOB_PRIVATE_KEY_FILE).toString())).toString());
        
        System.clearProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY);
        
        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        final URL c4gh = Crypt4ghFileChannelTest.class.getClassLoader().getResource(ENCRYPTED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Paths.get(c4gh.toURI());

            final byte[] unencrypted = Files.readAllBytes(pdf_path);
            final byte[] decrypted = new byte[25519];
            final ByteBuffer buf = ByteBuffer.wrap(decrypted);
            try (FileChannel ch = FileChannel.open(c4gh_path, StandardOpenOption.READ)) {
                for (int i = 0, n; (n = ch.read(buf)) >= 0; i += n, buf.clear()) {
                    Assertions.assertTrue(Arrays.equals(unencrypted, i, i + n, decrypted, 0, n));
                }
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }

    @Test
    public void writeCrypt4ghFile() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PRIVATE_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PUBLIC_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");
        
        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");

            final byte[] unencrypted = Files.readAllBytes(pdf_path);
            try (FileChannel ch = FileChannel.open(c4gh_path, 
                    StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE)) {
                for (int i = 0; i < unencrypted.length; i += 25519) {
                    final ByteBuffer src = ByteBuffer.wrap(unencrypted, i, Math.min(25519, unencrypted.length - i));
                    ch.write(src);
                }
                
                final byte[] decrypted = Files.readAllBytes(c4gh_path);
                Assertions.assertArrayEquals(unencrypted, decrypted);
            }
            
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
    
    @Test
    public void testReadMappedByteBuffer() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(BOB_PRIVATE_KEY_FILE).toString())).toString());
        
        System.clearProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY);

        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        final URL c4gh = Crypt4ghFileChannelTest.class.getClassLoader().getResource(ENCRYPTED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Paths.get(c4gh.toURI());

            final byte[] unencrypted = Files.readAllBytes(pdf_path);
            final byte[] decrypted = new byte[4096];
            try (FileChannel ch = FileChannel.open(c4gh_path, StandardOpenOption.READ)) {
                for (int i = 0; i < unencrypted.length; i += unencrypted.length) {
                    final int size = Math.min(decrypted.length, unencrypted.length - i);
                    final MappedByteBuffer buf = ch.map(FileChannel.MapMode.READ_ONLY, i, size);
                    buf.get(decrypted);
                    
                    Assertions.assertTrue(Arrays.equals(unencrypted, i, i + size, decrypted, 0, size),
                            "decrypted mapped buffer doesn't match");
                }
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }

    /**
     * Test whether the mapped byte buffers are updated when we write to the channel.
     */
    @Test
    public void testSyncMappedByteBufferOnWrite() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PRIVATE_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PUBLIC_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");
        
        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");
            
            final byte[] unencrypted = Files.readAllBytes(pdf_path);

            try (FileChannel ch = FileChannel.open(c4gh_path, StandardOpenOption.READ, 
                    StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE)) {
                
                // fill encrypted file with '0' up to the unencrypted.length
                ch.position(unencrypted.length);
                ch.write(ByteBuffer.allocate(0));
                
                final MappedByteBuffer buf1 = ch.map(FileChannel.MapMode.READ_WRITE, 10000, 10000);
                final MappedByteBuffer buf2 = ch.map(FileChannel.MapMode.READ_WRITE, 50000, 20000);
                final MappedByteBuffer buf3 = ch.map(FileChannel.MapMode.READ_WRITE, 70000, 80000);
                
                // this should not only write, but also sync with buffers
                ch.write(ByteBuffer.wrap(unencrypted).slice(10000, 150000), 10000);
                
                final byte[] arr1 = new byte[10000];
                final byte[] arr2 = new byte[20000];
                final byte[] arr3 = new byte[80000];
                
                buf1.get(arr1);
                buf2.get(arr2);
                buf3.get(arr3);
                
                Assertions.assertArrayEquals(Arrays.copyOfRange(unencrypted, 10000, 20000), arr1);
                Assertions.assertArrayEquals(Arrays.copyOfRange(unencrypted, 50000, 70000), arr2);
                Assertions.assertArrayEquals(Arrays.copyOfRange(unencrypted, 70000, 150000), arr3);
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }

    /**
     * Test whether reading channel got data from mapped buffers.
     * 
     * Writing to the mapped byte buffers is realized when enforced
     * or on garbage collection. Reading from the channel must reflect 
     * byte buffers changes even when no actual writing was yet performed.
     */
    @Test
    public void testReadChannelOnMappedByteBufferWrite() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PRIVATE_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PUBLIC_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");
        
        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");
            
            final byte[] unencrypted = Files.readAllBytes(pdf_path);

            try (FileChannel ch = FileChannel.open(c4gh_path, StandardOpenOption.READ, 
                    StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE)) {
                
                // fill encrypted file with '0' up to the unencrypted.length
                ch.position(unencrypted.length);
                ch.write(ByteBuffer.allocate(0));
                
                final MappedByteBuffer buf1 = ch.map(FileChannel.MapMode.READ_WRITE, 10000, 10000);
                final MappedByteBuffer buf2 = ch.map(FileChannel.MapMode.READ_WRITE, 50000, 20000);
                final MappedByteBuffer buf3 = ch.map(FileChannel.MapMode.READ_WRITE, 70000, 80000);
                
                buf1.put(unencrypted, 10000, 10000);
                buf2.put(unencrypted, 50000, 20000);
                buf3.put(unencrypted, 70000, 80000);
                
                // read the channel which must refclect buf1, buf2, and buf3 updates
                final byte[] arr = new byte[140000];
                ch.read(ByteBuffer.wrap(arr), 10000);
                
                Assertions.assertArrayEquals(Arrays.copyOfRange(unencrypted, 10000, 20000), 
                        Arrays.copyOfRange(arr, 0, 10000));
                
                Assertions.assertArrayEquals(Arrays.copyOfRange(unencrypted, 50000, 70000),
                        Arrays.copyOfRange(arr, 40000, 60000));
                
                Assertions.assertArrayEquals(Arrays.copyOfRange(unencrypted, 70000, 150000), 
                        Arrays.copyOfRange(arr, 60000, 140000));
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }

    @Test
    public void testWriteMappedByteBuffer() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PRIVATE_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PUBLIC_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");

        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");

            try (FileChannel ch = FileChannel.open(c4gh_path, 
                        StandardOpenOption.READ, StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE)) {
                final byte[] unencrypted = Files.readAllBytes(pdf_path);
                final byte[] encrypted = new byte[4096];

                for (int i = 0; i < unencrypted.length; i += encrypted.length) {
                    final int size = Math.min(encrypted.length, unencrypted.length - i);
                    final MappedByteBuffer buf = ch.map(FileChannel.MapMode.READ_WRITE, i, size);
                    buf.put(unencrypted, i, size);
                }
                
                ch.force(true); // flush all mapped buffers to the disk
                
                final byte[] decrypted = Files.readAllBytes(c4gh_path);
                Assertions.assertArrayEquals(unencrypted, decrypted);
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
    
    @Test
    public void testWriteMappedByteBufferAfterClose() {
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PRIVATE_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PUBLIC_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");

        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");

            final byte[] unencrypted = Files.readAllBytes(pdf_path);
            
            MappedByteBuffer buf;
            
            try (FileChannel ch = FileChannel.open(c4gh_path, 
                        StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                ch.write(ByteBuffer.wrap(unencrypted, 4096, unencrypted.length - 4096), 4096);
                
                buf = ch.map(FileChannel.MapMode.READ_WRITE, 0, 4096);
            }
            
            // here we have our encrypted file written except the first 4k.
            // write the first 4k into the mapped buffer
            buf.put(0, unencrypted, 0, 4096);
            
            // release buffer and wait it is garbage collected.
            ReferenceQueue rq = new ReferenceQueue();
            PhantomReference<MappedByteBuffer> ref = new PhantomReference(buf, rq);
            buf = null;
            while(rq.poll() == null) {
                System.gc();
            }

            // all finalizers are finished... only phantom references left.
            PhantomReference<PhantomReference> pref = new PhantomReference(ref, rq);
            ref.clear();
            ref = null;
            while(rq.poll() == null) {
                System.gc();
            }
            pref.clear();


            // wait a second to flush the buf to the disk 
            try {
                System.gc();
                TimeUnit.SECONDS.sleep(1);
            } catch (InterruptedException ex) {
                Logger.getLogger(Crypt4ghFileChannelTest.class.getName()).log(Level.SEVERE, null, ex);
            }

            final byte[] decrypted = Files.readAllBytes(c4gh_path);
            Assertions.assertArrayEquals(unencrypted, decrypted);
            
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }        
    }
    
    //@Test
    public void testTruncate() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PRIVATE_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghFileChannelTest.class.getClassLoader()
                        .getResource(ALICE_PUBLIC_KEY_FILE).toString())).toString());
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");
        
        final URL pdf = Crypt4ghFileChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");
            
            final byte[] unencrypted = Files.readAllBytes(pdf_path);

            try (FileChannel ch = FileChannel.open(c4gh_path, StandardOpenOption.READ, 
                    StandardOpenOption.WRITE, StandardOpenOption.DELETE_ON_CLOSE)) {
                ch.write(ByteBuffer.wrap(unencrypted));
                ch.truncate(unencrypted.length - 77777);
                
                final byte[] trucated = new byte[unencrypted.length - 77777];
                ch.read(ByteBuffer.wrap(trucated), 0);
                Assertions.assertArrayEquals(Arrays.copyOf(unencrypted, trucated.length), trucated);
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
}
