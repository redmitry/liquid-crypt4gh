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
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.net.URI;
import java.util.Arrays;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghSeekableByteChannelTest {
    
    public final static String UNENCRYPED_FILE = "crypt4gh.pdf";
    public final static String ENCRYPTED_FILE = "crypt4gh.c4gh";
    
    // encrypted PCSK#8 Alice private key file
    private final static String ALICE_PRIVATE_KEY_FILE = "alice.p8";
    
    // unencrypted PCSK#8 Bob private key file
    private final static String BOB_PRIVATE_KEY_FILE = "bob.p8";

    @Test
    public void testCrypt4ghFileSize() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(
                        BOB_PRIVATE_KEY_FILE).toString())).toString());
        
        final URL pdf = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        final URL c4gh = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(ENCRYPTED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Paths.get(c4gh.toURI());

            Assertions.assertEquals(Files.size(pdf_path), Files.size(c4gh_path), "different files sizes");
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }

    @Test
    public void readCrypt4ghFile() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(
                        BOB_PRIVATE_KEY_FILE).toString())).toString());

        final URL pdf = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        final URL c4gh = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(ENCRYPTED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Paths.get(c4gh.toURI());

            final byte[] unencrypted = Files.readAllBytes(pdf_path);
            final byte[] decrypted = Files.readAllBytes(c4gh_path);
            Assertions.assertArrayEquals(unencrypted, decrypted);
            
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
    
    @Test
    public void readCrypt4ghFileByChunks() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(
                        BOB_PRIVATE_KEY_FILE).toString())).toString());

        final URL pdf = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        final URL c4gh = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(ENCRYPTED_FILE);
        try {
            final Path pdf_path = Paths.get(pdf.toURI());
            final Path c4gh_path = Paths.get(c4gh.toURI());

            final byte[] unencrypted = Files.readAllBytes(pdf_path);
            // crypt4gh blocks are 64k - use 'arbitrary' number to test unaligned blocks
            final byte[] decrypted = new byte[25519];
            final ByteBuffer buf = ByteBuffer.wrap(decrypted);
            try (SeekableByteChannel ch = Files.newByteChannel(c4gh_path, StandardOpenOption.READ)) {
                for (int i = 0, n; (n = ch.read(buf)) >= 0; i += n, buf.clear()) {
                    Assertions.assertTrue(Arrays.equals(unencrypted, i, i + n, decrypted, 0, n));
                }
            }
            
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }

    @Test
    public void write() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(
                        ALICE_PRIVATE_KEY_FILE).toString())).toString());

        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, "");
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");
        
        final URL pdf = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");

            try {
                final Path pdf_path = Paths.get(pdf.toURI());
                final byte[] unencrypted = Files.readAllBytes(pdf_path);
                
                try (SeekableByteChannel ch = Files.newByteChannel(c4gh_path, 
                        StandardOpenOption.READ, StandardOpenOption.WRITE)) {
                    ch.write(ByteBuffer.wrap(unencrypted));
                }
            
                final byte[] decrypted = Files.readAllBytes(c4gh_path);
                Assertions.assertArrayEquals(unencrypted, decrypted);
            } finally {
                Files.delete(c4gh_path);
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
    
    /**
     * This test implicitly uses SeekableByteChannel.
     * <code>Files.write(c4gh_path, unencrypted);</code>
     * uses OutputStream with <code>BUFFER_SIZE = 8192</code>
     * which is not optimal for the CRYPT4GH which blocks are 64K.
     */
    @Test
    public void writeCrypt4ghFile() {
        
        System.setProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY, 
                Path.of(URI.create(Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(
                        ALICE_PRIVATE_KEY_FILE).toString())).toString());

        System.setProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY, "");
        
        System.setProperty(CRYPT4GH_PASSPHRASE_PROPERTY, "alice");
        
        final URL pdf = Crypt4ghSeekableByteChannelTest.class.getClassLoader().getResource(UNENCRYPED_FILE);
        try {
            final Path c4gh_path = Files.createTempFile("crypt4gh.c4gh", ".tmp");

            try {
                final Path pdf_path = Paths.get(pdf.toURI());
                final byte[] unencrypted = Files.readAllBytes(pdf_path);
                Files.write(c4gh_path, unencrypted);
            
                final byte[] decrypted = Files.readAllBytes(c4gh_path);
                Assertions.assertArrayEquals(unencrypted, decrypted);
            } finally {
                Files.delete(c4gh_path);
            }
        } catch (IOException | URISyntaxException ex) {
            Assertions.fail(ex.getMessage());
        }
    }
}
