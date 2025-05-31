/*
 * Copyright (C) 2024 ELIXIR ES, Spanish National Bioinformatics Institute (INB)
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

import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghDataEncryptionKey;
import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghException;
import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeader;
import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghKeys;
import es.bsc.inb.ga4gh.jcrypt4gh.security.Crypt4ghSecurityProvider;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghSeekableByteChannel implements SeekableByteChannel {

    private long vsize;
    private long vposition = 0;
    
    private final SeekableByteChannel channel;
    private final Crypt4ghHeader header;
    
    // last channel segment position
    private long sposition = 0;
    
    private final byte[] nonce = new byte[12];
    private final byte[] decrypted = new byte[65536];
    private final byte[] encrypted = new byte[65536 + 16];

    public Crypt4ghSeekableByteChannel(Path path, 
            Set<? extends OpenOption> options, FileAttribute<?>... attrs) 
            throws Crypt4ghException, IOException, GeneralSecurityException {
        
        this(null, path, options, attrs);
    }

    public Crypt4ghSeekableByteChannel(Crypt4ghKeys keys, Path path, 
            Set<? extends OpenOption> options, FileAttribute<?>... attrs)
            throws Crypt4ghException, IOException, GeneralSecurityException {
            
        channel = Files.newByteChannel(Crypt4ghPath.unwrap(path), options, attrs);

        if (channel.size() != 0) {
            header = Crypt4ghHeader.load(channel, keys);
            
            if (header == null) {
                channel.position(0);
            } else {
                // calculate the decrypted size - "virtual" size reported to the application
                final long dsize = channel.size() - channel.position();
                vsize = dsize % 65564;
                vsize -= vsize == 0 ? 0 : 28; // if there is a 'tail' remove nonce + mac
                vsize += (dsize / 65564) * 65536;

                if (header.keys.RPK != null &&
                       options.contains(StandardOpenOption.WRITE)) {
                    if (header.getEncryptionKey() == null) {
                        // we can't write to the file without changing the header
                    }
                }
            }
        } else if (options.contains(StandardOpenOption.WRITE)) {
            keys = keys != null ? keys : Crypt4ghKeys.instance();
            if (keys == null || keys.RPK == null) {
                // do not encrypt file if no explicit target public key is provided
                header = null;
            } else {
                header = new Crypt4ghHeader(keys);
                header.write(channel);
            }
        } else {
            header = null;
        }
    }
    
    @Override
    public int read(ByteBuffer dst) throws IOException {
        if (header == null) {
            return channel.read(dst);
        }

        if (vposition >= vsize) {
            return -1; // we are done
        }
        
        final Crypt4ghDataEncryptionKey packet = header.getEncryptionKey();
        if (packet == null) {
            throw new IOException("no suitable encrypted header found to decode");
        }
        final SecretKey encryptionKey = packet.secretKey;
                
        final int remaining = dst.remaining();
        
        while(dst.hasRemaining() && vposition < vsize) {
            int size = (int)Math.min(65536, vsize - vposition);
            final ByteBuffer src = ByteBuffer.wrap(encrypted, 0, size + 16);
            
            long spos = header.getSegmentPosition(vposition);
            if (sposition != spos) {
                sposition = spos;
                
                // reread nonce if we changed the segment
                channel.position(spos).read(ByteBuffer.wrap(nonce));
                
                Logger.getLogger(Crypt4ghSeekableByteChannel.class.getName())
                        .log(Level.FINE, "segment nonce: {0}" , HexFormat.of().formatHex(nonce).toUpperCase());

                channel.read(src);
                
                try {
                    final Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                    cipher.init(Cipher.DECRYPT_MODE, encryptionKey, new IvParameterSpec(nonce));
                    cipher.doFinal(encrypted, 0, size + 16, decrypted);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                        IllegalBlockSizeException | BadPaddingException | ShortBufferException |
                        NoSuchAlgorithmException | NoSuchPaddingException ex) {
                    Logger.getLogger(Crypt4ghSeekableByteChannel.class.getName()).log(Level.SEVERE, null, ex);
                    throw new IOException(ex.getMessage());
                }
            }
            
            final int shift = (int)(vposition % 65536);
            
            size = Math.min(Math.min(size, 65536 - shift), dst.remaining());
            dst.put(decrypted, shift, size);
            vposition += size;
        }
        
        return remaining - dst.remaining();
    }

    @Override
    public int write(ByteBuffer src) throws IOException {

        if (header == null) {
            return channel.write(src);
        }
        
        final Crypt4ghDataEncryptionKey packet = header.getEncryptionKey();
        if (packet == null) {
            throw new IOException("no suitable encrypted header found to encode");
        }
                
        final int remaining = src.remaining();
        
        while (src.hasRemaining()) {
            int shift = (int)(vposition % 65536);
            int size = Math.min(65536 - shift, src.remaining());
            
            final long spos = header.getSegmentPosition(vposition);
            final long dpos = spos + nonce.length; // segment data position
            final int tpos; // tag position relative to the segment data position

            if (spos == sposition) {
                tpos = shift + size;
            } else {
                sposition = spos;
                if (shift == 0 && vsize == vposition) {
                    // write new nonce
                    tpos = size;
                    new SecureRandom().nextBytes(nonce);
                    channel.position(spos).write(ByteBuffer.wrap(nonce));
                } else {
                    // read nonce + block
                    tpos = Math.min(65536, (int)(vsize - vposition));
                    channel.position(spos).read(ByteBuffer.wrap(nonce));
                    channel.position(dpos).read(ByteBuffer.wrap(encrypted, 0, tpos + 16));
                }
            }
            
            src.get(decrypted, shift, size);
            
            try {
                // encrypt par of the the block shift - shift + size
                // actually, encoding is aligned to the chacha20 block wich is 64 bytes.
                final Cipher cipher = Cipher.getInstance("ChaCha20");
                cipher.init(Cipher.ENCRYPT_MODE, packet.secretKey, new ChaCha20ParameterSpec(nonce, (shift >> 6) + 1));
                cipher.doFinal(decrypted, shift & 0xFFFFFFC0, size + (shift & 0x3F), encrypted, shift & 0xFFFFFFC0);
                
                // recalculate Poly1305 MAC with AEAD (ChaCha20-Poly1305)
                final Mac mac = Mac.getInstance("Poly1305", new Crypt4ghSecurityProvider());
                mac.init(packet.secretKey, new IvParameterSpec(nonce));
                mac.update(encrypted, 0, tpos);
                final byte[] tag = mac.doFinal();
                
                // put the tag into the segment
                System.arraycopy(tag, 0, encrypted, tpos, tag.length);
                
            } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                    NoSuchAlgorithmException | NoSuchPaddingException | 
                    ShortBufferException | IllegalBlockSizeException | BadPaddingException ex) {
                Logger.getLogger(Crypt4ghSeekableByteChannel.class.getName()).log(Level.SEVERE, null, ex);
                throw new IOException(ex.getMessage());
            }

            if (shift + size == tpos) {
                channel.position(dpos + shift).write(ByteBuffer.wrap(encrypted, shift, size + 16));
            } else {
                channel.position(dpos + shift).write(ByteBuffer.wrap(encrypted, shift, size));
                channel.position(dpos + tpos).write(ByteBuffer.wrap(encrypted, tpos, 16));
            }
            
            vposition += size;
            vsize = Math.max(vsize, vposition);
        }
        return remaining - src.remaining();        
    }

    @Override
    public long position() throws IOException {
        return header == null ? channel.position() : vposition;
    }

    @Override
    public SeekableByteChannel position(long newPosition) throws IOException {
        if (header != null) {
            vposition = newPosition;
        } else {
            channel.position(newPosition);
        }
        return this;
    }

    @Override
    public long size() throws IOException {
        return header == null ? channel.size() : vsize;
    }

    @Override
    public SeekableByteChannel truncate(long size) throws IOException {
        return this; // TODO
    }

    @Override
    public boolean isOpen() {
        return channel.isOpen();
    }

    @Override
    public void close() throws IOException {
        channel.close();
    }
}
