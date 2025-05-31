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

package es.bsc.inb.ga4gh.jcrypt4gh;

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghDataPacketType.DATA_ENCRYPTION_KEY;
import es.bsc.inb.ga4gh.jcrypt4gh.fs.Crypt4ghPath;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghHeader implements Crypt4ghHeaherElement {

    // The magic number is the ASCII representation of the string “crypt4gh”.
    private static final byte[] MAGIC = {'c', 'r', 'y', 'p', 't', '4', 'g', 'h'};
    // The version number is stored as a four-byte little-endian unsigned integer.
    private static final byte[] VERSION = {1, 0, 0, 0}; 
    
    public final Crypt4ghKeys keys;
    
    private Crypt4ghHeaderPacket editListPacket;
    private final List<Crypt4ghHeaderPacket> dataPackets;
    
    /**
     * Create Crypt4GH Header with given encryption keys.
     * 
     * @param keys a keys set (secret key and target public key
     * 
     * @throws GeneralSecurityException
     * @throws Crypt4ghException 
     */
    public Crypt4ghHeader(Crypt4ghKeys keys)
            throws GeneralSecurityException, Crypt4ghException {
        this(keys, new ArrayList(), null);
        
        dataPackets.add(new Crypt4ghX25519HeaderPacket(
                this.keys.SK, this.keys.PK, this.keys.RPK));
    }

    private Crypt4ghHeader(Crypt4ghKeys keys, List<Crypt4ghHeaderPacket> dataPackets, 
            Crypt4ghHeaderPacket editListPacket) 
            throws Crypt4ghException, GeneralSecurityException {
        
        this.keys = keys;
        this.dataPackets = dataPackets;
        this.editListPacket = editListPacket;
    }
        
    public int size() {
        int size = MAGIC.length + VERSION.length + 4;
        for (Crypt4ghHeaderPacket packet : dataPackets) {
            size += packet.size(); 
        }
        if (editListPacket != null) {
            size += editListPacket.size();
        }
        return size;
    }

    /**
     * Get encrypted segment file position based on the 'virtual' file position.
     * 
     * @param vposition the 'virtual' position (as if the file was not encrypted)
     * @return calculated segment disk position for the 'virtual' one
     */
    public long getSegmentPosition(long vposition) {
        return size() + (vposition / 65536) * 65564;
    }

    public long getPosition(long vposition) {
        return vposition % 65536 + 12 + getSegmentPosition(vposition);
    }
    
    public List<Crypt4ghHeaderPacket> getDataPackets() {
        return dataPackets;
    }
    
    /**
     * Find data encryption key for the target public key.
     * 
     * @return found secret (shared) key or null if not found
     */
    public Crypt4ghDataEncryptionKey getEncryptionKey() {
        for (Crypt4ghHeaderPacket pk : dataPackets) {
            if (pk.packet instanceof Crypt4ghDataEncryptionKey key &&
                Arrays.equals(keys.PK.getEncoded(), pk.pk.getEncoded())) {
                return key;
            }
        }
        return null;
    }
     
    public void addDataHeaderPacket(Crypt4ghX25519HeaderPacket dp) {
        dataPackets.add(dp);
    }

    public void write(WritableByteChannel ch) throws IOException {
        Crypt4ghHeaherElement.write(ch, ByteBuffer.wrap(MAGIC));
        Crypt4ghHeaherElement.write(ch, ByteBuffer.wrap(VERSION));
        
        final int packet_count = dataPackets.size() + (editListPacket == null ? 0 : 1);
        Crypt4ghHeaherElement.writeUnsignedInt(ch, packet_count);
        
        for (Crypt4ghHeaderPacket packet : dataPackets) {
            packet.write(ch);
        }
        
        if (editListPacket != null) {
            editListPacket.write(ch);
        }
    }

    public static Crypt4ghHeader load(ReadableByteChannel ch, Crypt4ghKeys keys) 
            throws Crypt4ghException, IOException, GeneralSecurityException {
        
        if (!Arrays.equals(MAGIC, Crypt4ghHeaherElement.readNBytes(ch, MAGIC.length))) {
            return null; // invalid 'crypt4gh' header
        }
        if (!Arrays.equals(VERSION, Crypt4ghHeaherElement.readNBytes(ch, VERSION.length))) {
            return null; // invalid crypt4gh header version
        }

        keys = keys != null ? keys : Crypt4ghKeys.instance();
                
        Crypt4ghHeaderPacket editListPacket = null;
        final ArrayList dataPackets = new ArrayList();
        
        final int packet_count = Crypt4ghHeaherElement.readUnsignedInt(ch);
        for (int i = 0; i < packet_count; i++) {
            final Crypt4ghHeaderPacket packet = Crypt4ghHeaderPacket.create(ch, keys.SK);
            if (packet != null) {
                if (packet.packet.type == DATA_ENCRYPTION_KEY) {
                    dataPackets.add(packet);
                } else if (editListPacket == null) { // DATA_EDIT_LIST
                    editListPacket = packet;
                } else {
                    throw new IOException("multiple edit lists");
                }
            }
        }

        if (dataPackets.isEmpty()) {
            throw new IOException("no matching key found in header");
        }
        
        return new Crypt4ghHeader(keys, dataPackets, editListPacket);
    }

    public static long getFileSize(Crypt4ghPath path) 
            throws IOException, GeneralSecurityException, Crypt4ghException {
        try (SeekableByteChannel ch = Files.newByteChannel(path.proxy, StandardOpenOption.READ)) {
            final Crypt4ghHeader header = load(ch, null); // TODO!!!!!!!!
            if (header == null) {
                return ch.size();
            }
            final long dsize = ch.size() - header.size(); // data size
            return (dsize / 65564) * 65536 + dsize % 65564 - 28;
        }
    }
}
