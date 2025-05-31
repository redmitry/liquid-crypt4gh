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

import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghDataEncryptionKey;
import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghException;
import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeader;
import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghKeys;
import es.bsc.inb.ga4gh.jcrypt4gh.security.Crypt4ghSecurityProvider;
import java.io.IOException;
import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.ref.WeakReference;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.ClosedChannelException;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Consumer;
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

public class Crypt4ghFileChannel extends FileChannel {

    private boolean closed;
    
    private long vsize;
    private long vposition = 0;
    
    private final FileChannel channel;
    private final Crypt4ghHeader header;
    
    // last channel segment position
    private long sposition = 0;
    
    private final byte[] nonce = new byte[12];
    private final byte[] decrypted = new byte[65536];
    private final byte[] encrypted = new byte[65536 + 16];

    /**
     * Mapped segments cache.
     */
    private final TreeMap<Long, WeakReference<MemorySegment>> segments = new TreeMap();
    
    /**
     * Mapped buffers (each lock corresponds to the emulated memory mapped buffer)
     */
    private final TreeMap<Long, FileLock> locks = new TreeMap();

    public Crypt4ghFileChannel(Path path, 
            Set<? extends OpenOption> options, FileAttribute<?>... attrs) 
            throws Crypt4ghException, IOException, GeneralSecurityException {
        
        this(null, path, options, attrs);
    }
    
    public Crypt4ghFileChannel(Crypt4ghKeys keys, Path path, 
            Set<? extends OpenOption> options, FileAttribute<?>... attrs) 
            throws Crypt4ghException, IOException, GeneralSecurityException {

        channel = FileChannel.open(Crypt4ghPath.unwrap(path), options, attrs);

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
                // do not encrypt file if no target public key is provided
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
    public synchronized int read(ByteBuffer dst) throws IOException {
        final int read = read(dst, vposition);
        vposition += read;
        return read;
    }
    
    @Override
    public synchronized int read(ByteBuffer dst, long position) throws IOException {
        if (header == null) {
            return channel.read(dst);
        }

        if (closed) {
            throw new ClosedChannelException();
        }

        if (position >= vsize) {
            return -1; // we are done
        }
        
        if (dst.remaining() == 0) {
            return 0;
        }
        
        final int remaining = dst.remaining();
        
        // if we have mapped segments - update them

        Entry<Long, WeakReference<MemorySegment>> entry = segments.floorEntry(position);
        while (dst.hasRemaining() && entry != null || (entry = segments.ceilingEntry(position)) != null) {
            final long key = entry.getKey();
            final WeakReference<MemorySegment> ref = entry.getValue();
            final MemorySegment seg = ref.get();
            if (seg == null) {
                segments.remove(key);
            } else if (key > position + dst.remaining()) {
                break; // segment higher than the read range 
            } else if (key + seg.byteSize() <= position) {
                entry = null; // segment below the read range;
            } else {
                int offset = Math.min(dst.remaining(), (int)(key - position));
                if (offset > 0) {
                    // read the gap from the file
                    // having a segment means we can't reach end of the file here
                    position += _read(dst.slice(dst.position(), dst.position() + offset), position);
                    offset = 0;
                } else if (offset < 0 && (key & 0xFFFF) != 0) {
                    // rollback to reread overlapped segment (not bound to the 64k)
                    final int rollback = Math.max(offset, dst.remaining() - remaining);
                    if (rollback != 0) { // offset <= rollback <= 0
                        dst.put(dst.position() + rollback, seg.asByteBuffer(), rollback - offset, -rollback);
                    }
                }
                
                final int size = Math.min(dst.remaining(), (int)seg.byteSize() + offset);
                
                // fill from the segment
                dst.put(dst.position(), seg.asByteBuffer(), -offset, size);
                dst.position(dst.position() + size);
                position += size;
                
                entry = segments.lowerEntry(position);
            }
        }

        for (int read; (read = _read(dst, position)) > 0; position += read) {}
        
        return remaining - dst.remaining();
    }

    @Override
    public synchronized long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
        if (header == null) {
            return channel.read(dsts, offset, length);
        }

        if (closed) {
            throw new ClosedChannelException();
        }

        if (vposition >= vsize) {
            return -1; // we are done
        }
        
        int count = 0;
        for (int read, i = offset; i < length; i++) {
            while ((read = read(dsts[i])) >= 0) {
                count +=read;
            }
        }
        return count;
    }    
    
    private int _read(ByteBuffer dst, long position) throws IOException {

        final Crypt4ghDataEncryptionKey packet = header.getEncryptionKey();
        if (packet == null) {
            throw new IOException("no suitable encrypted header found to decode");
        }
        
        final int remaining = dst.remaining();
        
        while(dst.hasRemaining() && position < vsize) {
            int size = (int)Math.min(65536, vsize - position);
            final ByteBuffer src = ByteBuffer.wrap(encrypted, 0, size + 16);
            
            long spos = header.getSegmentPosition(position);
            if (sposition != spos) {
                sposition = spos;
                
                // reread nonce if we changed the segment
                channel.position(spos).read(ByteBuffer.wrap(nonce));
                channel.read(src);

                try {
                    final Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
                    cipher.init(Cipher.DECRYPT_MODE, packet.secretKey, new IvParameterSpec(nonce));
                    cipher.doFinal(encrypted, 0, size + 16, decrypted);
                } catch (InvalidKeyException | InvalidAlgorithmParameterException |
                        IllegalBlockSizeException | BadPaddingException | ShortBufferException |
                        NoSuchAlgorithmException | NoSuchPaddingException ex) {
                    Logger.getLogger(Crypt4ghFileChannel.class.getName()).log(Level.SEVERE, null, ex);
                    throw new IOException(ex.getMessage());
                }
            }
            final int shift = (int)(position % 65536);
            size = Math.min(Math.min(size, 65536 - shift), dst.remaining());
            dst.put(decrypted, shift, size);
            position += size;
        }
        
        return remaining - dst.remaining();
    }

    @Override
    public synchronized int write(ByteBuffer src) throws IOException {
        if (header == null) {
            return channel.write(src);
        }

        if (closed) {
            throw new ClosedChannelException();
        }

        final int written = write(src, vposition);
        vposition += written;
        return written;
    }

    @Override
    public synchronized int write(ByteBuffer src, long position) throws IOException {
        if (header == null) {
            return channel.write(src, position);
        }
        
        if (closed) {
            throw new ClosedChannelException();
        }

        // if we have mapped segments - update them
        Entry<Long, WeakReference<MemorySegment>> entry = segments.lowerEntry(position + src.remaining());
        while (entry != null) {
            final long key = entry.getKey();
            final WeakReference<MemorySegment> ref = entry.getValue();
            final MemorySegment seg = ref.get();
            if (seg == null) {
                segments.remove(key);
            } else if (key + src.remaining() < position) {
                break; // sement is below writing
            } else if (key < position) {
                seg.asByteBuffer().put((int)(position - key), src, 0, 
                        (int)Math.min(key + seg.byteSize() - position, src.remaining()));
            } else {
                seg.asByteBuffer().put(0, src, (int)(key - position), 
                        (int)Math.min(position + src.remaining() - key, seg.byteSize()));
            }
            entry = segments.lowerEntry(key);
        }
        
        if (channel.size() < header.getPosition(position)) {
            extend(position);
        }
        
        return _write(src, position);
    }
    
    private int _write(ByteBuffer src, long position) throws IOException {
        
        final Crypt4ghDataEncryptionKey packet = header.getEncryptionKey();
        if (packet == null) {
            throw new IOException("no suitable encrypted header found to encode");
        }
        
        final int remaining = src.remaining();
        
        while (src.hasRemaining()) {
            int shift = (int)(position % 65536);
            int size = Math.min(65536 - shift, src.remaining());
            
            final long spos = header.getSegmentPosition(position);
            final long dpos = spos + nonce.length; // segment data position
            final int tpos; // tag position relative to the segment data position

            if (spos == sposition) {
                tpos = Math.max(shift + size, Math.min(65536, (int)(vsize - position)));
            } else {
                sposition = spos;
                if (shift == 0 && vsize == position) {
                    // write new nonce
                    tpos = size;
                    new SecureRandom().nextBytes(nonce);
                    channel.position(spos).write(ByteBuffer.wrap(nonce));
                } else {
                    // read nonce + block + tag
                    tpos = Math.min(65536, (int)(vsize - position));
                    channel.position(spos).read(ByteBuffer.wrap(nonce));
                    channel.position(dpos).read(ByteBuffer.wrap(encrypted, 0, tpos + 16));
                }
            }
            
            src.get(decrypted, shift, size);
            
            try {
                // encrypt part of the the block shift - shift + size
                // actually, encoding is aligned to the chacha20 block wich is 64 bytes.
                final Cipher cipher = Cipher.getInstance("ChaCha20");
                cipher.init(Cipher.ENCRYPT_MODE, packet.secretKey, new ChaCha20ParameterSpec(nonce, (shift >> 6) + 1));
                cipher.doFinal(decrypted, shift & 0xFFFFFFC0, size + (shift & 0x3F), encrypted, shift & 0xFFFFFFC0);
                
                Logger.getLogger(Crypt4ghFileChannel.class.getName()).log(
                    Level.FINEST, String.format("encrypt chunk %s (%s - %s)", position & 0xFFFFFFFFFFFF0000L, (shift & 0xFFFFFFC0), (shift & 0xFFFFFFC0) + size + (shift & 0x3F)));
                
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
                throw new IOException(ex.getMessage());
            }

            if (shift + size == tpos) {
                channel.write(ByteBuffer.wrap(encrypted, shift, size + 16), dpos + shift);
            } else {
                channel.write(ByteBuffer.wrap(encrypted, shift, size), dpos + shift);
                channel.write(ByteBuffer.wrap(encrypted, tpos, 16), dpos + tpos);
            }
            
            Logger.getLogger(Crypt4ghFileChannel.class.getName()).log(
                    Level.FINEST, String.format("writing data %s (%s - %s)", position & 0xFFFFFFFFFFFF0000L, shift, (shift + size)));
            
            position += size;
            vsize = Math.max(vsize, position);
        }
        return remaining - src.remaining();        
    }
    
    @Override
    public synchronized long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
        if (header == null) {
            return channel.write(srcs, offset, length);
        }

        if (closed) {
            throw new ClosedChannelException();
        }

        int count = 0;
        for (int write, i = offset; i < length; i++) {
            while ((write = write(srcs[i])) >= 0) {
                count +=write;
            }
        }
        return count;
    }

    @Override
    public synchronized long position() throws IOException {
        if (header == null) {
            return channel.position();
        }

        if (closed) {
            throw new ClosedChannelException();
        }

        return vposition;
    }

    @Override
    public synchronized FileChannel position(long newPosition) throws IOException {
        sposition = 0;
        if (header == null) {
            channel.position(newPosition);
        } else if (closed) {
            throw new ClosedChannelException();
        } else {
            vposition = newPosition;
        }
        return this;
    }

    @Override
    public synchronized long size() throws IOException {
        if (header == null) {
            return channel.size();
        }

        if (closed) {
            throw new ClosedChannelException();
        }

        return vsize;
    }

    @Override
    public synchronized FileChannel truncate(long size) throws IOException {
        if (header == null) {
            return channel.truncate(size);
        }
        
        if (closed) {
            throw new ClosedChannelException();
        }

        if (size < 0) {
            throw new IllegalArgumentException(String.format("negative truncate position %s", size));
        }
        
        if (size < vsize) {
            final long pos = size & 0xFFFFFFFFFFFF0000L;
            final int sz = (int)(size - pos);
            if (sz > 0) {
                // read nonce + truncated segment
                final byte[] arr = new byte[sz + nonce.length];
                channel.read(ByteBuffer.wrap(arr), header.getPosition(pos) - nonce.length);
                
                channel.truncate(header.getPosition(size));
                
                final Crypt4ghDataEncryptionKey packet = header.getEncryptionKey();
                if (packet == null) {
                    throw new IOException("no suitable encrypted header found to encode");
                }

                final SecretKey sharedKey = packet.secretKey;

                try {
                    // recalculate Poly1305 MAC with AEAD (ChaCha20-Poly1305)
                    final Mac mac = Mac.getInstance("Poly1305", new Crypt4ghSecurityProvider());
                    mac.init(sharedKey, new IvParameterSpec(arr, 0, nonce.length));
                    mac.update(arr, nonce.length, sz);
                    final byte[] tag = mac.doFinal();
                    
                    // write updated MAC to the end of the file
                    channel.write(ByteBuffer.wrap(tag), channel.size());
                } catch (NoSuchAlgorithmException | InvalidKeyException | 
                        InvalidAlgorithmParameterException ex) {
                    throw new IOException(ex.getMessage(), ex);
                }
            } else {
                // trucate entire segment
                channel.truncate(header.getPosition(size));
            }
            
            vsize = size;
            vposition = Math.min(vposition, size);
        } 
        
        return this;
    }

    @Override
    public synchronized void force(boolean metaData) throws IOException {
        if (header != null) {
            if (closed) {
                throw new ClosedChannelException();
            }

            for (Entry<Long, WeakReference<MemorySegment>> entry : segments.entrySet()) {
                final long key = entry.getKey();
                final WeakReference<MemorySegment> ref = entry.getValue();
                final MemorySegment seg = ref.get();
                if (seg == null) {
                    segments.remove(key);
                } else {
                    flush(seg, key);
                }
            }
        }
        channel.force(metaData);
    }

    @Override
    public synchronized long transferTo(long position, long count, 
            WritableByteChannel target) throws IOException {

        if (header == null) {
            return channel.transferTo(position, count, target);
        }
        
        if (closed) {
            throw new ClosedChannelException();
        }

        final ByteBuffer buf = ByteBuffer.allocate(
                (int)Math.min(this.vsize - position, Math.min(65536, count)));
        
        final int i = read(buf, position);
        if (i > 0) {
            buf.rewind();
            buf.limit(i);
            while (buf.hasRemaining()) {
                target.write(buf);
            }
        }
        return i;
        
    }

    @Override
    public synchronized long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
        
        if (header == null) {
            return channel.transferFrom(src, position, count);
        }
        
        if (closed) {
            throw new ClosedChannelException();
        }

        final ByteBuffer buf = ByteBuffer.allocate((int)Math.min(65536, count));
        final int len = src.read(buf);
        if (len > 0) {
            buf.rewind();
            buf.limit(len);
            while (buf.hasRemaining()) {
                write(buf);
            }
        }
        return len;
    }

    @Override
    public synchronized MappedByteBuffer map(MapMode mode, long position, long size)
            throws IOException {
        
        if (header == null) {
            return channel.map(mode, position, size);
        }

        if (closed) {
            throw new ClosedChannelException();
        }

        Logger.getLogger(Crypt4ghFileChannel.class.getName()).log(
                Level.FINEST, String.format("mapping segment %s - %s", 
                            position, position + size));

        if (MapMode.READ_ONLY == mode) {
            // no need to sync back to the file
            final ByteBuffer buf = ByteBuffer.allocateDirect((int)size);
            read(buf, position);
            return (MappedByteBuffer)buf.rewind().asReadOnlyBuffer();
        }
        
        extend(position + size); // ensure file size
        
        Entry<Long, FileLock> lock_entry = locks.floorEntry(position + size);
        if (lock_entry != null && position <= lock_entry.getKey()) {
                throw new IOException(String.format("overlapping mapped buffer request %s - %s " +
                        "with already allocated segment: %s - %s", 
                        position, position + size, lock_entry.getKey(), 
                        lock_entry.getKey() + lock_entry.getValue().size()));
        }
        
        ByteBuffer buffer = null; // overlapped buffer
        
        Entry<Long, WeakReference<MemorySegment>> entry;
        while ((entry = segments.floorEntry(position)) != null) {
            final long key = entry.getKey();
            final MemorySegment seg = entry.getValue().get();
            if (seg == null) {
                segments.remove(key);
                continue;
            }
            
            final long overlap = key + seg.byteSize() - position;
            if (overlap > 0) {
                // overlapping with segment
                if (size <= overlap) {
                    // buffer is fully inside the segment
                    final FileLock lock = lock(position, size, false);
                    final MemorySegment s = seg.asSlice(position - key, size);
                    final MappedByteBuffer buf = (MappedByteBuffer)s.asByteBuffer();
                    locks.put(position, lock);
                    return buf;
                }
                buffer = ByteBuffer.allocateDirect((int)size);
                
                // partially overlapped - copy overlapped data from segment
                final int offset = (int)(seg.byteSize() - overlap);
                buffer.put(0, seg.asByteBuffer(), offset, (int)overlap);
                buffer.position((int)overlap);
            }
            break;
        }
        
        while ((entry = segments.ceilingEntry(position)) != null) {
            final long key = entry.getKey();
            final MemorySegment seg = entry.getValue().get();
            if (seg == null) {
                segments.remove(key);
                continue;
            }
            
            final long shift = position + size - key;
            if (shift > 0) {
                // overlapping with segment
                final int sz = (int)(key - position);
                if (buffer == null) {
                    buffer = ByteBuffer.allocateDirect((int)size);
                    buffer.limit(sz);
                }
                buffer.put(sz, seg.asByteBuffer(), 0, (int)shift);
            }
        }

        if (buffer != null) {
            Logger.getLogger(Crypt4ghFileChannel.class.getName()).log(
                    Level.FINEST, String.format("overlapped segment %s - %s", 
                            position, position + size));
        
            // read the gap (between buffer position and its limit)
            for (long i, pos = position + buffer.position(); (i = read(buffer, pos)) > 0; pos += i) {}

            // create new memory segment for the overlapped buffer
            final MemorySegment s = MemorySegment.ofBuffer(buffer.limit(buffer.capacity()).rewind());
            final MemorySegment s2 = s.reinterpret(Arena.ofAuto(), new MemorySegmentCleaner(position));
            segments.put(position, new WeakReference(s2));
            buffer = s2.asByteBuffer();
        } else {
            // we always decript entire segments
            final long vpos = position & 0xFFFFFFFFFFFF0000L;
            final long vsiz = (size >> 16) * 65536 + 65536;

            buffer = ByteBuffer.allocateDirect((int)vsiz);
            for (long i, pos = vpos; (i = read(buffer, pos)) > 0; pos += i) {}
            buffer.rewind();

            final MemorySegment s = MemorySegment.ofBuffer(buffer);
            final MemorySegment s2 = s.reinterpret(Arena.ofAuto(), new MemorySegmentCleaner(vpos));
            segments.put(vpos, new WeakReference(s2));

            buffer = buffer.slice((int)(position - vpos), (int)size);
        }
        
        final FileLock lock = lock(position, size, false);
        locks.put(position, lock);
        
        return (MappedByteBuffer)buffer;
    }
    
    @Override
    public synchronized FileLock lock(long position, long size, boolean shared)
            throws IOException {
        
        if (header == null) {
            return channel.lock(position, size, shared);
        }
        
        if (closed) {
            throw new ClosedChannelException();
        }

        final long pos1 = header.getPosition(position);
        final long pos2 = header.getPosition(position + size);
        
        final FileLock lock = channel.lock(pos1, pos2 - pos1, shared);
        return new Crypt4ghFileLock(lock, this, position, size, shared);
    }

    @Override
    public synchronized FileLock tryLock(long position, long size, boolean shared)
            throws IOException {

        if (header == null) {
            return channel.tryLock(position, size, shared);
        }
        
        if (closed) {
            throw new ClosedChannelException();
        }

        final long pos1 = header.getPosition(position);
        final long pos2 = header.getPosition(position + size);
        
        final FileLock lock = channel.tryLock(pos1, pos2 - pos1, shared);
        return new Crypt4ghFileLock(lock, this, position, size, shared);

    }

    @Override
    protected void implCloseChannel() throws IOException {
        if (header == null || segments.isEmpty()) {
            channel.close();
        } else {
            // do not close the file if there are still some mapped segments.
            closed = true;
        }
    }

    /**
     * Increase file size if needed.
     * 
     * @param newFileSize new minimum file size
     */
    private void extend(long newFileSize) throws IOException {
        if (newFileSize > vsize) {
            // writing outside the file - fill with zeros
            final byte[] buf = new byte[(int)Math.min(newFileSize - vsize, 65536)];
            do {
                _write(ByteBuffer.wrap(buf, 0, (int)Math.min(newFileSize - vsize, 65536)), vsize);
            } while (newFileSize > vsize);
        }
    }
    
    private void flush(MemorySegment segment, long position) {
        if (!segment.isReadOnly()) {
            long endpos = position + segment.byteSize();

            long start = position; 
            long end = position;

            // calculate segment range to be flushed to the disk from mapped to this segment buffers
            Entry<Long, FileLock> entry;
            while ((entry = locks.ceilingEntry(start)) != null) {
                final long key = entry.getKey();
                final FileLock lock = entry.getValue();
                if (key + lock.size() > endpos) {
                    break;
                }
                // buffer is entirely within a segment
                start = Math.min(start, key);
                end = Math.max(end, key + lock.size());

                // release lock
                locks.remove(key);
                try {
                    lock.release();
                } catch (IOException ex) {}
            }

            final ByteBuffer buf = segment.asSlice(start - position, end - start).asByteBuffer();

            Logger.getLogger(Crypt4ghFileChannel.class.getName()).log(
                    Level.FINEST, String.format("flush segment %s - %s", start, end));

            try {
                _write(buf, start);
            } catch (IOException ex) {
                Logger.getLogger(Crypt4ghFileChannel.class.getName()).log(
                    Level.WARNING, String.format("error flushing segment %s - %s", start, end));
            }
        }
    }
    
    final class MemorySegmentCleaner implements Consumer<MemorySegment> {

        private final long position;
        
        public MemorySegmentCleaner(long position) {
            this.position = position;
        }
        
        @Override
        public void accept(MemorySegment segment) {
            flush(segment, position);
            segments.remove(position);
            
            if (closed && segments.isEmpty()) {
                try {
                    channel.close();
                } catch (IOException ex) {}
            }
        }
    }
}
