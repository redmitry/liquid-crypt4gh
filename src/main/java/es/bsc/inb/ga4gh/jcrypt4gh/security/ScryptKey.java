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

package es.bsc.inb.ga4gh.jcrypt4gh.security;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.IntBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

/**
 * RFC 7914 Scrypt Algorithm implementation.
 * 
 * @author Dmitry Repchevsky
 */

public class ScryptKey implements SecretKey {

    public final static String ALGORITHM = "SCRYPT";
    
    private byte[] key;
    
    public ScryptKey(ScryptKeySpec spec) {

        try {
            final SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            final byte[] kdf = f.generateSecret(new PBEKeySpec(
                    spec.passphrase, spec.salt, 1, spec.p * spec.blockSize * 1024))
                    .getEncoded();
            
            for (int i = 0, sz = spec.blockSize << 7; i < spec.p; i++) {
                final ByteBuffer buf = ByteBuffer.wrap(kdf, i * sz, sz)
                        .order(ByteOrder.LITTLE_ENDIAN);
                scryptROMix(buf, buf, spec.blockSize, spec.cost);
            }
            
            key = f.generateSecret(
                    new PBEKeySpec(spec.passphrase, kdf, 1, spec.keyLength << 3))
                    .getEncoded();
            
        } catch (NoSuchAlgorithmException | InvalidKeySpecException ex) {
            Logger.getLogger(ScryptKey.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
    @Override
    public String getAlgorithm() {
        return ALGORITHM;
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public byte[] getEncoded() {
        return key;
    }
    
    /**
     * The Salsa20/8 Core Function
     * 
     * @param blk - input array
     * @param off - offset of the array
     * 
     */
    static void salsa20(int[] blk, int off) {

        int[] copy = Arrays.copyOfRange(blk, off, off + 16);
        
        for (int i = 8; i > 0; i -= 2) {
            blk[off + 4] ^= Integer.rotateLeft(blk[off] + blk[off + 12], 7);
            blk[off + 8] ^= Integer.rotateLeft(blk[off + 4] + blk[off], 9);
            blk[off + 12] ^= Integer.rotateLeft(blk[off + 8] + blk[off + 4], 13);
            blk[off] ^= Integer.rotateLeft(blk[off + 12] + blk[off + 8], 18);
            blk[off + 9] ^= Integer.rotateLeft(blk[off + 5] + blk[off + 1], 7);
            blk[off + 13] ^= Integer.rotateLeft(blk[off + 9] + blk[off + 5], 9);
            blk[off + 1] ^= Integer.rotateLeft(blk[ off + 13] + blk[off + 9], 13);
            blk[off + 5] ^= Integer.rotateLeft(blk[off + 1] + blk[off + 13], 18);
            blk[off + 14] ^= Integer.rotateLeft(blk[off + 10] + blk[off + 6], 7);
            blk[off + 2] ^= Integer.rotateLeft(blk[off + 14] + blk[off + 10], 9);
            blk[off + 6] ^= Integer.rotateLeft(blk[off + 2] + blk[off + 14], 13);
            blk[off + 10] ^= Integer.rotateLeft(blk[off + 6] + blk[off + 2], 18);
            blk[off + 3] ^= Integer.rotateLeft(blk[off + 15] + blk[off + 11], 7);
            blk[off + 7] ^= Integer.rotateLeft(blk[off + 3] + blk[off + 15], 9);
            blk[off + 11] ^= Integer.rotateLeft(blk[off + 7] + blk[off + 3], 13);
            blk[off + 15] ^= Integer.rotateLeft(blk[off + 11] + blk[off + 7], 18);
            
            blk[off + 1] ^= Integer.rotateLeft(blk[off] + blk[off + 3], 7);
            blk[off + 2] ^= Integer.rotateLeft(blk[off + 1] + blk[off], 9);
            blk[off + 3] ^= Integer.rotateLeft(blk[off + 2] + blk[off + 1], 13);
            blk[off] ^= Integer.rotateLeft(blk[off + 3] + blk[off + 2], 18);
            blk[off + 6] ^= Integer.rotateLeft(blk[off + 5] + blk[off + 4], 7);
            blk[off + 7] ^= Integer.rotateLeft(blk[off + 6] + blk[off + 5], 9);
            blk[off + 4] ^= Integer.rotateLeft(blk[off + 7] + blk[off + 6], 13);
            blk[off + 5] ^= Integer.rotateLeft(blk[off + 4] + blk[off + 7], 18);
            blk[off + 11] ^= Integer.rotateLeft(blk[off + 10] + blk[off + 9], 7);
            blk[off + 8] ^= Integer.rotateLeft(blk[off + 11] + blk[off + 10], 9);
            blk[off + 9] ^= Integer.rotateLeft(blk[off + 8] + blk[off + 11], 13);
            blk[off + 10] ^= Integer.rotateLeft(blk[off + 9] + blk[off +8], 18);
            blk[off + 12] ^= Integer.rotateLeft(blk[off + 15] + blk[off + 14], 7);
            blk[off + 13] ^= Integer.rotateLeft(blk[off + 12] + blk[off + 15], 9);
            blk[off + 14] ^= Integer.rotateLeft(blk[off + 13] + blk[off + 12], 13);
            blk[off + 15] ^= Integer.rotateLeft(blk[off + 14] + blk[off + 13], 18);
        }

        for (int i = 0; i < 16; i++) {
            blk[off++] += copy[i];
        }
    }
    
    /**
     * Mix 16 int blocks in the input buffer (in.remaining starting from in.position).
     * 
     * @param in integer buffer to read blocks from
     * @param out integer buffer to write to (may be the same as the input)
     */
    static void scryptBlockMix(IntBuffer in, IntBuffer out) {
        
        final int blen = in.remaining();
        final int opos = out.position();
        
        final int[] y = new int[blen];
        in.get(in.position() + blen - 16, y, 0, 16); // Y[0] = B[2 * r - 1] 

        for (int i = 0, m = 0, n = 0, h = blen >> 1; i < blen; n = m, m = ((i & 0xFFFFFEF) >> 1) + h * (i >> 4 & 1)) {
            for (int j = m; j < m + 16; i++) {
                y[j++] = y[n++] ^ in.get();
            }
            salsa20(y, m);
        }
        
        out.put(opos, y);
    }
    
    /**
     * scryptROMix Algorithm RFC 7914 section 5.
     * 
     * @param in input data
     * @param out output data
     * @param blockSize block size parameter
     * @param cost cpu/memory cost parameter
     */
    static void scryptROMix(ByteBuffer in, ByteBuffer out, int blockSize, int cost) {
        
        final int bsize = in.remaining() >> 2;
        final int blen = bsize * cost;
        
        final int[] v = new int[blen + bsize];
        in.asIntBuffer().get(v, 0, bsize); // V[0] = B[0]
        
        for (int i = 0; i < blen; i += bsize) {
            scryptBlockMix(IntBuffer.wrap(v, i, bsize), IntBuffer.wrap(v, i + bsize, bsize));
        }

        for (int i = 0; i < cost; i++) {
            int j = bsize * (v[v.length - 16] & (cost - 1)); //  cost is power of 2
            for (int k = blen; k < v.length; k++) {
                v[k] ^= v[j++];
            }
            final IntBuffer buf = IntBuffer.wrap(v, blen, bsize);
            scryptBlockMix(buf, buf);
        }
        
        out.asIntBuffer().put(v, blen, bsize);
    }
}
