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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.MacSpi;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.ChaCha20ParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public final class Poly1305 extends MacSpi {
    
    private static final int BLOCK_SIZE = 16;
    
    private int r0, r1, r2, r3, r4;
    private long s0, s1, s2, s3;
    private long a0, a1, a2, a3, a4;
    
    private int count;
    private final byte[] block = new byte[BLOCK_SIZE];

    private boolean AEAD;
    
    private void processBlock() {

        final long t0 = (block[0] & 0xFF) | (block[1] & 0xFF) << 8 | (block[2] & 0xFF) << 16 | (block[3] & 0xFF) << 24 & 0xffffffffL;
        final long t1 = (block[4] & 0xFF) | (block[5] & 0xFF) << 8 | (block[6] & 0xFF) << 16 | (block[7] & 0xFF) << 24 & 0xffffffffL;
        final long t2 = (block[8] & 0xFF) | (block[9] & 0xFF) << 8 | (block[10] & 0xFF) << 16 | (block[11] & 0xFF) << 24 & 0xffffffffL;
        final long t3 = (block[12] & 0xFF) | (block[13] & 0xFF) << 8 | (block[14] & 0xFF) << 16 | (block[15] & 0xFF) << 24 & 0xffffffffL;

        a0 += t0 & 0x3ffffff;
        a1 += (((t1 << 32) | t0) >>> 26) & 0x3ffffff;
        a2 += (((t2 << 32) | t1) >>> 20) & 0x3ffffff;
        a3 += (((t3 << 32) | t2) >>> 14) & 0x3ffffff;
        a4 += (t3 >>> 8);

        if ((count & 0x0F) == 0) {
            a4 += (1 << 24);
        }

        // r * a
        long tp0 = a0 * r0 + (a1 * r4 + a2 * r3 + a3 * r2 + a4 * r1) * 5;
        long tp1 = a0 * r1 + a1 * r0 + (a2 * r4 + a3 * r3 + a4 * r2) * 5;
        long tp2 = a0 * r2 + a1 * r1 + a2 * r0 + (a3 * r4 + a4 * r3) * 5;
        long tp3 = a0 * r3 + a1 * r2 + a2 * r1 + a3 * r0 + a4 * r4 * 5;
        long tp4 = a0 * r4 + a1 * r3 + a2 * r2 + a3 * r1 + a4 * r0;

        a0 = tp0 & 0x3ffffff; tp1 += (tp0 >>> 26);
        a1 = tp1 & 0x3ffffff; tp2 += (tp1 >>> 26);
        a2 = tp2 & 0x3ffffff; tp3 += (tp2 >>> 26);
        a3 = tp3 & 0x3ffffff; tp4 += (tp3 >>> 26);
        a4 = tp4 & 0x3ffffff;
        a0 += (tp4 >>> 26) * 5;
        a1 += (a0 >>> 26); 
        a0 &= 0x3ffffff;
    }

    @Override
    protected int engineGetMacLength() {
        return BLOCK_SIZE;
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params) 
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        
        final byte[] r;
        if (params instanceof IvParameterSpec iv) {
            final byte[] nonce = iv.getIV();
            try {
                final Cipher cipher = Cipher.getInstance("ChaCha20");
                cipher.init(Cipher.ENCRYPT_MODE, key, new ChaCha20ParameterSpec(nonce, 0));
                r = Arrays.copyOf(cipher.doFinal(new byte[1024]), 32);
                AEAD = true;
            } catch (NoSuchAlgorithmException | NoSuchPaddingException |
                    IllegalBlockSizeException | BadPaddingException ex) {
                throw new InvalidAlgorithmParameterException("No 'ChaCha20' for IV", ex);
            }
        } else {
            AEAD = false;
            r = key.getEncoded();
        }
        
        if (r.length != 32) {
            throw new IllegalArgumentException("Poly1305 key must be 256 bits.");
        }

        // r = 0x0ffffffc0ffffffc0ffffffc0fffffff
        
        // r[00] ....dddd cccccccc bbbbbbbb aaaaaaaa
        // r[04] ....hhhh gggggggg ffffffff eeeeee..
        // r[08] ....llll kkkkkkkk jjjjjjjj iiiiii..
        // r[12] ....pppp oooooooo nnnnnnnn mmmmmm..
        
        // r0   ______dd cccccccc bbbbbbbb aaaaaaaa
        // r1   ______gg ggffffff ffeeeeee ......dd
        // r2   ______jj jjjjiiii ii...... hhhhgggg
        // r3   ______mm mmmm.... ..llllkk kkkkkkjj
        // r4   ________ ....pppp oooooooo nnnnnnnn
        
        r0 = (r[0] & 0xFF) | (r[1] & 0xFF) << 8 | (r[2] & 0xFF) << 16 | (r[3] & 0x03) << 24;
        r1 = (r[3] & 0x0F) >>> 2 | (r[4] & 0xFC) << 6 | (r[5] & 0xFF) << 14 | (r[6] & 0x0F) << 22;
        r2 = (r[6] & 0xF0) >>> 4 | (r[7] & 0x0F) << 4 | (r[8] & 0xFC) << 12 | (r[9] & 0x3F) << 20;
        r3 = (r[9] & 0xC0) >>> 6 | (r[10] & 0xFF) << 2 | (r[11] & 0x0F) << 10 | (r[12] & 0xFC) << 18;
        r4 = (r[13] & 0xFF) | (r[14] & 0xFF) << 8 | (r[15] & 0x0F) << 16;

        s0 = (r[16] & 0xFF) | (r[17] & 0xFF) << 8 | (r[18] & 0xFF) << 16 | (r[19] & 0xFF) << 24 & 0xffffffffl;
        s1 = (r[20] & 0xFF) | (r[21] & 0xFF) << 8 | (r[22] & 0xFF) << 16 | (r[23] & 0xFF) << 24 & 0xffffffffl;
        s2 = (r[24] & 0xFF) | (r[25] & 0xFF) << 8 | (r[26] & 0xFF) << 16 | (r[27] & 0xFF) << 24 & 0xffffffffl;
        s3 = (r[28] & 0xFF) | (r[29] & 0xFF) << 8 | (r[30] & 0xFF) << 16 | (r[31] & 0xFF) << 24 & 0xffffffffl;
        
        engineReset();
    }

    @Override
    protected void engineUpdate(byte in) {
        if ((count & 0x0F) == 0 && count > 0) {
            processBlock();
        }
        block[count++ & 0x0F] = in;
    }

    @Override
    protected void engineUpdate(byte[] in, int off, int len) {
        final int end = off + len;
        while (off < end) {
            if ((count & 0x0F) == 0 & count > 0) {
                processBlock();
            }

            int sz = Math.min(end - off, BLOCK_SIZE - (count & 0x0F));
            System.arraycopy(in, off, block, count & 0x0F, sz);
            count += sz;
            off += sz;
        }
    }

    @Override
    protected byte[] engineDoFinal() {
        if (AEAD) {
            final long length = count;
            
            // pad16
            while ((count & 0x0F) != 0) {
                engineUpdate((byte)0);
            }
            
            engineUpdate(new byte[Long.BYTES], 0, Long.BYTES); //  AAD.length = 0
            engineUpdate(ByteBuffer.allocate(Long.BYTES).order(ByteOrder.LITTLE_ENDIAN).putLong(length).array(), 0, Long.BYTES);
        }

        if (count > 0) {
            if ((count & 0x0F) != 0) {
                block[count & 0x0F] = 1;
                Arrays.fill(block, (count & 0x0F) + 1, BLOCK_SIZE, (byte)0);
            }
            processBlock();
        }

        // pack back accumulator and add 's'
        long t0 = (((a0       ) | (a1 << 26)) & 0xffffffffl) + s0;
        long t1 = (((a1 >>> 6 ) | (a2 << 20)) & 0xffffffffl) + s1;
        long t2 = (((a2 >>> 12) | (a3 << 14)) & 0xffffffffl) + s2;
        long t3 = (((a3 >>> 18) | (a4 << 8 )) & 0xffffffffl) + s3;

        t1 += (t0 >>> 32);
        t2 += (t1 >>> 32);
        t3 += (t2 >>> 32);
        
        return new byte[] {
            (byte)(t0 & 0xFF), (byte)(t0 >>> 8 & 0xFF), (byte)(t0 >>> 16 & 0xFF), (byte)(t0 >>> 24 & 0xFF),
            (byte)(t1 & 0xFF), (byte)(t1 >>> 8 & 0xFF), (byte)(t1 >>> 16 & 0xFF), (byte)(t1 >>> 24 & 0xFF),
            (byte)(t2 & 0xFF), (byte)(t2 >>> 8 & 0xFF), (byte)(t2 >>> 16 & 0xFF), (byte)(t2 >>> 24 & 0xFF),
            (byte)(t3 & 0xFF), (byte)(t3 >>> 8 & 0xFF), (byte)(t3 >>> 16 & 0xFF), (byte)(t3 >>> 24 & 0xFF),
        };
    }

    @Override
    protected void engineReset() {
        count = 0;
        a0 = a1 = a2 = a3 = a4 = 0;
    }
}
