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

package es.bsc.inb.ga4gh.jcrypt4gh.security;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Dmitry Repchevsky
 */

public class Poly1305Test {

    public final static String TEXT =
            """
Finally, the value of the secret key 's' is added to the accumulator,
and the 128 least significant bits are serialized in little-endian
order to form the tag...
            """;

    @Test
    public void poly1305AEAD() throws GeneralSecurityException {
        byte[] data = TEXT.getBytes();
        byte[] key = new byte[32];
        byte[] nonce = new byte[12];
       
        new SecureRandom().nextBytes(key);
        new SecureRandom().nextBytes(nonce);

        final Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
        final SecretKey sk = new SecretKeySpec(key, "ChaCha20");
        cipher.init(Cipher.ENCRYPT_MODE, sk, new IvParameterSpec(nonce));

        final byte[] encrypted = cipher.doFinal(data);
       
        final Mac mac = Mac.getInstance("Poly1305", new Crypt4ghSecurityProvider());

        mac.init(sk, new IvParameterSpec(nonce));
        byte[] tag = mac.doFinal(Arrays.copyOf(encrypted, data.length));
        
        Assertions.assertArrayEquals(Arrays.copyOfRange(encrypted, data.length, 
                encrypted.length), tag, "invalid Poly1305 AEAD tag.");
    }
}
