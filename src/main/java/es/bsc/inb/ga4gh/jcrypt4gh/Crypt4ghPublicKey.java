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

package es.bsc.inb.ga4gh.jcrypt4gh;

import java.math.BigInteger;
import java.security.interfaces.XECPublicKey;
import java.security.spec.NamedParameterSpec;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghPublicKey implements XECPublicKey {

    private final byte[] key;
    private final BigInteger u;

    public Crypt4ghPublicKey(BigInteger u) {
        this.u = u;
        
        key = u.toByteArray();
        for (int i = 0, n = key.length; i < n; key[i] ^= key[--n], key[n] ^= key[i], key[i++] ^= key[n]) {}
    }

    public Crypt4ghPublicKey(byte[] key) {
        this.key = key;
        
        final byte[] arr = new byte[key.length];
        for (int i = 0, n = key.length - 1; n > 0; i++, n--) {
            arr[i] = key[n];
        }
        
        u = new BigInteger(arr);

    }
    
    @Override
    public BigInteger getU() {
        return u;
    }

    @Override
    public NamedParameterSpec getParams() {
        return NamedParameterSpec.X25519;
    }

    @Override
    public String getAlgorithm() {
        return "XDH";
    }

    @Override
    public String getFormat() {
        return "Cryt4GH";
    }

    @Override
    public byte[] getEncoded() {
        return key;
    }
    
    public static byte[] getKey(XECPublicKey key) {
        final byte[] arr = key.getU().toByteArray();
        for (int i = 0, n = arr.length; i < n; arr[i] ^= arr[--n], arr[n] ^= arr[i], arr[i++] ^= arr[n]) {}
        return arr;
    }
}
