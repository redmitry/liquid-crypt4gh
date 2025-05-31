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

import java.security.spec.KeySpec;

/**
 * @author Dmitry Repchevsky
 */

public class ScryptKeySpec implements KeySpec {
    
    public final char[] passphrase;
    public final byte[] salt;
    public final int cost;
    public final int blockSize;
    public final int p;
    public final int keyLength;
    
    public ScryptKeySpec(String passphrase, byte[] salt, int cost, 
            int blockSize, int p, int keyLength) {
        this(passphrase == null ? null : passphrase.toCharArray(), 
                salt, cost, blockSize, p, keyLength);
    }
    
    public ScryptKeySpec(char[] passphrase, byte[] salt, int cost, 
            int blockSize, int p, int keyLength) {
        this.passphrase = passphrase;
        this.salt = salt;
        this.cost = cost;
        this.blockSize = blockSize;
        this.p = p;
        this.keyLength = keyLength;
    }

}
