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

import java.util.Objects;

/**
 * Crypt4GH keys properties loader.
 * Keeps keys properties together to simplify Crypt4GH keys loading.
 * 
 * @author Dmitry Repchevsky
 */

public final class Crypt4ghConfig {
    
    public final static String CRYPT4GH_PASSPHRASE_PROPERTY = "CRYPT4GH_PASSPHRASE";
    public final static String CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY = "CRYPT4GH_PRIVATE_KEY_FILE";
    public final static String CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY = "CRYPT4GH_PUBLIC_KEY_FILE";

    public final String passphrase;
    public final String private_key_file;
    public final String public_key_file;
    
    private Crypt4ghConfig(String private_key_file, String public_key_file,
            String passphrase) {
        this.private_key_file = private_key_file;
        this.public_key_file = public_key_file;
        this.passphrase = passphrase;
    }
    
    public static Crypt4ghConfig load() {
        String sk = System.getProperty(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY);
        if (sk == null) {
            sk = System.getenv(CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY);
        }
        
        if (sk == null) {
            return null;
//            throw new Crypt4ghException(
//                    String.format("error: no secret key provided ('%s' property)", 
//                            CRYPT4GH_PRIVATE_KEY_FILE_PROPERTY));
        }
        
        String pk = System.getProperty(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY);
        if (pk == null) {
            pk = System.getenv(CRYPT4GH_PUBLIC_KEY_FILE_PROPERTY);
        }

        final String passphrase = System.getProperty(CRYPT4GH_PASSPHRASE_PROPERTY);
        
        return new Crypt4ghConfig(sk, pk, passphrase);
    }

    @Override
    public boolean equals(Object obj) {
        return this == obj || obj instanceof Crypt4ghConfig other &&
                Objects.equals(this.private_key_file, other.private_key_file) &&
                Objects.equals(this.public_key_file, other.public_key_file) &&
                Objects.equals(this.passphrase, other.passphrase);
    }

    @Override
    public int hashCode() {
        int hash = 7;
        hash = 97 * hash + Objects.hashCode(this.private_key_file);
        hash = 97 * hash + Objects.hashCode(this.public_key_file);
        hash = 97 * hash + Objects.hashCode(this.passphrase);
        return hash;
    }
}
