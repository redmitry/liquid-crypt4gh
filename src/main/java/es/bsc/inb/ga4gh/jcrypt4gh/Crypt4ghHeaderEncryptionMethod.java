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

import java.io.IOException;
import java.nio.channels.ReadableByteChannel;

/**
 * @author Dmitry Repchevsky
 */

public enum Crypt4ghHeaderEncryptionMethod {
    X25519_CHACHA20_IETF_POLY1305(0, 12, 32, 16);
    
    public final int CODE;
    public final int KEY_SIZE;
    public final int NONCE_SIZE;
    public final int MAC_SIZE;
    
    Crypt4ghHeaderEncryptionMethod(int code, int szKey, int szNonce, int szMac) {
        CODE = code;
        KEY_SIZE = szKey;
        NONCE_SIZE = szNonce;
        MAC_SIZE = szMac;
    }

    public static Crypt4ghHeaderEncryptionMethod read(ReadableByteChannel ch) throws IOException {
        switch((int)Crypt4ghHeaherElement.readUnsignedInt(ch)) {
            case 0: return X25519_CHACHA20_IETF_POLY1305;
        }
        throw new IOException("unsupported crypt4gh encryption method");
    }
}
