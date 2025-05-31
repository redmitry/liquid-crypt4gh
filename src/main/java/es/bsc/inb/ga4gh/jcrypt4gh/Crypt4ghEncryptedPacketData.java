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
import java.io.IOException;
import java.nio.channels.ReadableByteChannel;

/**
 * @author Dmitry Repchevsky
 */

public abstract class Crypt4ghEncryptedPacketData implements Crypt4ghHeaherElement {
    
    public final Crypt4ghDataPacketType type;
    
    public Crypt4ghEncryptedPacketData(Crypt4ghDataPacketType type) {
        this.type = type;
    }
    
    public abstract int size();
    public abstract byte[] getPayload();

    public static Crypt4ghEncryptedPacketData create(ReadableByteChannel ch)
        throws IOException {
        final Crypt4ghDataPacketType packet_type = Crypt4ghDataPacketType.read(ch);
        switch(packet_type) {
            case DATA_ENCRYPTION_KEY: return new Crypt4ghDataEncryptionKey(ch);
            case DATA_EDIT_LIST: return new Crypt4ghDataEditList(ch);
        }
        throw new IOException("invalid packet type");
    }
}
