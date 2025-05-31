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

import static es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghDataPacketType.DATA_EDIT_LIST;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.channels.ReadableByteChannel;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghDataEditList extends Crypt4ghEncryptedPacketData {
    
    private long[] lengths;

    public Crypt4ghDataEditList(ReadableByteChannel ch) 
            throws IOException {
        super(DATA_EDIT_LIST);
        
        final int numberLengths = (int)Crypt4ghHeaherElement.readUnsignedInt(ch);
        final ByteBuffer buf = ByteBuffer.allocate(numberLengths * Long.BYTES);
        lengths = Crypt4ghHeaherElement.read(ch, buf).asLongBuffer().array();
    }
    
    /**
     * Return the "data edit list packet" size.
     * (packet type + number of lengths + lengths * 8)
     * 
     * @return the size
     */
    @Override
    public int size() {
        return 4 + 4 + lengths.length * Long.BYTES;
    }
    
    @Override
    public byte[] getPayload() {
        final byte[] payload = new byte[size()];
        ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN)
                .putInt(DATA_EDIT_LIST.TYPE)
                .putInt(lengths.length)
                .asLongBuffer().put(lengths);
        return payload;
    }
}
