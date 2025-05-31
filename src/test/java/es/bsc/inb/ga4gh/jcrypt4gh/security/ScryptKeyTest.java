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

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HexFormat;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/**
 * @author Dmitry Repchevsky
 */

public class ScryptKeyTest {

    private final static String SALSA20_INPUT = 
            "7E879A214F3EC9867CA940E641718F26" +
            "BAEE555B8C61C1B50DF846116DCD3B1D" +
            "EE24F319DF9B3D8514121E4B5AC5AA32" +
            "76021D2909C74829EDEBC68DB8B8C25E";
    
    private final static String SALSA20_OUTPUT = 
            "A41F859C6608CC993B81CACB020CEF05" +
            "044B2181A2FD337DFD7B1C6396682F29" +
            "B4393168E3C9E6BCFE6BC5B7A06D96BA" +
            "E424CC102C91745C24AD673DC7618F81";
    
    private final static String SCRYPT_BLOCK_MIX_INPUT = 
            "F7CE0B653D2D72A4108CF5ABE912FFDD" +
            "777616DBBB27A70E8204F3AE2D0F6FAD" +
            "89F68F4811D1E87BCC3BD7400A9FFD29" +
            "094F0184639574F39AE5A1315217BCD7" +
            "894991447213BB226C25B54DA86370FB" +
            "CD984380374666BB8FFCB5BF40C254B0" +
            "67D27C51CE4AD5FED829C90B505A571B" +
            "7F4D1CAD6A523CDA770E67BCEAAF7E89";
    
    private final static String SCRYPT_BLOCK_MIX_OUTPUT = 
           "A41F859C6608CC993B81CACB020CEF05" + 
           "044B2181A2FD337DFD7B1C6396682F29" +
           "B4393168E3C9E6BCFE6BC5B7A06D96BA" +
           "E424CC102C91745C24AD673DC7618F81" +
           "20EDC975323881A80540F64C162DCD3C" +
           "21077CFE5F8D5FE2B1A4168F953678B7" +
           "7D3B3D803B60E4AB920996E59B4D53B6" +
           "5D2A225877D5EDF5842CB9F14EEFE425";
    
    private final static String SCRYPT_ROMIX_INPUT = 
            "F7CE0B653D2D72A4108CF5ABE912FFDD" +
            "777616DBBB27A70E8204F3AE2D0F6FAD" +
            "89F68F4811D1E87BCC3BD7400A9FFD29" +
            "094F0184639574F39AE5A1315217BCD7" +
            "894991447213BB226C25B54DA86370FB" +
            "CD984380374666BB8FFCB5BF40C254B0" +
            "67D27C51CE4AD5FED829C90B505A571B" +
            "7F4D1CAD6A523CDA770E67BCEAAF7E89";
    
    private final static String SCRYPT_ROMIX_OUTPUT =
            "79CCC193629DEBCA047F0B70604BF6B6" +
            "2CE3DD4A9626E355FAFC6198E6EA2B46" +
            "D58413673B99B029D665C357601FB426" +
            "A0B2F4BBA200EE9F0A43D19B571A9C71" +
            "EF1142E65D5A266FDDCA832CE59FAA7C" +
            "AC0B9CF1BE2BFFCA300D01EE387619C4" +
            "AE12FD4438F203A0E4E1C47EC314861F" +
            "4E9087CB33396A6873E8F9D2539A4B8E";

    private final static String SCRYPT_VECTOR2_OUTPUT =
            "FDBABE1C9D3472007856E7190D01E9FE" +
            "7C6AD7CBC8237830E77376634B373162" +
            "2EAF30D92E22A3886FF109279D9830DA" +
            "C727AFB94A83EE6D8360CBDFA2CC0640";
            
    @Test
    public void slasa20() {
        final byte[] v1 = HexFormat.of().parseHex(SALSA20_INPUT);
        final byte[] v2 = HexFormat.of().parseHex(SALSA20_OUTPUT);
        
        final int[] tst = new int[v1.length >> 2];
        ByteBuffer.wrap(v1).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(tst);

        final int[] res = new int[v2.length >> 2];
        ByteBuffer.wrap(v2).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer().get(res);
        
        ScryptKey.salsa20(tst, 0);
        
        Assertions.assertArrayEquals(tst, res, "inequal arrays");
    }
    
    @Test
    public void scryptBlockMix() {
        
        final byte[] b = HexFormat.of().parseHex(SCRYPT_BLOCK_MIX_INPUT);
        final byte[] o = HexFormat.of().parseHex(SCRYPT_BLOCK_MIX_OUTPUT);
        
        final byte[] res = new byte[b.length];
        ScryptKey.scryptBlockMix(ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer(),
                ByteBuffer.wrap(res).order(ByteOrder.LITTLE_ENDIAN).asIntBuffer());
        
        Assertions.assertArrayEquals(o, res, "inequal arrays");
    }
    
    @Test
    public void scryptROMix() {
        final byte[] b = HexFormat.of().parseHex(SCRYPT_ROMIX_INPUT);
        final byte[] o = HexFormat.of().parseHex(SCRYPT_ROMIX_OUTPUT);
        
        ByteBuffer buf = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN);
        
        ScryptKey.scryptROMix(buf, buf, 1, 16);
        
        Assertions.assertArrayEquals(o, b, "inequal arrays");
    }
    
    @Test
    public void scrypt() {
        ScryptKeySpec spec = new ScryptKeySpec("password", "NaCl".getBytes(), 1024, 8, 16, 64);
        ScryptKey key  = new ScryptKey(spec);
        byte[] res = key.getEncoded();
        
        final byte[] o = HexFormat.of().parseHex(SCRYPT_VECTOR2_OUTPUT);
        Assertions.assertArrayEquals(o, res, "inequal arrays");
    }
}
