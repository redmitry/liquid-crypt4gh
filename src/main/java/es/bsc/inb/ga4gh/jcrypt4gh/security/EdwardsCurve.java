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

/**
 * @author Dmitry Repchevsky
 */

public class EdwardsCurve {
    
    public static byte[] convertPublicKey(byte[] pub) {
        int [] z = new int[] {1, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int[] y = fromBytes(pub);
        
        int[] tx = add(z, y);
        int[] tz = sub(z, y);
        
        invert(tz, tz);
        int[] x = mul(tx, tz);

        return toBytes(x);
    }
        
    private static int[] add(int[] a, int[] b) {
        int[] e = new int[10];
        for (int i = 0; i < e.length; i++) {
            e[i] = a[i] + b[i];
        }
        return e;
    }
    
    private static int[] sub(int[] a, int[] b) {
        int[] e = new int[10];
        for (int i = 0; i < e.length; i++) {
            e[i] = a[i] - b[i];
        }
        return e;
    }
    
    private static int[] mul(int[] f, int[] g) {
        return mul(new int[10], f, g);
    }
    
    private static int[] mul(int[] h, int[] f, int[] g) {
        int f0 = f[0];
        int f1 = f[1];
        int f2 = f[2];
        int f3 = f[3];
        int f4 = f[4];
        int f5 = f[5];
        int f6 = f[6];
        int f7 = f[7];
        int f8 = f[8];
        int f9 = f[9];
        
        int g0 = g[0];
        int g1 = g[1];
        int g2 = g[2];
        int g3 = g[3];
        int g4 = g[4];
        int g5 = g[5];
        int g6 = g[6];
        int g7 = g[7];
        int g8 = g[8];
        int g9 = g[9];
        
        int g1_19 = 19 * g1;
        int g2_19 = 19 * g2;
        int g3_19 = 19 * g3;
        int g4_19 = 19 * g4;
        int g5_19 = 19 * g5;
        int g6_19 = 19 * g6;
        int g7_19 = 19 * g7;
        int g8_19 = 19 * g8;
        int g9_19 = 19 * g9;
        
        int f1_2 = 2 * f1;
        int f3_2 = 2 * f3;
        int f5_2 = 2 * f5;
        int f7_2 = 2 * f7;
        int f9_2 = 2 * f9;
        
        long f0g0 = f0 * (long)g0;
        long f0g1 = f0 * (long)g1;
        long f0g2 = f0 * (long)g2;
        long f0g3 = f0 * (long)g3;
        long f0g4 = f0 * (long)g4;
        long f0g5 = f0 * (long)g5;
        long f0g6 = f0 * (long)g6;
        long f0g7 = f0 * (long)g7;
        long f0g8 = f0 * (long)g8;
        long f0g9 = f0 * (long)g9;
        long f1g0 = f1 * (long)g0;
        long f1g1_2 = f1_2 * (long)g1;
        long f1g2 = f1 * (long)g2;
        long f1g3_2 = f1_2 * (long)g3;
        long f1g4 = f1 * (long)g4;
        long f1g5_2 = f1_2 * (long)g5;
        long f1g6 = f1 * (long)g6;
        long f1g7_2 = f1_2 * (long)g7;
        long f1g8 = f1 * (long)g8;
        long f1g9_38 = f1_2 * (long)g9_19;
        long f2g0 = f2 * (long)g0;
        long f2g1 = f2 * (long)g1;
        long f2g2 = f2 * (long)g2;
        long f2g3 = f2 * (long)g3;
        long f2g4 = f2 * (long)g4;
        long f2g5 = f2 * (long)g5;
        long f2g6 = f2 * (long)g6;
        long f2g7 = f2 * (long)g7;
        long f2g8_19 = f2 * (long)g8_19;
        long f2g9_19 = f2 * (long)g9_19;
        long f3g0 = f3 * (long)g0;
        long f3g1_2 = f3_2 * (long)g1;
        long f3g2 = f3 * (long)g2;
        long f3g3_2 = f3_2 * (long)g3;
        long f3g4 = f3 * (long)g4;
        long f3g5_2 = f3_2 * (long)g5;
        long f3g6 = f3 * (long)g6;
        long f3g7_38 = f3_2 * (long)g7_19;
        long f3g8_19 = f3 * (long)g8_19;
        long f3g9_38 = f3_2 * (long)g9_19;
        long f4g0 = f4 * (long)g0;
        long f4g1 = f4 * (long)g1;
        long f4g2 = f4 * (long)g2;
        long f4g3 = f4 * (long)g3;
        long f4g4 = f4 * (long)g4;
        long f4g5 = f4 * (long)g5;
        long f4g6_19 = f4 * (long)g6_19;
        long f4g7_19 = f4 * (long)g7_19;
        long f4g8_19 = f4 * (long)g8_19;
        long f4g9_19 = f4 * (long)g9_19;
        long f5g0 = f5 * (long)g0;
        long f5g1_2 = f5_2 * (long)g1;
        long f5g2 = f5 * (long)g2;
        long f5g3_2 = f5_2 * (long)g3;
        long f5g4 = f5 * (long)g4;
        long f5g5_38 = f5_2 * (long)g5_19;
        long f5g6_19 = f5 * (long)g6_19;
        long f5g7_38 = f5_2 * (long)g7_19;
        long f5g8_19 = f5 * (long)g8_19;
        long f5g9_38 = f5_2 * (long)g9_19;
        long f6g0 = f6 * (long)g0;
        long f6g1 = f6 * (long)g1;
        long f6g2 = f6 * (long)g2;
        long f6g3 = f6 * (long)g3;
        long f6g4_19 = f6 * (long)g4_19;
        long f6g5_19 = f6 * (long)g5_19;
        long f6g6_19 = f6 * (long)g6_19;
        long f6g7_19 = f6 * (long)g7_19;
        long f6g8_19 = f6 * (long)g8_19;
        long f6g9_19 = f6 * (long)g9_19;
        long f7g0 = f7 * (long)g0;
        long f7g1_2 = f7_2 * (long)g1;
        long f7g2 = f7 * (long)g2;
        long f7g3_38 = f7_2 * (long)g3_19;
        long f7g4_19 = f7 * (long)g4_19;
        long f7g5_38 = f7_2 * (long)g5_19;
        long f7g6_19 = f7 * (long)g6_19;
        long f7g7_38 = f7_2 * (long)g7_19;
        long f7g8_19 = f7 * (long)g8_19;
        long f7g9_38 = f7_2 * (long)g9_19;
        long f8g0 = f8 * (long)g0;
        long f8g1 = f8 * (long)g1;
        long f8g2_19 = f8 * (long)g2_19;
        long f8g3_19 = f8 * (long)g3_19;
        long f8g4_19 = f8 * (long)g4_19;
        long f8g5_19 = f8 * (long)g5_19;
        long f8g6_19 = f8 * (long)g6_19;
        long f8g7_19 = f8 * (long)g7_19;
        long f8g8_19 = f8 * (long)g8_19;
        long f8g9_19 = f8 * (long)g9_19;
        long f9g0 = f9 * (long)g0;
        long f9g1_38 = f9_2 * (long)g1_19;
        long f9g2_19 = f9 * (long)g2_19;
        long f9g3_38 = f9_2 * (long)g3_19;
        long f9g4_19 = f9 * (long)g4_19;
        long f9g5_38 = f9_2 * (long)g5_19;
        long f9g6_19 = f9 * (long)g6_19;
        long f9g7_38 = f9_2 * (long)g7_19;
        long f9g8_19 = f9 * (long)g8_19;
        long f9g9_38 = f9_2 * (long)g9_19;
        
        long h0 = f0g0 + f1g9_38 + f2g8_19 + f3g7_38 + f4g6_19 + f5g5_38 + f6g4_19 + f7g3_38 + f8g2_19 + f9g1_38;
        long h1 = f0g1 + f1g0 + f2g9_19 + f3g8_19 + f4g7_19 + f5g6_19 + f6g5_19 + f7g4_19 + f8g3_19 + f9g2_19;
        long h2 = f0g2 + f1g1_2 + f2g0 + f3g9_38 + f4g8_19 + f5g7_38 + f6g6_19 + f7g5_38 + f8g4_19 + f9g3_38;
        long h3 = f0g3 + f1g2 + f2g1 + f3g0 + f4g9_19 + f5g8_19 + f6g7_19 + f7g6_19 + f8g5_19 + f9g4_19;
        long h4 = f0g4 + f1g3_2 + f2g2 + f3g1_2 + f4g0 + f5g9_38 + f6g8_19 + f7g7_38 + f8g6_19 + f9g5_38;
        long h5 = f0g5 + f1g4 + f2g3 + f3g2 + f4g1 + f5g0 + f6g9_19 + f7g8_19 + f8g7_19 + f9g6_19;
        long h6 = f0g6 + f1g5_2 + f2g4 + f3g3_2 + f4g2 + f5g1_2 + f6g0 + f7g9_38 + f8g8_19 + f9g7_38;
        long h7 = f0g7 + f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1 + f7g0 + f8g9_19 + f9g8_19;
        long h8 = f0g8 + f1g7_2 + f2g6 + f3g5_2 + f4g4 + f5g3_2 + f6g2 + f7g1_2 + f8g0 + f9g9_38;
        long h9 = f0g9 + f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1 + f9g0;
        
        long c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;

        c0 = (h0 + (1L << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        c4 = (h4 + (1L << 25)) >> 26; h5 += c4; h4 -= c4 << 26;

        c1 = (h1 + (1L << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        c5 = (h5 + (1L << 24)) >> 25; h6 += c5; h5 -= c5 << 25;

        c2 = (h2 + (1L << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        c6 = (h6 + (1L << 25)) >> 26; h7 += c6; h6 -= c6 << 26;

        c3 = (h3 + (1L << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        c7 = (h7 + (1L << 24)) >> 25; h8 += c7; h7 -= c7 << 25;

        c4 = (h4 + (1L << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        c8 = (h8 + (1L << 25)) >> 26; h9 += c8; h8 -= c8 << 26;

        c9 = (h9 + (1L << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        c0 = (h0 + (1L << 25)) >> 26; h1 += c0; h0 -= c0 << 26;

        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;
        
        return h;
    }

    private static int[] sq(int[] f) {
        return sq(new int[10], f);
    }
    
    private static int[] sq(int[] h, int[] f) {
        
        int f0 = f[0];
        int f1 = f[1];
        int f2 = f[2];
        int f3 = f[3];
        int f4 = f[4];
        int f5 = f[5];
        int f6 = f[6];
        int f7 = f[7];
        int f8 = f[8];
        int f9 = f[9];

        int f0_2 = 2 * f0;
        int f1_2 = 2 * f1;
        int f2_2 = 2 * f2;
        int f3_2 = 2 * f3;
        int f4_2 = 2 * f4;
        int f5_2 = 2 * f5;
        int f6_2 = 2 * f6;
        int f7_2 = 2 * f7;
        int f5_38 = 38 * f5;
        int f6_19 = 19 * f6;
        int f7_38 = 38 * f7;
        int f8_19 = 19 * f8;
        int f9_38 = 38 * f9;

        long f0f0 = (long)f0 * (long)f0;
        long f0f1_2 = (long)f0_2 * (long)f1;
        long f0f2_2 = (long)f0_2 * (long)f2;
        long f0f3_2 = (long)f0_2 * (long)f3;
        long f0f4_2 = (long)f0_2 * (long)f4;
        long f0f5_2 = (long)f0_2 * (long)f5;
        long f0f6_2 = (long)f0_2 * (long)f6;
        long f0f7_2 = (long)f0_2 * (long)f7;
        long f0f8_2 = (long)f0_2 * (long)f8;
        long f0f9_2 = (long)f0_2 * (long)f9;
        long f1f1_2 = (long)f1_2 * (long)f1;
        long f1f2_2 = (long)f1_2 * (long)f2;
        long f1f3_4 = (long)f1_2 * (long)f3_2;
        long f1f4_2 = (long)f1_2 * (long)f4;
        long f1f5_4 = (long)f1_2 * (long)f5_2;
        long f1f6_2 = (long)f1_2 * (long)f6;
        long f1f7_4 = (long)f1_2 * (long)f7_2;
        long f1f8_2 = (long)f1_2 * (long)f8;
        long f1f9_76 = (long)f1_2 * (long)f9_38;
        long f2f2 = (long)f2 * (long)f2;
        long f2f3_2 = (long)f2_2 * (long)f3;
        long f2f4_2 = (long)f2_2 * (long)f4;
        long f2f5_2 = (long)f2_2 * (long)f5;
        long f2f6_2 = (long)f2_2 * (long)f6;
        long f2f7_2 = (long)f2_2 * (long)f7;
        long f2f8_38 = (long)f2_2 * (long)f8_19;
        long f2f9_38 = (long)f2 * (long)f9_38;
        long f3f3_2 = (long)f3_2 * (long)f3;
        long f3f4_2 = (long)f3_2 * (long)f4;
        long f3f5_4 = (long)f3_2 * (long)f5_2;
        long f3f6_2 = (long)f3_2 * (long)f6;
        long f3f7_76 = (long)f3_2 * (long)f7_38;
        long f3f8_38 = (long)f3_2 * (long)f8_19;
        long f3f9_76 = (long)f3_2 * (long)f9_38;
        long f4f4 = (long)f4 * (long)f4;
        long f4f5_2 = (long)f4_2 * (long)f5;
        long f4f6_38 = (long)f4_2 * (long)f6_19;
        long f4f7_38 = (long)f4 * (long)f7_38;
        long f4f8_38 = (long)f4_2 * (long)f8_19;
        long f4f9_38 = (long)f4 * (long)f9_38;
        long f5f5_38 = (long)f5 * (long)f5_38;
        long f5f6_38 = (long)f5_2 * (long)f6_19;
        long f5f7_76 = (long)f5_2 * (long)f7_38;
        long f5f8_38 = (long)f5_2 * (long)f8_19;
        long f5f9_76 = (long)f5_2 * (long)f9_38;
        long f6f6_19 = (long)f6 * (long)f6_19;
        long f6f7_38 = (long)f6 * (long)f7_38;
        long f6f8_38 = (long)f6_2 * (long)f8_19;
        long f6f9_38 = (long)f6 * (long)f9_38;
        long f7f7_38 = (long)f7 * (long)f7_38;
        long f7f8_38 = (long)f7_2 * (long)f8_19;
        long f7f9_76 = (long)f7_2 * (long)f9_38;
        long f8f8_19 = (long)f8 * (long)f8_19;
        long f8f9_38 = (long)f8 * (long)f9_38;
        long f9f9_38 = (long)f9 * (long)f9_38;
        
        long h0 = f0f0 + f1f9_76 + f2f8_38 + f3f7_76 + f4f6_38 + f5f5_38;
        long h1 = f0f1_2 + f2f9_38 + f3f8_38 + f4f7_38 + f5f6_38;
        long h2 = f0f2_2 + f1f1_2 + f3f9_76 + f4f8_38 + f5f7_76 + f6f6_19;
        long h3 = f0f3_2 + f1f2_2 + f4f9_38 + f5f8_38 + f6f7_38;
        long h4 = f0f4_2 + f1f3_4 + f2f2 + f5f9_76 + f6f8_38 + f7f7_38;
        long h5 = f0f5_2 + f1f4_2 + f2f3_2 + f6f9_38 + f7f8_38;
        long h6 = f0f6_2 + f1f5_4 + f2f4_2 + f3f3_2 + f7f9_76 + f8f8_19;
        long h7 = f0f7_2 + f1f6_2 + f2f5_2 + f3f4_2 + f8f9_38;
        long h8 = f0f8_2 + f1f7_4 + f2f6_2 + f3f5_4 + f4f4 + f9f9_38;
        long h9 = f0f9_2 + f1f8_2 + f2f7_2 + f3f6_2 + f4f5_2;

        long c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;

        c0 = (h0 + (1L << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        c4 = (h4 + (1L << 25)) >> 26; h5 += c4; h4 -= c4 << 26;

        c1 = (h1 + (1L << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        c5 = (h5 + (1L << 24)) >> 25; h6 += c5; h5 -= c5 << 25;

        c2 = (h2 + (1L << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        c6 = (h6 + (1L << 25)) >> 26; h7 += c6; h6 -= c6 << 26;

        c3 = (h3 + (1L << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        c7 = (h7 + (1L << 24)) >> 25; h8 += c7; h7 -= c7 << 25;

        c4 = (h4 + (1L << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        c8 = (h8 + (1L << 25)) >> 26; h9 += c8; h8 -= c8 << 26;

        c9 = (h9 + (1L << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        c0 = (h0 + (1L << 25)) >> 26; h1 += c0; h0 -= c0 << 26;

        h[0] = (int) h0;
        h[1] = (int) h1;
        h[2] = (int) h2;
        h[3] = (int) h3;
        h[4] = (int) h4;
        h[5] = (int) h5;
        h[6] = (int) h6;
        h[7] = (int) h7;
        h[8] = (int) h8;
        h[9] = (int) h9;

        return h;
    }

    private static int[] invert(int[] result, int[] z) {
        
        int[] t0 = sq(z);
        int[] t1 = sq(t0); 
        for (int i = 1; i < 2; ++i) {
            sq(t1, t1);
        }

        mul(t1, z, t1);
        mul(t0, t0, t1);
        
        int[] t2 = sq(t0);
        
        mul(t1, t1, t2);
        sq(t2, t1);
        for (int i = 1; i < 5; ++i) {
            sq(t2, t2);
        }

        mul(t1, t2, t1);
        sq(t2, t1);
        for (int i = 1; i < 10; ++i) {
            sq(t2, t2);
        }

        mul(t2, t2, t1);
        int[] t3 = sq(t2); 
        
        for (int i = 1; i < 20; ++i) {
            sq(t3, t3);
        }

        mul(t2, t3, t2);
        sq(t2, t2);
        for (int i = 1; i < 10; ++i) {
            sq(t2, t2);
        }

        mul(t1, t2, t1);
        sq(t2, t1);
        for (int i = 1; i < 50; ++i) {
            sq(t2, t2);
        }

        mul(t2, t2, t1);
        sq(t3, t2);
        for (int i = 1; i < 100; ++i) {
            sq(t3, t3);
        }

        mul(t2, t3, t2);
        sq(t2, t2); 
        for (int i = 1; i < 50; ++i) {
            sq(t2, t2);
        }

        mul(t1, t2, t1);
        sq(t1, t1);
        for (int i = 1; i < 5; ++i) {
            sq(t1, t1);
        }
        
        mul(result, t1, t0);

        return result;
    }

    private static int[] fromBytes(byte[] b) {
        long h0 = load_4(b, 0);
        long h1 = load_3(b, 4) << 6;
        long h2 = load_3(b, 7) << 5;
        long h3 = load_3(b, 10) << 3;
        long h4 = load_3(b, 13) << 2;
        long h5 = load_4(b, 16);
        long h6 = load_3(b, 20) << 7;
        long h7 = load_3(b, 23) << 5;
        long h8 = load_3(b, 26) << 4;
        long h9 = load_3(b, 29) << 2;
        
        long c9 = (h9 + (1 << 24)) >> 25; h0 += c9 * 19; h9 -= c9 << 25;
        long c1 = (h1 + (1 << 24)) >> 25; h2 += c1; h1 -= c1 << 25;
        long c3 = (h3 + (1 << 24)) >> 25; h4 += c3; h3 -= c3 << 25;
        long c5 = (h5 + (1 << 24)) >> 25; h6 += c5; h5 -= c5 << 25;
        long c7 = (h7 + (1 << 24)) >> 25; h8 += c7; h7 -= c7 << 25;

        long c0 = (h0 + (1 << 25)) >> 26; h1 += c0; h0 -= c0 << 26;
        long c2 = (h2 + (1 << 25)) >> 26; h3 += c2; h2 -= c2 << 26;
        long c4 = (h4 + (1 << 25)) >> 26; h5 += c4; h4 -= c4 << 26;
        long c6 = (h6 + (1 << 25)) >> 26; h7 += c6; h6 -= c6 << 26;
        long c8 = (h8 + (1 << 25)) >> 26; h9 += c8; h8 -= c8 << 26;

        return new int[] {(int)h0, (int)h1, (int)h2, (int)h3, (int)h4, 
                           (int)h5, (int)h6, (int)h7, (int)h8, (int)h9};
    }
    
    private static long load_3(byte[] data, int offset) {
        return (data[offset] & 0xFF) | 
               (data[offset + 1] & 0xFF) << 8 | 
               (data[offset + 2] & 0xFF) << 16;
    }

    private static long load_4(byte[] data, int offset) {
        return (data[offset] & 0xFF) | 
               (data[offset + 1] & 0xFF) << 8 | 
               (data[offset + 2] & 0xFF) << 16 |
               (data[offset + 3] & 0xFF) << 24 & 0xFFFFFFFFL;
    }

    private static byte[] toBytes(int[] h) {
        
        int[] hr = reduce(h);

        int h0 = hr[0];
        int h1 = hr[1];
        int h2 = hr[2];
        int h3 = hr[3];
        int h4 = hr[4];
        int h5 = hr[5];
        int h6 = hr[6];
        int h7 = hr[7];
        int h8 = hr[8];
        int h9 = hr[9];

        byte[] s = new byte[32];

        s[0] = (byte) h0;
        s[1] = (byte) (h0 >> 8);
        s[2] = (byte) (h0 >> 16);
        s[3] = (byte) ((h0 >> 24) | (h1 << 2));
        s[4] = (byte) (h1 >> 6);
        s[5] = (byte) (h1 >> 14);
        s[6] = (byte) ((h1 >> 22) | (h2 << 3));
        s[7] = (byte) (h2 >> 5);
        s[8] = (byte) (h2 >> 13);
        s[9] = (byte) ((h2 >> 21) | (h3 << 5));
        s[10] = (byte) (h3 >> 3);
        s[11] = (byte) (h3 >> 11);
        s[12] = (byte) ((h3 >> 19) | (h4 << 6));
        s[13] = (byte) (h4 >> 2);
        s[14] = (byte) (h4 >> 10);
        s[15] = (byte) (h4 >> 18);
        s[16] = (byte) h5;
        s[17] = (byte) (h5 >> 8);
        s[18] = (byte) (h5 >> 16);
        s[19] = (byte) ((h5 >> 24) | (h6 << 1));
        s[20] = (byte) (h6 >> 7);
        s[21] = (byte) (h6 >> 15);
        s[22] = (byte) ((h6 >> 23) | (h7 << 3));
        s[23] = (byte) (h7 >> 5);
        s[24] = (byte) (h7 >> 13);
        s[25] = (byte) ((h7 >> 21) | (h8 << 4));
        s[26] = (byte) (h8 >> 4);
        s[27] = (byte) (h8 >> 12);
        s[28] = (byte) ((h8 >> 20) | (h9 << 6));
        s[29] = (byte) (h9 >> 2);
        s[30] = (byte) (h9 >> 10);
        s[31] = (byte) (h9 >> 18);

        return s;
    }

    private static int[] reduce(int[] h) {
        
        int h0 = h[0];
        int h1 = h[1];
        int h2 = h[2];
        int h3 = h[3];
        int h4 = h[4];
        int h5 = h[5];
        int h6 = h[6];
        int h7 = h[7];
        int h8 = h[8];
        int h9 = h[9];
        
        int q = (19 * h9 + (1 << 24)) >> 25;
        q = (h0 + q) >> 26;
        q = (h1 + q) >> 25;
        q = (h2 + q) >> 26;
        q = (h3 + q) >> 25;
        q = (h4 + q) >> 26;
        q = (h5 + q) >> 25;
        q = (h6 + q) >> 26;
        q = (h7 + q) >> 25;
        q = (h8 + q) >> 26;
        q = (h9 + q) >> 25;

        h0 += 19 * q;

        int c0 = h0 >> 26; h1 += c0; h0 -= c0 << 26;
        int c1 = h1 >> 25; h2 += c1; h1 -= c1 << 25;
        int c2 = h2 >> 26; h3 += c2; h2 -= c2 << 26;
        int c3 = h3 >> 25; h4 += c3; h3 -= c3 << 25;
        int c4 = h4 >> 26; h5 += c4; h4 -= c4 << 26;
        int c5 = h5 >> 25; h6 += c5; h5 -= c5 << 25;
        int c6 = h6 >> 26; h7 += c6; h6 -= c6 << 26;
        int c7 = h7 >> 25; h8 += c7; h7 -= c7 << 25;
        int c8 = h8 >> 26; h9 += c8; h8 -= c8 << 26;
        int c9 = h9 >> 25; h9 -= c9 << 25;

        return new int[] {h0, h1, h2, h3, h4, h5, h6, h7, h8, h9};
    }
}
