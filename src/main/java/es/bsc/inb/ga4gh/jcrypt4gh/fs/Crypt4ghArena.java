//package es.bsc.inb.ga4gh.jcrypt4gh.fs;
//
//import java.lang.foreign.Arena;
//import java.lang.foreign.MemorySegment;
//
///**
// * @author Dmitry Repchevsky
// */
//public class Crypt4ghArena implements Arena {
//
//    private final Arena arena;
//    private MemorySegment segment;
//    
//    public Crypt4ghArena() {
//        arena = Arena.ofShared();
//    }
//    
//    @Override
//    public MemorySegment allocate(long byteSize, long byteAlignment) {
//        segment.asSlice(byteSize, byteSize);
//    }
//
//    @Override
//    public MemorySegment.Scope scope() {
//        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//    }
//
//    @Override
//    public void close() {
//        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
//    }
//}
