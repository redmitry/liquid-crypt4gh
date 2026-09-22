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

package es.bsc.inb.ga4gh.jcrypt4gh.fs;

import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghException;
import es.bsc.inb.ga4gh.jcrypt4gh.Crypt4ghHeader;
import java.io.IOException;
import java.net.URI;
import java.nio.channels.FileChannel;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AccessMode;
import java.nio.file.CopyOption;
import java.nio.file.DirectoryStream;
import java.nio.file.FileStore;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.LinkOption;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributeView;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.FileAttributeView;
import java.nio.file.spi.FileSystemProvider;
import java.security.GeneralSecurityException;
import java.util.Map;
import java.util.Set;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghFileSystemProvider extends FileSystemProvider {

    private final String scheme;
    
    private Crypt4ghFileSystem fs;

    /**
     * Crypt4GH file system provider constructor bound to the 'c4gh:' scheme.
     * 
     * This constructor is used in explicit Crypt4GH SPI service definitions
     * (via META-INF/services/java.nio.file.spi.FileSystemProvider).
     */
    public Crypt4ghFileSystemProvider() {
        scheme = "c4gh";
    }
    
    /**
     * Constructor for default file system provider.
     * 
     * The provider will intercept all files operations to provide
     * transparent Crypt4GH encoding / decoding operations.
     * 
     * @param parent proxied provider
     */
    public Crypt4ghFileSystemProvider(FileSystemProvider parent) {
        scheme = "file";
        fs = new Crypt4ghFileSystem(parent.getFileSystem(URI.create(scheme + ":/")), this);
    }
    
    Crypt4ghFileSystem getFileSystem() {
        if (fs == null) {
            fs = new Crypt4ghFileSystem(FileSystems.getFileSystem(URI.create(scheme + ":/")), this);
        }
        return fs;
    }

    @Override
    public String getScheme() {
        return scheme;
    }

    @Override
    public FileSystem newFileSystem(URI uri, Map<String, ?> env) throws IOException {
        return new Crypt4ghFileSystem(getFileSystem().proxy.provider().newFileSystem(uri, env), this);
    }

    @Override
    public FileSystem getFileSystem(URI uri) {
        return getFileSystem(); // ???
    }

    @Override
    public Path getPath(URI uri) {
        return new Crypt4ghPath(Crypt4ghPath.unwrap(
                getFileSystem().proxy.provider().getPath(uri)), getFileSystem());
    }

    @Override
    public SeekableByteChannel newByteChannel(Path path, Set<? extends OpenOption> options, 
            FileAttribute<?>... attrs) throws IOException {
        if (path instanceof Crypt4ghPath cpath) {
            try {
                return new Crypt4ghSeekableByteChannel(cpath, options, attrs);
            } catch (Crypt4ghException | GeneralSecurityException ex) {
                throw new IOException(ex.getMessage());
            }
        }
        return FileChannel.open(path, options, attrs);
    }

    @Override
    public FileChannel newFileChannel(Path path, Set<? extends OpenOption> options, 
            FileAttribute<?>... attrs) throws IOException {
        if (path instanceof Crypt4ghPath cpath) {
            try {
                return new Crypt4ghFileChannel(cpath, options, attrs);
            } catch (Crypt4ghException | GeneralSecurityException ex) {
                throw new IOException(ex.getMessage());
            }
        }
        return FileChannel.open(path, options, attrs);
    }
    
    @Override
    public DirectoryStream<Path> newDirectoryStream(Path dir, DirectoryStream.Filter<? super Path> filter) 
            throws IOException {
        return getFileSystem().proxy.provider().newDirectoryStream(Crypt4ghPath.unwrap(dir), filter);
    }

    @Override
    public void createDirectory(Path dir, FileAttribute<?>... attrs) throws IOException {
        getFileSystem().proxy.provider().createDirectory(Crypt4ghPath.unwrap(dir), attrs);
    }

    @Override
    public void delete(Path path) throws IOException {
        getFileSystem().proxy.provider().delete(Crypt4ghPath.unwrap(path));
    }

    @Override
    public void copy(Path source, Path target, CopyOption... options) throws IOException {
        getFileSystem().proxy.provider().copy(Crypt4ghPath.unwrap(source), Crypt4ghPath.unwrap(target), options);
    }

    @Override
    public void move(Path source, Path target, CopyOption... options) throws IOException {
        getFileSystem().proxy.provider().move(Crypt4ghPath.unwrap(source), Crypt4ghPath.unwrap(target), options);
    }

    @Override
    public boolean isSameFile(Path path, Path path2) throws IOException {
        return getFileSystem().proxy.provider().isSameFile(Crypt4ghPath.unwrap(path), Crypt4ghPath.unwrap(path2));
    }

    @Override
    public boolean isHidden(Path path) throws IOException {
        return getFileSystem().proxy.provider().isHidden(Crypt4ghPath.unwrap(path));
    }

    @Override
    public FileStore getFileStore(Path path) throws IOException {
        return getFileSystem().proxy.provider().getFileStore(Crypt4ghPath.unwrap(path));
    }

    @Override
    public void checkAccess(Path path, AccessMode... modes) throws IOException {
        getFileSystem().proxy.provider().checkAccess(Crypt4ghPath.unwrap(path), modes);
    }


    @Override
    public <V extends FileAttributeView> V getFileAttributeView(Path path, Class<V> type, 
            LinkOption... options) {
        V v = getFileSystem().proxy.provider().getFileAttributeView(Crypt4ghPath.unwrap(path), type, options);
        if (path instanceof Crypt4ghPath p) {
            if (v instanceof BasicFileAttributeView view) {
                try {
                    final long size = Crypt4ghHeader.getFileSize(p);
                    return (V)new Crypt4ghBasicFileAttributeView(view, size);
                } catch(IOException | GeneralSecurityException | Crypt4ghException ex) {}
            }
        }
        return v;
    }

    @Override
    public <A extends BasicFileAttributes> A readAttributes(Path path, 
            Class<A> type, LinkOption... options) throws IOException {
        final A a = getFileSystem().proxy.provider().readAttributes(Crypt4ghPath.unwrap(path), type, options);
        if (a.isRegularFile() && path instanceof Crypt4ghPath p) {
            if (a instanceof BasicFileAttributes) {
                try {
                    final long size = Crypt4ghHeader.getFileSize(p);
                    return (A)new Crypt4ghBasicFileAttributes((BasicFileAttributes)a, size);
                } catch(IOException | GeneralSecurityException | Crypt4ghException ex) {
                    throw new IOException(ex);
                }
            }
        }        
        return a;
    }

    @Override
    public Map<String, Object> readAttributes(Path path, 
            String attributes, LinkOption... options) throws IOException {
        return getFileSystem().proxy.provider().readAttributes(Crypt4ghPath.unwrap(path), attributes, options);
    }

    @Override
    public void setAttribute(Path path, String attribute, Object value, 
            LinkOption... options) throws IOException {
        getFileSystem().proxy.provider().setAttribute(Crypt4ghPath.unwrap(path), attribute, value, options);
    }
    
}
