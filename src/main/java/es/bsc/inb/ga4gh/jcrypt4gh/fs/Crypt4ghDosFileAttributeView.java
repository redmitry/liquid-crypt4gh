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

package es.bsc.inb.ga4gh.jcrypt4gh.fs;

import java.io.IOException;
import java.nio.file.attribute.DosFileAttributeView;
import java.nio.file.attribute.DosFileAttributes;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghDosFileAttributeView
        extends Crypt4ghBasicFileAttributeView<DosFileAttributeView> 
        implements DosFileAttributeView {
    
    public Crypt4ghDosFileAttributeView(DosFileAttributeView proxy, long size) {
        super(proxy, size);
    }

    @Override
    public DosFileAttributes readAttributes() throws IOException {
        return (DosFileAttributes)super.readAttributes();
    }

    @Override
    public void setReadOnly(boolean value) throws IOException {
        proxy.setReadOnly(value);
    }

    @Override
    public void setHidden(boolean value) throws IOException {
        proxy.setHidden(value);
    }

    @Override
    public void setSystem(boolean value) throws IOException {
        proxy.setSystem(value);
    }

    @Override
    public void setArchive(boolean value) throws IOException {
        proxy.setArchive(value);
    }
}
