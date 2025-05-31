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

import java.nio.file.attribute.DosFileAttributes;

/**
 * @author Dmitry Repchevsky
 */

public class Crypt4ghDosFileAttributes
        extends Crypt4ghBasicFileAttributes<DosFileAttributes>
        implements DosFileAttributes {

    public Crypt4ghDosFileAttributes(DosFileAttributes proxy, long size) {
        super(proxy, size);
    }
    
    @Override
    public boolean isReadOnly() {
        return proxy.isReadOnly();
    }

    @Override
    public boolean isHidden() {
        return proxy.isHidden();
    }

    @Override
    public boolean isArchive() {
        return proxy.isArchive();
    }

    @Override
    public boolean isSystem() {
        return proxy.isSystem();
    }
}
