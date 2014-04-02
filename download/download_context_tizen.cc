// Copyright (c) 2013 Intel Corporation. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "download/download_context.h"
#include "filesystem/filesystem_context.h"

#include <pwd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>


std::string DownloadContext::GetFullDestinationPath(
    const std::string destination)  {
   return FS_Context.GetRealPath(destination);
}
