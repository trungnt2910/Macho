using System;
using System.Collections.Generic;
using System.Text;

namespace Macho
{
    enum NSObjectFileImageReturnCode : uint
    {
        NSObjectFileImageFailure,
        NSObjectFileImageSuccess,
        NSObjectFileImageInappropriateFile,
        NSObjectFileImageArch,
        NSObjectFileImageFormat,
        NSObjectFileImageAccess
    }
}
