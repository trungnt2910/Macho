using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace Macho
{
    internal static class Macho
    {
        const uint PAGE_SIZE = 0x1000;

        const uint CPU_ARCH_ABI64 = 0x01000000; // 64 bit ABI
        const uint CPU_TYPE_X86 = 7;
        const uint CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
        const uint CPU_TYPE_ARM = 12;
        const uint CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64;

        const uint NSLINKMODULE_OPTION_NONE = 0x0;
        const uint NSLINKMODULE_OPTION_PRIVATE = 0x2;
        const uint NSLINKMODULE_OPTION_RETURN_ON_ERROR = 0x4;
        const uint LC_SEGMENT = 0x1;
        const uint LC_SEGMENT_64 = 0x19;
        const uint LC_ID_DYLIB = 0xd;
        const uint LC_SYMTAB = 0x2;     /* link-edit stab symbol table info */

        const uint MH_MAGIC = 0xfeedface;     /* the mach magic number */
        const uint MH_CIGAM = 0xcefaedfe;    /* NXSwapInt(MH_MAGIC) */
        const uint MH_MAGIC_64 = 0xfeedfacf;     /* the 64-bit mach magic number */
        const uint MH_CIGAM_64 = 0xcffaedfe;     /* NXSwapInt(MH_MAGIC_64) */

        const uint MH_DYLIB	= 0x6;
        const uint MH_BUNDLE = 0x8;

        const int O_WRONLY = 0x0001;

        [StructLayout(LayoutKind.Explicit)]
        struct lc_str
        {
            [FieldOffset(0)]
            public uint offset;
            [FieldOffset(0)]
            public UIntPtr ptr;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct dylib
        {
            public lc_str  name;                 /* library's path name */
            public uint timestamp;                 /* library's build time stamp */
            public uint current_version;           /* library's current version number */
            public uint compatibility_version;     /* library's compatibility vers number*/
        };

        [StructLayout(LayoutKind.Sequential)]
        struct load_command_t
        {
            public uint cmd;           /* type of load command */
            public uint cmdsize;       /* total size of command in bytes */
        }

        [StructLayout(LayoutKind.Sequential)]
        struct symtab_command_t
        {
            public uint cmd;            /* LC_SYMTAB */
            public uint cmdsize;        /* sizeof(struct symtab_command) */
            public uint symoff;         /* symbol table offset */
            public uint nsyms;          /* number of symbol table entries */
            public uint stroff;         /* string table offset */
            public uint strsize;        /* string table size in bytes */
        }

        [StructLayout(LayoutKind.Sequential)]
        struct dylib_command_t
        {
            public uint cmd;            /* LC_ID_DYLIB, LC_LOAD_{,WEAK_}DYLIB, LC_REEXPORT_DYLIB */
            public uint cmdsize;        /* includes pathname string */
            public dylib    dylib;          /* the library identification */
        }

        [StructLayout(LayoutKind.Explicit)]
        struct mach_header_t
        {
            [FieldOffset(0)]
            public uint magic;                          /* mach magic number identifier */
            [FieldOffset(4)]
            public uint cputype;                        /* cpu specifier */
            [FieldOffset(8)]
            public uint cpusubtype;                     /* machine specifier */
            [FieldOffset(12)]
            public uint filetype;                       /* type of file */
            [FieldOffset(16)]
            public uint ncmds;                          /* number of load commands */
            [FieldOffset(20)]
            public uint sizeofcmds;                     /* the size of all the load commands */
            [FieldOffset(24)]
            public UIntPtr flags_and_reserved;          /* A bundle that is 64-bit on 64-bit platforms. */
            [FieldOffset(24)]
            public uint flags;                          /* flags */

            public uint reserved
            {
                [MethodImpl(MethodImplOptions.AggressiveInlining)]
                get => (uint)((ulong)flags_and_reserved & uint.MaxValue);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        unsafe struct segment_command_t
        { /* for 64-bit architectures */
            public uint cmd;            /* LC_SEGMENT_64 */
            public uint cmdsize;        /* includes sizeof section_64 structs */
            public fixed byte segname[16];    /* segment name */
            public UIntPtr vmaddr;         /* memory address of this segment */
            public UIntPtr vmsize;         /* memory size of this segment */
            public UIntPtr fileoff;        /* file offset of this segment */
            public UIntPtr filesize;       /* amount to map from the file */
            public uint maxprot;        /* maximum VM protection */
            public uint initprot;       /* initial VM protection */
            public uint nsects;         /* number of sections in segment */
            public uint flags;          /* flags */
        }

        [StructLayout(LayoutKind.Sequential)]
        unsafe struct section_t
        { /* for 64-bit architectures */
            public fixed byte sectname[16];   /* name of this section */
            public fixed byte segname[16];    /* segment this section goes in */
            public UIntPtr addr;           /* memory address of this section */
            public UIntPtr size;           /* size in bytes of this section */
            public uint offset;         /* file offset of this section */
            public uint align;          /* section alignment (power of 2) */
            public uint reloff;         /* file offset of relocation entries */
            public uint nreloc;         /* number of relocation entries */
            public uint flags;          /* flags (section type and attributes)*/
            public uint reserved1;      /* reserved (for offset or index) */
            public UIntPtr reserved2_3;      /* reserved (for count or sizeof) */
        }

        [StructLayout(LayoutKind.Sequential)]
        struct nlist_t 
        {
            [StructLayout(LayoutKind.Explicit)]
            public unsafe struct DummyUnion
            {
                [FieldOffset(0)]
                private uint n_name_field;
                [FieldOffset(0)]
                public uint n_strx;
                public byte* n_name => (byte *)n_name_field;
            }
            public DummyUnion n_un;
            public byte n_type;         /* type flag, see below */
            public byte n_sect;         /* section number or NO_SECT */
            public short n_desc;         /* see <mach-o/stab.h> */
            public UIntPtr n_value;       /* value of this symbol (or stab offset) */
        }

        public static readonly uint MACHO_MAGIC = Environment.Is64BitProcess ? MH_MAGIC_64 : MH_MAGIC;
        public static readonly uint CPU_TYPE = Environment.Is64BitProcess ? CPU_TYPE_X86_64 : CPU_TYPE_X86;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        unsafe delegate NSObjectFileImageReturnCode 
            ptr_NSCreateObjectFileImageFromMemory(void* address, int size, void* objectFileImage);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        unsafe delegate void* ptr_NSLinkModule(
            void* objectFileImage, 
            [MarshalAs(UnmanagedType.LPStr)] string moduleName, 
            UIntPtr options);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        unsafe delegate void* ptr_NSLookupSymbolInModule(
            void* module, 
            [MarshalAs(UnmanagedType.LPStr)] string symbolName);
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        unsafe delegate void* ptr_NSAddressOfSymbol(void* symbol);

        class func_t
        {
            public ptr_NSCreateObjectFileImageFromMemory NSCreateObjectFileImageFromMemory;
            public ptr_NSLinkModule NSLinkModule;
            public ptr_NSLookupSymbolInModule NSLookupSymbolInModule;
            public ptr_NSAddressOfSymbol NSAddressOfSymbol;
        }

        static readonly func_t funcs;
        private static int _fd = 0;

        static Macho()
        {
            if (!macho_bootstrap2(out funcs))
            {
                throw new InvalidOperationException("Couldn't find libdyld in memory.");
            }

            Console.WriteLine("Okay..");
        }

        static unsafe bool macho_bootstrap(out func_t f)
        {
            // We need a pointer anywhere onto the stack
            byte* s = stackalloc byte[16];
            Console.WriteLine($"Starting pointer: 0x{(ulong)s:x}");

            Debug.Assert(is_ptr_valid((UIntPtr)s));

            // Let's find the very top of the stack
            while (is_ptr_valid((UIntPtr)s + 1))
            {
                ++s;
            }

            Console.WriteLine($"Top of stack: 0x{(ulong)s:x}");

            for (uint x = 0; true; x += PAGE_SIZE)
            {
                // Walk down the stack, one byte at a time
                UIntPtr* ptr = (UIntPtr*)(s - x);

                // Do we have a valid pointer?
                if (!is_ptr_valid((UIntPtr)ptr) || !is_ptr_valid(*ptr))
                    continue;

                // Page-align the pointer
                UIntPtr addr = (UIntPtr)Align((ulong)*ptr, PAGE_SIZE);

                // Walk backwards one page at a time and try to find the beginning
                // of a mach-o file
                for (int y = 0; y < 100; ++y)
                {
                    try
                    {
                        if (is_ptr_valid(addr) && is_macho(addr) && macho_parse((mach_header_t*)addr, out f))
                            return true;
                    }
                    catch (NullReferenceException e)
                    {
                        Console.WriteLine(e);
                    }

                    UIntPtr.Subtract(addr, (int)PAGE_SIZE);
                }
            }

            f = null;
            return false;
        }

        const ulong EXECUTABLE_BASE_ADDR = 0x100000000;
        const ulong DYLD_BASE = 0x00007fff5fc00000;

        private static int IS_SIERRA = -1;

        private static bool is_sierra()
        {
            if (IS_SIERRA == -1)
            {
                // To-Do: Check official mac APIs
                IS_SIERRA = 1;
	        }
	        return Convert.ToBoolean(IS_SIERRA);
        }

        private static unsafe bool find_macho(out func_t f, ulong addr, out ulong output, uint increment, bool deref = false)
        {
            ulong ptr;

            // find a Mach-O header by searching from address.
            output = 0;

            while (true)
            {
                ptr = addr;

                if (!is_ptr_valid((UIntPtr)ptr))
                {
                    Console.WriteLine($"Invalid ptr: 0x{ptr:x}");
                    goto bail;
                }

                if (deref)
                {
                    if (is_ptr_valid((UIntPtr)ptr))
                    {
                        ptr = *(ulong*)ptr;
                    }
                    else
                    {
                        goto bail;
                    }
                }

                Console.WriteLine($"0x{ptr:x} = {*(uint*)ptr}, MACHO_MACH = {MACHO_MAGIC}");

                if (is_ptr_valid((UIntPtr)ptr) && is_macho((UIntPtr)ptr) && macho_parse((mach_header_t*)ptr, out f))
                {
                    return true;
                }

            bail:
                addr += increment;
            }

            return false;
        }

        static unsafe bool macho_bootstrap1(out func_t f)
        {
            f = null;

            ulong binary, dyld;

            var pid = Process.GetCurrentProcess().Id;
            var cmd = new ProcessStartInfo()
            {
                FileName = "vmmap",
                Arguments = $"{pid}",
                UseShellExecute = true
            };

            var proc = Process.Start(cmd);
            proc.WaitForExit();

            if (is_sierra())
            {
                Console.WriteLine("Finding start binary...");
                if (!find_macho(out f, EXECUTABLE_BASE_ADDR, out dyld, 0x1000)) return false;
                //Console.WriteLine($"Start binary found at: 0x{binary:x}");
                //if (!find_macho(binary + 0x1000, out dyld, 0x1000)) return false;
                //Console.WriteLine($"Dyld found at: 0x{dyld:x}");
                return true;
            }
            else
            {
                if (!find_macho(out f, DYLD_BASE, out dyld , 0x1000)) return false;
                return true;
            }

            //return macho_parse((mach_header_t*)dyld, out f);
        }

        static unsafe bool macho_bootstrap2(out func_t f)
        {
            Console.WriteLine("Bootstrapping...");

            var pid = Process.GetCurrentProcess().Id;
            var cmd = new ProcessStartInfo()
            {
                FileName = "vmmap",
                Arguments = $"{pid}",
                UseShellExecute = false,
                RedirectStandardOutput = true
            };

            var proc = Process.Start(cmd);

            try
            {
                while (true)
                {
                    var current = proc.StandardOutput.ReadLine();
                    if (current == null)
                    {
                        break;
                    }

                    Console.WriteLine(current);

                    const string dylibName = "/usr/lib/system/libdyld.dylib";
                    var idx = current.IndexOf(dylibName);

                    if (idx == -1)
                    {
                        continue;
                    }

                    if (idx != 0 && !char.IsWhiteSpace(current[idx - 1]))
                    {
                        continue;
                    }

                    if (idx + dylibName.Length < current.Length && !char.IsWhiteSpace(current[idx + dylibName.Length]))
                    {
                        continue;
                    }

                    Console.WriteLine("Good match.");

                    var match = Regex.Match(current, "\\s([\\da-f]*)-([\\da-f]*)\\s");

                    if (match.Success)
                    {
                        ulong addr = ulong.Parse(match.Groups[1].Value, NumberStyles.HexNumber);
                        Console.WriteLine($"Found dylib at: 0x{addr:x}");
                        Console.WriteLine($"Magic number: {*(uint *)addr}");
                        Console.WriteLine($"MACHO_MAGIC: {MACHO_MAGIC}");
                        Console.WriteLine("parsing...");
                        var result = macho_parse((mach_header_t*)addr, out f);
                        Console.WriteLine("Returning from bootstrap...");
                        return result;
                    }
                }
            }
            finally
            {
                proc.Kill();
                proc.WaitForExit();
                proc.Dispose();
                Console.WriteLine("LMAO Finally");
            }

            throw new NotImplementedException();
        }

        public static unsafe void* macho_load(void* data, string name, int size)
        {
            void* image;

            uint* type = &((uint*)data)[3];
            *type = MH_BUNDLE;

            if (funcs.NSCreateObjectFileImageFromMemory(data, size, &image) != 
                    NSObjectFileImageReturnCode.NSObjectFileImageSuccess)
                return null;

            Console.WriteLine("Preparing to link module...");
            return funcs.NSLinkModule(image, name, (UIntPtr)(NSLINKMODULE_OPTION_NONE | NSLINKMODULE_OPTION_RETURN_ON_ERROR));
        }

        public static unsafe void* macho_sym(void* module, string name)
        {
            void* symbol;

            if (module == null)
                return null;

            symbol = funcs.NSLookupSymbolInModule(module, name);

            if (symbol == null)
                return null;

            return funcs.NSAddressOfSymbol(symbol);
        }

        private static unsafe bool is_ptr_valid(UIntPtr ptr)
        {
            //if (_fd == 0)
            //{
            //    _fd = open("/dev/random", O_WRONLY);
            //    Console.WriteLine($"Random file descriptor: {_fd}");
            //}

            //if ((long)write(_fd, (IntPtr)(ulong)ptr, (UIntPtr)IntPtr.Size) == IntPtr.Size)
            //{
            //    return true;
            //}

            int ret = chmod((void*)ptr, 0777);
            int errno = Marshal.GetLastWin32Error();
            Console.WriteLine(errno);
            Console.WriteLine(ret);

            if (errno != 14) // Not fault
            {
                return true;
            }

            return false;
        }

        private static unsafe bool is_macho(UIntPtr ptr)
        {
            mach_header_t* mh = (mach_header_t*)ptr;

            // Is this a valid mach-o dylib file?
            if (mh->magic == MACHO_MAGIC && /*mh->filetype == MH_DYLIB &&*/ mh->cputype == CPU_TYPE)
                return true;

            Console.WriteLine("Invalid macho file?");
            Console.WriteLine($"Filetype: {mh->filetype}, CpuType: {mh->cputype}.");
            Console.WriteLine($"Expected: {MH_DYLIB}, {CPU_TYPE}");

            return false;
        }

        private static unsafe bool macho_parse(mach_header_t* mh, out func_t f)
        {
            Console.WriteLine("Parsing...");

            f = new func_t();

            int x, y;

            segment_command_t* seg = null;
            segment_command_t* seg_linkedit = null;
            segment_command_t* seg_text = null;
            symtab_command_t* sym = null;
            dylib_command_t* dlb = null;

            nlist_t* nls;
            byte* strtab;

            // Sometimes, we can find our own image in memory, so unless we see a LC_ID_DYLIB
            // that matches our needed string, treat this as a failure
            var found = false;

            Console.WriteLine($"Size of header: {sizeof(mach_header_t)}");
            Console.WriteLine($"Size of cmd: {sizeof(load_command_t)}");
            load_command_t* cmd = (load_command_t*)&mh[1];

            Console.WriteLine("Parsing commands...");
            Console.WriteLine(mh->ncmds);

            for (x = 0; x < mh->ncmds; x++)
            {
                Console.WriteLine(cmd->cmd);
                Console.WriteLine(cmd->cmdsize);
                switch (cmd->cmd)
                {
                    case LC_SEGMENT_64:
                    case LC_SEGMENT:
                        seg = (segment_command_t*)cmd;

                        // __LINKEDIT
                        if (hash_djb(seg->segname) == 0xc214bfb7)
                            seg_linkedit = seg;

                        // __TEXT
                        if (hash_djb(seg->segname) == 0xec5f7168)
                            seg_text = seg;

                        break;

                    case LC_ID_DYLIB:
                        dlb = (dylib_command_t*)cmd;
                        byte* name = (byte*)cmd + dlb->dylib.name.offset;

                        Console.WriteLine($"0x{(ulong)name:x}: {Marshal.PtrToStringAnsi((IntPtr)name)}");

                        // Is this the lib: /usr/lib/system/libdyld.dylib?
                        if (hash_djb(name) == 0x8d3fccfd)
                        {
                            found = true;
                        }
                        else
                        {
                            return false;
                        }

                        break;

                    case LC_SYMTAB:
                        sym = (symtab_command_t*)cmd;

                        // Determine symbol and string table offsets
                        // http://lists.llvm.org/pipermail/lldb-commits/Week-of-Mon-20150608/019449.html
                        strtab = ((byte*)mh + (ulong)seg_linkedit->vmaddr + (ulong)sym->stroff - (ulong)seg_linkedit->fileoff - (ulong)seg_text->vmaddr);
                        nls = (nlist_t*)((byte*)mh + (ulong)seg_linkedit->vmaddr + (ulong)sym->symoff - (ulong)seg_linkedit->fileoff - (ulong)seg_text->vmaddr);

                        for (y = 0; y < sym->nsyms; y++)
                        {
                            byte* sym_name = &strtab[nls[y].n_un.n_strx];
                            IntPtr sym_val = (IntPtr)((byte*)mh + (ulong)nls[y].n_value - (ulong)seg_text->vmaddr);
                            uint hash = hash_djb(sym_name);

                            switch (hash)
                            {
                                case 0x64c5cea0:
                                    f.NSCreateObjectFileImageFromMemory = 
                                        Marshal.GetDelegateForFunctionPointer
                                        <ptr_NSCreateObjectFileImageFromMemory>(sym_val);
                                    break;
                                case 0x6f320e79:
                                    f.NSLinkModule = 
                                        Marshal.GetDelegateForFunctionPointer
                                        <ptr_NSLinkModule>(sym_val);
                                    break;

                                case 0x515bc152:
                                    f.NSLookupSymbolInModule =
                                        Marshal.GetDelegateForFunctionPointer
                                        <ptr_NSLookupSymbolInModule>(sym_val);
                                    break;

                                case 0xf4da6396:
                                    f.NSAddressOfSymbol = 
                                        Marshal.GetDelegateForFunctionPointer
                                        <ptr_NSAddressOfSymbol>(sym_val);
                                    break;
                            }
                        }
                        break;
                }

                cmd = (load_command_t*)((byte*)cmd + cmd->cmdsize);
            }

            // We found libdyld.lib, and we are done
            return found;
        }

        static unsafe uint hash_djb(byte* str)
        {
            uint c;
            uint hash = 5381;

            while ((c = *str++) != 0)
                hash = unchecked((hash << 5) + hash + c); // hash * 33 + c

            return hash;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static long RoundUp(long v, long s)
        {
            return (v + s - 1) & -s;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static ulong Align(ulong val, ulong align)
        {
            return val & ~(align - 1);
        }

        [DllImport("libc")]
        private static extern int open([MarshalAs(UnmanagedType.LPStr)] string path, int oflag);

        [DllImport("libc")]
        private static extern IntPtr write(int fildes, IntPtr buf, UIntPtr nbyte);

        [DllImport("libc", SetLastError = true)]
        private static unsafe extern int chmod(void* path, ushort mode);
    }
}
