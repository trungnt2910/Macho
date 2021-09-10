using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

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

        const uint NSLINKMODULE_OPTION_PRIVATE = 0x2;
        const uint LC_SEGMENT = 0x1;
        const uint LC_SEGMENT_64 = 0x19;
        const uint LC_ID_DYLIB = 0xd;
        const uint LC_SYMTAB = 0x2;     /* link-edit stab symbol table info */

        const uint MH_MAGIC = 0xfeedface;     /* the mach magic number */
        const uint MH_CIGAM = 0xcefaedfe;    /* NXSwapInt(MH_MAGIC) */
        const uint MH_MAGIC_64 = 0xfeedfacf;     /* the 64-bit mach magic number */
        const uint MH_CIGAM_64 = 0xcffaedfe;     /* NXSwapInt(MH_MAGIC_64) */

        const uint MH_DYLIB	= 0x6;

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
            uint options);
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

        static Macho()
        {
            if (!macho_bootstrap(out funcs))
            {
                throw new InvalidOperationException("Couldn't find libdyld in memory.");
            }
        }

        static unsafe bool macho_bootstrap(out func_t f)
        {
            // We need a pointer anywhere onto the stack
            byte* s = stackalloc byte[1];

            // Let's find the very top of the stack
            while (is_ptr_valid((UIntPtr)s + 1))
            {
                ++s;
            }

            for (int x = 0; x < 10000; ++x)
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
                    if (is_ptr_valid(addr) && is_macho(addr) && macho_parse((mach_header_t*)addr, out f))
                        return true;

                    UIntPtr.Subtract(addr, (int)PAGE_SIZE);
                }
            }

            f = null;
            return false;
        }

        public static unsafe void* macho_load(void* data, int size)
        {
            void* image;

            if (funcs.NSCreateObjectFileImageFromMemory(data, size, &image) != 
                    NSObjectFileImageReturnCode.NSObjectFileImageSuccess)
                return null;

            return funcs.NSLinkModule(image, "", NSLINKMODULE_OPTION_PRIVATE);
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

        private static bool is_ptr_valid(UIntPtr ptr)
        {
            throw new NotImplementedException("Do some research first <(\")");
        }

        private static unsafe bool is_macho(UIntPtr ptr)
        {
            mach_header_t* mh = (mach_header_t*)ptr;

            // Is this a valid mach-o dylib file?
            if (mh->magic == MACHO_MAGIC && mh->filetype == MH_DYLIB && mh->cputype == CPU_TYPE)
                return true;

            return false;
        }

        private static unsafe bool macho_parse(mach_header_t* mh, out func_t f)
        {
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

            load_command_t* cmd = (load_command_t*)&mh[1];

            for (x = 0; x < mh->ncmds; x++)
            {
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

                        // Is this the lib: /usr/lib/system/libdyld.dylib?
                        if (hash_djb(name) == 0x8d3fccfd)
                            found = true;

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

                cmd = (load_command_t*)((char*)cmd + cmd->cmdsize);
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
    }
}
