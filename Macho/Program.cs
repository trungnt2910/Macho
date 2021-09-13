using System;
using System.IO;
using System.Runtime.InteropServices;

namespace Macho
{
    class Program
    {
        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int fDelegate();

        static unsafe int Main(string[] args)
        {
            void* module = null;
            foreach (var arg in args)
            {
                var bytes = File.ReadAllBytes(arg);

                fixed (byte* data = &bytes[0])
                {
                    module = Macho.macho_load(data, bytes.Length);

                    if (module == null)
                    {
                        Console.WriteLine("Couldn't load the module");
                        return 1;
                    }
                }
            }

            var funPtr = (IntPtr)Macho.macho_sym(module, "_foo");

            var f = Marshal.GetDelegateForFunctionPointer<fDelegate>(funPtr);

            if (f == null)
            {
                Console.WriteLine("Couldn't resolve the symbol");
                return 1;
            }

            Console.WriteLine($"Module: 0x{(ulong)module:x}, Sym: 0x{(ulong)funPtr}");

            Console.WriteLine(f());

            return 0;
        }
    }
}
