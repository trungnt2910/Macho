#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "macho.h"

int main(int argc, char *argv[])
{
   func_t funcs;

   // Resolve the functions
   if(!macho_bootstrap(&funcs))
   {
      printf("Couldn't find libdyld in memory\n");
      return 0;
   }

   int i;
   void* module;

   for (i = 1; i < argc; i += 2)
   {
      printf("Loading %s as %s...\n", argv[i], argv[i + 1]);
      fflush(stdout);

      // Load the bundle into memory
      int fd = open(argv[i], O_RDONLY, 0);

      int size = lseek(fd, 0, SEEK_END);
      lseek(fd, 0, SEEK_SET);

      void *data = mmap(0, ROUND_UP(size, PAGE_SIZE), PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, -1, 0);
      read(fd, data, size);

      // Load the module
      module = macho_load(&funcs, data, argv[i + 1], size);

      if(!module)
      {
         printf("Couldn't load the module: %s...\n", argv[i]);
         return 0;
      }
   }

   printf("Done.\n");
   fflush(stdout);

   // Find the symbol
   int (*f)() = macho_sym(&funcs, module, "_foo");

   if(!f)
   {
      printf("Couldn't resolve the symbol\n");
      return 0;
   }

   printf("Module: %p, Sym: %p\n", module, f);

   // And we are done!
   printf("%i\n", f());

// Values should match
// printf("%llx %llx %llx %llx\n", funcs.NSCreateObjectFileImageFromMemory, NSCreateObjectFileImageFromMemory, funcs.NSLinkModule, NSLinkModule);
}

