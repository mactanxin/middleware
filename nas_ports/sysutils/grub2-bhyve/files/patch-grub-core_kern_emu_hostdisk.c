--- grub-core/kern/emu/hostdisk.c
+++ grub-core/kern/emu/hostdisk.c
@@ -1318,7 +1318,7 @@ read_device_map (const char *dev_map)
 
       /* NUL-terminate the filename.  */
       e = p;
-      while (*e && ! grub_isspace (*e))
+      while (*e && *e != '\n')
 	e++;
       *e = '\0';
