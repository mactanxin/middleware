--- src/gevent/threadpool.py.orig	2017-01-04 13:36:07.000000000 +0100
+++ src/gevent/threadpool.py	2017-01-04 13:39:09.000000000 +0100
@@ -294,8 +294,6 @@
             # LoopExit (XXX: Why?)
             self._call_when_ready()
         try:
-            if self.exc_info:
-                self.hub.handle_error(self.context, *self.exc_info)
             self.context = None
             self.async = None
             self.hub = None
