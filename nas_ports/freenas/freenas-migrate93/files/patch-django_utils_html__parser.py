--- html_parser.py.orig 2017-01-08 23:45:45.749619996 -0800
+++ html_parser.py      2017-01-08 23:54:49.046133025 -0800
@@ -9,7 +9,12 @@
     (current_version >= (3, 0) and current_version < (3, 2, 3))
 )

-HTMLParseError = _html_parser.HTMLParseError
+try:
+    HTMLParseError = _html_parser.HTMLParseError
+except AttributeError:
+    # create a dummy class for Python 3.5+ where it's been removed
+    class HTMLParseError(Exception):
+        pass

 if not use_workaround:
     HTMLParser = _html_parser.HTMLParser