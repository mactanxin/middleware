--- django1611/django/utils/html_parser.py      2017-01-08 23:54:49.046133025 -0800
+++ django1611/django/utils/html_parser.py.orig 2017-01-08 23:45:45.749619996 -0800
@@ -9,12 +9,7 @@
     (current_version >= (3, 0) and current_version < (3, 2, 3))
 )

-try:
-    HTMLParseError = _html_parser.HTMLParseError
-except AttributeError:
-    # create a dummy class for Python 3.5+ where it's been removed
-    class HTMLParseError(Exception):
-        pass
+HTMLParseError = _html_parser.HTMLParseError

 if not use_workaround:
     HTMLParser = _html_parser.HTMLParser