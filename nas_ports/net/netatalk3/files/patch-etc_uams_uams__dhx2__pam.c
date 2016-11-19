--- etc/uams/uams_dhx2_pam.c
+++ etc/uams/uams_dhx2_pam.c
@@ -325,7 +325,7 @@ static int login(void *obj, char *username, int ulen,  struct passwd **uam_pwd _
         return AFPERR_NOTAUTH;
     }
 
+    PAM_username = username;
-    PAM_username = dhxpwd->pw_name;
     LOG(log_info, logtype_uams, "DHX2 login: %s", username);
     return dhx2_setup(obj, ibuf, ibuflen, rbuf, rbuflen);
 }