#!/bin/bash
HTTP="/rdcweb01/HTTPServer/conf"
APACHE_PREFIX="/rdcweb01/HTTPServer/"


OUTPUT=$( cat $HTTP/httpd.conf | grep -v "#" |  grep 'log_config')
SCORE=0
if [[ $OUTPUT == 'LoadModule log_config_module modules/mod_log_config.so' ]]
then
#SCORE= $(( SCORE+1 ))
(( SCORE=SCORE+1))
echo " CONTROL 2.2 Ensure the Log Config Module Is Enabled : PASSED"
#echo $SCORE 

else


echo " CONTROL 2.2 Ensure the Log Config Module Is Enabled : FAILED "

fi
OUTPUT2=$( cat $HTTP/httpd.conf | grep -v "#" |  grep 'dav'  )
if [[  $OUTPUT2 == ''  ]]
then
echo " CONTROL 2.3 Ensure the WebDAV Modules Are Disabled : PASSED "
else
echo " CONTROL 2.3 Ensure the WebDAV Modules Are Disabled : FAILED "
fi
OUTPUT3=$( cat $HTTP/httpd.conf | grep -v "#" |  grep  'status_module' )
if [[  $OUTPUT3 == ''  ]]
then
echo " CONTROL 2.4: Ensure the Status Module Is Disabled :  PASSED "
else
echo " CONTROL 2.4:Ensure the Status Module Is Disabled : FAILED     "
fi
OUTPUT4=$( cat $HTTP/httpd.conf | grep -v "#" |  grep  'mod_autoindex'  )
if [[  $OUTPUT4 == ''  ]]
then
echo " CONTROL 2.5: Ensure the Autoindex Module Is Disabled  :  PASSED "
else
echo " CONTROL 2.5: Ensure the Autoindex Module Is Disabled : FAILED   "
fi
OUTPUT5=$( cat $HTTP/httpd.conf | grep -v "#" |  grep  'mod_proxy'  )
if [[  $OUTPUT5 == ''  ]]
then
echo " CONTROL 2.6: Ensure the Proxy Modules Are Disabled  : PASSED "
else
echo " CONTROL 2.6: Ensure the Proxy Modules Are Disabled : FAILED     "
fi
OUTPUT6=$( cat $HTTP/httpd.conf | grep -v "#" |  grep  'userdir_module' )
if [[  $OUTPUT6 == ''  ]]
then
echo " CONTROL 2.7:  Ensure the User Directories Module Is Disabled  :  PASSED "
else
echo " CONTROL 2.7:   Ensure the User Directories Module Is Disabled: FAILED   "
fi
OUTPUT7=$( cat $HTTP/httpd.conf | grep -v "#" |  grep  'mod_info' )
if [[  $OUTPUT7 == ''  ]]
then
echo " CONTROL 2.8:  Ensure the Info Module Is Disabled:  PASSED "
else
echo " CONTROL 2.8:     Ensure the Info Module Is Disabled: FAILED "
fi
OUTPUT8=$( cat $HTTP/httpd.conf | grep -v "#" |  grep  'auth_' )
if [[  $OUTPUT8 == ''  ]]
then
echo " CONTROL 2.9: Ensure the Basic and Digest Authentication Modules are Disabled:  PASSED "
else
echo " CONTROL 2.9: Ensure the Basic and Digest Authentication Modules are Disabled    : FAILED "
fi
echo " SECTION 3 CONTROLS"
HTTP_USER=$( cat $HTTP/httpd.conf | grep -v "#" | grep "User " | awk '{print $2}' )
PROCESS_USER=$(  ps -ef | grep httpd |grep -v "grep" |  awk '{print $1}'  |   sort -u  )
if [[ $HTTP_USER == root || $PROCESS_USER == root ]]
then 
echo " 3.1 Ensure the Apache Web Server Runs As a Non-Root User : FAILED"
elif [[ $HTTP_USER == $PROCESS_USER ]]
then
echo " 3.1 Ensure the Apache Web Server Runs As a Non-Root User : PASSED "
else
echo " 3.1 Ensure the Apache Web Server Runs As a Non-Root User : FAILED"
fi
apachelogin=$( cat /etc/passwd | grep $HTTP_USER | awk -F ':' '{print $7}' )
if [[ $apachelogin == /dev/null || $apachelogin == /sbin/nologin ]]
then
echo " 3.2 Ensure the Apache User Account Has an Invalid Shell : PASSED "
else
echo " 3.2 Ensure the Apache User Account Has an Invalid Shell : FAILED "
fi
#usrck -l $HTTP_USER  2> /dev/null
lockofuser=$(  passwd -S $HTTP_USER | grep "Password locked" | wc -l )


if [[  $lockofuser == 0  ]]
then
echo " 3.3 Ensure the Apache User Account Is Locked : FAILED"
else
echo "3.3 Ensure the Apache User Account Is Locked :  PASSED"
fi
ownership=$( find $APACHE_PREFIX   \! -user root   -ls | wc -l | awk '{print $1}' )
if [[ $ownership == 0 ]]
then
echo " 3.4 Ensure Apache Directories and Files Are Owned By Root : PASSED "
else
echo " 3.4 Ensure Apache Directories and Files Are Owned By Root : FAILED "
fi
groupownership=$( find $APACHE_PREFIX  \! -group root  -ls | wc -l | awk '{print $1}' )
if [[ $groupownership == 0 ]]
then
echo " 3.5 Ensure the Group Is Set Correctly on Apache Directories and Files : PASSED "
else
echo " 3.5 Ensure the Group Is Set Correctly on Apache Directories and Files : FAILED "
fi
PERM1=$( find $APACHE_PREFIX  -perm -o+w | wc -l | awk '{print $1}' )
if [ $PERM1 == 0 ]
then
echo " 3.6 Ensure Other Write Access on Apache Directories and Files Is Restricted : PASSED "
else
echo " 3.6 Ensure Other Write Access on Apache Directories and Files Is Restricted : FAILED "
fi
HTTP_COREDUMP=$( cat $HTTP/httpd.conf | grep CoreDumpDirectory | grep -v "#" | wc -l | awk '{ print $1}' )
HTTP_COREDUMP_LOCATION=$(  cat $HTTP/httpd.conf | grep CoreDumpDirectory | grep -v "#" | awk '{print $2}'  )
HTTP_COREDUMP_LOCATION_USER=$( ls -ld $COREDUMPEXIST | awk '{print $3}')
HTTP_COREDUMP_LOCATION_GROUP=$( ls -ld $COREDUMPEXIST | awk '{print $4}')
if [[ $HTTP_COREDUMP == 0 ]]
then
echo " 3.7 Ensure the Core Dump Directory Is Secured : PASSED "
elif [[ $COREDUMP_LOCATION_USER == root && $COREDUMP_LOCATION_GROUP == $HTTP_USER ]]
then
echo "3.7 Ensure the Core Dump Directory Is Secured : PASSED "
else
echo "3.7 Ensure the Core Dump Directory Is Secured : FAILED"
fi
MUTEX_LOCK_FILE=$( cat $HTTP/httpd.conf | grep Mutex | grep -v "#"  | wc -l | awk '{print $1}' )
LOCK_FILE=$(cat $HTTP/httpd.conf | grep LockFile | grep -v "#" | awk '{print $2}' | uniq )
LOCK_FILE_OWNER=$(  ls -ld $LOCK_FILE | awk '{ print $3}' )
ls -l $APACHE_PREFIX$LOCK_FILE  > /dev/null 2>&1
status=$?
if [[  $MUTEX_LOCK_FILE == 0 ]]
then
echo " 3.8 Ensure the Lock File Is Secured : PASSED "

elif [ $status == 2  ] && [[ $LOCK_FILE_OWNER == root || $LOCK_FILE_OWNER == $HTTP_USER ]]
then
echo " 3.8 Ensure the Lock File Is Secured : PASSED "
else
echo " 3.8 Ensure the Lock File Is Secured : FAILED "
fi
PID_FILE=$(cat $HTTP/httpd.conf | grep PidFile  | grep -v "#" | awk '{print $2}' | uniq )
APACHE_PREFIX2="/rdcweb01/HTTPServer"
PID_FILE_OWNER=$( ls -l $APACHE_PREFIX2/$PID_FILE | awk '{ print $3}' )
ls -l $APACHE_PREFIX2/$PID_FILE  > /dev/null 2>&1
status=$?
if [ $status == 2 ] && [[ $PID_FILE_OWNER == root || $PID_FILE_OWNER == $HTTP_USER ]]
then
echo "3.9 Ensure the Pid File Is Secured : PASSED"
else
echo "3.9 Ensure the Pid File Is Secured : FAILED"
fi
SCOREBOARD=$( cat $HTTP/httpd.conf | grep ScoreBoardFile | grep -v "#" | wc -l | awk '{print $1}' )
SCOREBOARDFILE=$( cat $HTTP/httpd.conf | grep ScoreBoardFile | grep -v "#" | awk '{print $2}' | uniq )
SCOREBOARDFILE_OWNER=$( ls -ld $SCOREBOARDFILE | awk '{print $3}' )
ls -ld $APACHE_PREFIX2/$SCOREBOARDFILE >/dev/null 2>&1
status=$?
if [[ $SCOREBOARD == 0 ]]
then
echo " 3.10 Ensure the ScoreBoard File Is Secured : PASSED "
elif [ $status == 2 ] && [ $SCOREBOARDFILE_OWNER == root || $SCOREBOARDFILE_OWNER == $HTTP_USER ]
then
echo " 3.10 Ensure the ScoreBoard File Is Secured : PASSED "
else
echo " 3.10 Ensure the ScoreBoard File Is Secured : FAILED "
fi
PERM3=$( find $APACHE_PREFIX -perm -g=w | wc -l | awk '{print $1}' )
if [[ $PERM3 == 0 ]]
then
echo "3.11 Ensure Group Write Access for the Apache Directories and Files Is Properly Resrticted : PASSED"
else
echo "3.11 Ensure Group Write Access for the Apache Directories and Files Is Properly Resrticted : FAILED"
fi
echo " 3.12 Ensure Group Write Access for the Document Root Directories and
Files Is Properly Restricted : PASSED "

echo " SECTION 4  CONTROLS "
DENIED=$( cat $HTTP/httpd.conf | grep  -e 'Order deny,allow' -e 'Deny from all' | grep -v "#" | uniq -u | wc -l |  awk '{print $1}' )
REQUIRED=$(  cat $HTTP/httpd.conf | grep " Require all denied " | grep -v "#" | uniq -u | wc -l | awk '{print $1}' )
if [[ $DENIED == 0  ]] && [[ $REQUIRED == 0 ]];
then
echo " 4.1 Ensure Access to OS Root Directory Is Denied By Default : FAILED "
else
echo " 4.1 Ensure Access to OS Root Directory Is Denied By Default : PASSED  "
fi
echo " 4.2 Ensure Appropriate Access to Web Content Is Allowed (Not Scored) "
ROOTDIR=$( perl -ne 'print if /^ *<Directory *\//i .. /<\/Directory/i' $HTTP/httpd.conf  > rootdir.txt)
OVERRIDE_ROOT=$( cat ./rootdir.txt | grep -v "#" | grep  "AllowOverride None" | wc -l | awk '{print $1}'  )
if [[ $OVERRIDE_ROOT == 0  ]];
then
echo " 4.3 Ensure OverRide Is Disabled for the OS Root Directory : FAILED "
else
echo " 4.3 Ensure OverRide Is Disabled for the OS Root Directory : PASSED "
fi
OVERRIDE_ALL=$( cat $HTTP/httpd.conf | grep -v "#" | grep  "AllowOverride None" | wc -l | awk '{print $1}' )
if [[ OVERRIDE_ALL == 0 ]]
then
echo  "4.4 Ensure OverRide Is Disabled for All Directories : FAILED "
else
echo  "4.4 Ensure OverRide Is Disabled for All Directories : PASSED "
fi
echo " SECTION 5 CONTROLS "
OPTIONS_ROOT=$( cat ./rootdir.txt | grep -v "#" | grep "Options None" | wc -l | awk '{print $1}' )
if [[ $OPTIONS_ROOT == 0 ]] ;
then
echo " 5.1 Ensure Options for the OS Root Directory Are Restricted : FAILED "
else
echo " 5.1 Ensure Options for the OS Root Directory Are Restricted : PASSED "
fi
WEB_ROOT=$( perl -ne 'print if /^ *<Directory */i .. /<\/Directory/i' $HTTP/httpd.conf > webroot.txt)
OPTIONS_WEB=$( cat  ./webroot.txt | grep -v "#" | grep "Options None" | wc -l | awk '{print $1}' )
if [[ $OPTIONS_WEB == 0 ]] ;
then
echo " 5.2 Ensure Options for the Web Root Directory Are Restricted : FAILED "
else
echo " 5.2 Ensure Options for the Web Root Directory Are Restricted : PASSED "
fi
WEB_DIR=$( perl -ne 'print if /^ *<Directory */i .. /<\/Directory/i' $HTTP/httpd.conf > webdir.txt )
OPTIONS_WEB_DIR=$( cat  ./webroot.txt | grep -v "#" | grep "Options None" | wc -l | awk '{print $1}' )
if [[ $OPTIONS_WEB_DIR == 0 ]] ;
then
echo " 5.3 Ensure Options for Other Directories Are Minimized : FAILED "
else
echo " 5.3 Ensure Options for Other Directories Are Minimized : PASSED "
fi
if [ $(ls $APACHE_PREFIX/cgi-bin/printenv 2>/dev/null) ];
then
echo " 5.5: Ensure the Default CGI Content printenv Script Is Removed: FAILED "
else
echo "5.5: Ensure the Default CGI Content printenv Script Is Removed: PASSED "
fi
if [ $(ls $APACHE_PREFIX/cgi-bin/test-cgi  2>/dev/null) ] ;
then
echo "5.6: Ensure the Default CGI Content test-cgi Script Is Removed : FAILED "
else
echo "5.6: Ensure the Default CGI Content test-cgi Script Is Removed : PASSED "
fi 
 
trace_method=$( cat $HTTP/httpd.conf | grep "TraceEnable off" | grep -v "#" | wc -l | awk '{print $1}' )
if [[ $trace_method == 0 ]]
then
echo " 5.8 Ensure the HTTP TRACE Method Is Disabled: FAILED "
else
echo " 5.8 Ensure the HTTP TRACE Method Is Disabled: PASSED "
fi
x_frame=$( cat $HTTP/httpd.conf | grep "Header always append X-Frame-Options SAMEORIGIN" | grep -v "#" | wc -l | awk '{print $1}' )
if [[ $x_frame == o ]]
then
echo " 5.14 Ensure Browser Framing Is Restricted : FAILED "
else
echo " 5.14 Ensure Browser Framing Is Restricted : PASSED "
fi 
echo " SECTION 6 CONTROLS "
security2=$( cat $HTTP/httpd.conf | grep security2_module | grep -v "#" | wc -l | awk '{print $1}' )
if [[ $security2 == 0 ]]
then
echo " 6.6 Ensure ModSecurity Is Installed and Enabled : FAILED "
else
echo " 6.6 Ensure ModSecurity Is Installed and Enabled : PASSED "
fi 
echo "SECTIONS 7 CONTROLS  "
ibm_ssl=$( cat $HTTP/httpd.conf | egrep 'ssl_module|nss_module' | grep -v "#" |  wc -l | awk '{print $1}' )
if [[ $ibm_ssl == 0 ]]
then
echo "  7.1 Ensure mod_ssl and/or mod_nss Is Installed : FAILED "
else
echo "  7.1 Ensure mod_ssl and/or mod_nss Is Installed : PASSED "
fi 
SSLInsecureRenegotiation=$( cat $HTTP/httpd.conf | grep  "SSLInsecureRenegotiation on" | grep -v "#" |  wc -l | awk '{print $1}' )
if [[ $SSLInsecureRenegotiation == 0 ]]
then
echo "  7.6 Ensure Insecure SSL Renegotiation Is Not Enabled : PASSED "
else
echo "  7.6 Ensure Insecure SSL Renegotiation Is Not Enabled : FAILED "
fi
SLCompression=$( cat $HTTP/httpd.conf | grep "SSLCompression on" |grep -v "#" |  wc -l | awk '{print $1}' )
if [[ $SLCompression == 0 ]]
then
echo "  7.7 Ensure SSL Compression is Not Enabled : PASSED "
else
echo "  7.7 Ensure SSL Compression is Not Enabled : FAILED "
fi
SSLUSESTAPLING=$( cat $HTTP/httpd.conf | grep "SSLUseStapling On" | grep -v "#" | wc -l | awk '{print$1}')
SSLSTAPLINGCACHE=$( cat $HTTP/httpd.conf | grep "SSLStaplingCache" | grep -v "#" )
if [[ $SSLUSESTAPLING == 0 ]]
then
echo "   7.11 Ensure OCSP Stapling Is Enabled : FAILED "
elif [[ $SSLSTAPLINGCACHE  ==  'SSLStaplingCache "shmcb:logs/ssl_staple_cache(512000)"' ||  $SSLSTAPLINGCACHE  == 'SSLStaplingCache "dbm:logs/ssl_staple_cache.db"' || $SSLSTAPLINGCACHE  == 'SSLStaplingCache dc:UNIX:logs/ssl_staple_socket' ]]
then
echo "   7.11 Ensure OCSP Stapling Is Enabled : PASSED "
else
echo "   7.11 Ensure OCSP Stapling Is Enabled : FAILED"
fi
HSTS_VALUE=$( cat $HTTP/httpd.conf  | grep "Strict-Transport-Security" | grep -v "#"  | awk '{print $5}' | sed -e 's/.*=//' -e 's/;.*//' )
HSTS=$( cat $HTTP/httpd.conf  | grep "Strict-Transport-Security"  | grep -v "#" | wc -l | awk '{print $1}' )
num="480"
if [[  $HSTS == 0 ]]
then
echo " 7.12 Ensure HTTP Strict Transport Security Is Enabled : FAILED "
elif [ "$HSTS_VALUE" -ge "$num" ]
then
echo "  7.12 Ensure HTTP Strict Transport Security Is Enabled : PASSED"
else
echo "  7.12 Ensure HTTP Strict Transport Security Is Enabled : FAILED "
fi

echo " SECTION 8 CONTROLS "
SERVERTOKENS=$( cat $HTTP/httpd.conf | grep -e  "ServerTokens Prod" -e "ServerTokens ProductOnly" | wc -l | awk '{print $1}' )
if [[ $SERVERTOKENS == 0 ]]
then
echo " 8.1 Ensure ServerTokens is Set to 'Prod' or 'ProductOnly' : FAILED"
else
echo " 8.1 Ensure ServerTokens is Set to 'Prod' or 'ProductOnly' : PASSED "
fi 
SERVERSIGNATURE=$( cat $HTTP/httpd.conf | grep "ServerSignature Off" | wc -l | awk '{print $1}' )
if [[ $SERVERSIGNATURE == 0 ]]
then 
echo " 8.2 Ensure ServerSignature Is Not Enabled : FAILED "
else
echo " 8.2 Ensure ServerSignature Is Not Enabled : PASSED "
fi 
DEF_SOURCE=$( cat $HTTP/httpd.conf | grep "Include conf/extra/httpd-autoindex.conf" | grep -v "#" | wc -l | awk '{print $1}'  )
if [[ $DEF_SOURCE == 0 ]]
then 
echo " 8.3 Ensure All Default Apache Content Is Removed : PASSED "
else
echo " 8.3 Ensure All Default Apache Content Is Removed : FAILED "
fi 

FILE_TAG=$( cat $HTTP/httpd.conf | grep -i  FileETag | grep -v "#" | wc -l | awk '{print $1}' )
FILE_TAG2=$( cat $HTTP/httpd.conf | grep -e "FileETag all" -e "FileETag inode" -e "FileETag +inode" | grep -v "#" | wc -l | awk '{print $1}' ) 
if [[ $FILE_TAG == 0 ]]
then 
echo " 8.4 Ensure ETag Response Header Fields Do Not Include Inodes : PASSED" 
elif [[ $FILE_TAG2 == 0 ]]
then
echo "8.4 Ensure ETag Response Header Fields Do Not Include Inodes : PASSED " 
else
echo " 8.4 Ensure ETag Response Header Fields Do Not Include Inodes : FAILED"
fi 
echo " SECTION 9 CONTROLS "
TMHTTP=$( cat $HTTP/httpd.conf | grep -w "Timeout" | grep -v "#" | awk '{print $2}') 
num2="10"
if [ "$TMHTTP" -le "$num2" ]
then
echo " 9.1 Ensure the TimeOut Is Set Properly : PASSED "
else
echo " 9.1 Ensure the TimeOut Is Set Properly : FAILED "
fi 
KEEPALIVE=$( cat $HTTP/httpd.conf | grep "KeepAlive On" | grep -v "#" | wc -l | awk '{print $1}' )
if [[ $KEEPALIVE == 0 ]]
then
echo " 9.2 Ensure KeepAlive Is Enabled : FAILED "
else
echo " 9.2 Ensure KeepAlive Is Enabled :PASSED "
fi
MAXKEEPALIVE=$( cat $HTTP/httpd.conf | grep "MaxKeepAliveRequests" | grep -v "#" | awk '{print $2}' )
num3="100"

if [  "$MAXKEEPALIVE" -ge "$num3" ]
then
echo " 9.3 Ensure MaxKeepAliveRequests Is Set Properly : PASSED "
else
echo " 9.3 Ensure MaxKeepAliveRequests Is Set Properly : FAILED "
fi
KEEPALIVETMOUT=$( cat $HTTP/httpd.conf | grep "KeepAliveTimeout" | grep -v "#" | awk '{print $2}' )
num3="15"
if [ "$KEEPALIVETMOUT" -le "$num3" ]
then
echo " 9.4 Ensure the KeepAliveTimeout Is Set Properly : PASSED "
else
echo " 9.4 Ensure the KeepAliveTimeout Is Set Properly : FAILED "
fi
REQUEST_READTMOUT=$( cat $HTTP/httpd.conf |  grep RequestReadTimeout | grep -v "#" |  awk -F ' |-|,'  '{print $3}' )
reqtimeout=$( cat $HTTP/httpd.conf | grep "reqtimeout" | grep -v "#" | wc -l | awk '{print $1}' )
REQUEST_READTMOUT_EXISTENCE=$( cat $HTTP/httpd.conf |  grep RequestReadTimeout | grep -v "#" | wc -l | awk '{print $1}' )
num4="40"
if [[ $reqtimeout != 0  &&  $REQUEST_READTMOUT_EXISTENCE == 0 ]]
then 
echo " 9.5 Ensure the Timeout Limits for Request Headers is Set to 40 or Less : PASSED "
elif [ "$REQUEST_READTMOUT" -eq "$num4" ] 
then
echo " 9.5 Ensure the Timeout Limits for Request Headers is Set to 40 or Less : PASSED "
else
echo " 9.5 Ensure the Timeout Limits for Request Headers is Set to 40 or Less : FAILED "
fi  
#REQTMOUT=$( cat $HTTP/httpd.conf |  grep RequestReadTimeout | grep -v "#" |  awk -F ' |-|,' 
echo "9.6 Ensure Timeout Limits for the Request Body Are Set Properly : TO BE CHECKED AGAIN"

echo " SECTION 10 CONTROLS "
LIMIT_REQUESTLINE=$( cat $HTTP/httpd.conf | grep "LimitRequestLine" | grep -v "#" |  awk '{print $2}' )
LIMIT_REQUESTLINE_existance=$( cat $HTTP/httpd.conf | grep "LimitRequestLine"|  grep -v "#" | wc -l | awk '{print $1}' )
num6="512"
if [[ $LIMIT_REQUESTLINE_existance == 0 ]]
then
echo " 10.1 Ensure the LimitRequestLine directive is Set to 512 or less : FAILED "
elif [ "$LIMIT_REQUESTLINE" -le "$num6" ]
then
echo " 10.1 Ensure the LimitRequestLine directive is Set to 512 or less : PASSED "
else
echo "10.1 Ensure the LimitRequestLine directive is Set to 512 or less : FAILED "
fi
LIMITREQUESTFEILDS=$( cat $HTTP/httpd.conf | grep -w "LimitRequestFields" | awk '{print $2}' )
LIMITREQUESTFEILDS_existance=$( cat $HTTP/httpd.conf | grep -w  "LimitRequestFields" | wc -l | awk '{print $1}' )
num7="100"
if [[ $LIMITREQUESTFEILDS_existance == 0 ]]
then 
echo " 10.2 Ensure the LimitRequestFields Directive is Set to 100 or Less : FAILED "
elif [ "$LIMITREQUESTFEILDS" -le "$num7" ]
then 
echo "10.2 Ensure the LimitRequestFields Directive is Set to 100 or Less : PASSED "
else
echo "10.2 Ensure the LimitRequestFields Directive is Set to 100 or Less : FAILED " 
fi
LimitRequestFieldsize=$( cat $HTTP/httpd.conf | grep "LimitRequestFieldsize" | awk '{print $2}')
LimitRequestFieldsize_existance=$(cat $HTTP/httpd.conf | grep "LimitRequestFieldsize" | wc -l | awk '{print $1}' )
num8="1024"
if [[ $LimitRequestFieldsize_existance == 0 ]]
then 
echo " 10.3 Ensure the LimitRequestFieldsize Directive is Set to 1024 or Less : FAILED "
elif [ "$LimitRequestFieldsize" -le "$num8" ]
then
echo " 10.3 Ensure the LimitRequestFieldsize Directive is Set to 1024 or Less : PASSED "
else
echo "10.3 Ensure the LimitRequestFieldsize Directive is Set to 1024 or Less : FAILED "
fi
LimitRequestBody=$(  cat $HTTP/httpd.conf | grep "LimitRequestBody" | awk '{print $2}')
LimitRequestBody_existance=$( cat $HTTP/httpd.conf | grep "LimitRequestBody" | wc -l | awk '{print $1}' )
num9="102400"
if [[ $LimitRequestBody_existance == 0 ]]
then
echo " 10.4 Ensure the LimitRequestBody Directive is Set to 102400 or Less : FAILED "
elif [ "$LimitRequestBody" -le "$num9" ]
then
echo " 10.4 Ensure the LimitRequestBody Directive is Set to 102400 or Less : PASSED "
else
echo " 10.4 Ensure the LimitRequestBody Directive is Set to 102400 or Less : FAILED "
fi 
 
