#!/bin/bash
#### script fot CIS tomcat controls #########
#DONE BY Mohammad alkhateeb and Mohammad Sammour 
CATALINA_HOME="/rdcapp01/PS/apache-tomcat-9.0.22_secure_bank"
echo " ENTER THE TOMCAT ADMIN USER NAME "
read tomcat_admin
echo " ENTER THE TOMCAT ADMIN GROUP NAME "
read tomcat_group
examples=$( ls -l $CATALINA_HOME/webapps/examples 2>/dev/null | wc -l )
docs=$( ls -l $CATALINA_HOME/webapps/docs 2>/dev/null | wc -l )
ROOT=$( ls -l $CATALINA_HOME/webapps/ROOT 2>/dev/null | wc -l )
host_manager=$( ls -l $CATALINA_HOME/webapps/host-manager 2>/dev/null | wc -l )
manager=$( ls -l $CATALINA_HOME/webapps/manager 2>/dev/null | wc -l )
#app1="manager"
#app2="ald"
echo " ENTER THE APP1 NAME : "
read app1
#echo " ENTER THE APP2 NAME : "
#read app2








if [[ $examples == "0" && $docs == "0" && $ROOT == "0"  && $host_manager == "0" && $manager == "0" ]];
then
echo " 1.1 Remove extraneous files and directories : PASSED "
else
echo " 1.1 Remove extraneous files and directories : FAILED "
fi

cat  $CATALINA_HOME/conf/server.xml | sed 's/<!--/\x0<!--/g;s/-->/-->\x0/g' | grep -zv '^<!--' | tr -d '\0' >  $CATALINA_HOME/conf/server_back.xml
chown $tomcat_admin:$tomcat_group    $CATALINA_HOME/conf/server_back.xml
xpoweredby=$( cat $CATALINA_HOME/conf/server_back.xml | grep  'xpoweredBy="true"'  | wc -l )
if [[ $xpoweredby == 0 ]]
then 
echo " 2.4 Disable X-Powered-By HTTP Header and Rename the Server Value
for all Connectors : PASSED "
else
echo " 2.4 Disable X-Powered-By HTTP Header and Rename the Server Value
for all Connectors : FAILED  "
fi

Traces=$( cat  $CATALINA_HOME/conf/web.xml | grep ' <error-page>
<exception-type>java.lang.Throwable</exception-type>
<location>/error.jsp</location>
</error-page> ' | wc -l )
if [[ $Traces == 0 ]]
then
echo " 2.5 Disable client facing Stack Traces : FAILED "
else
echo " 2.5 Disable client facing Stack Traces : PASSED "
fi 
allow_trace=$( cat $CATALINA_HOME/conf/server_back.xml | allowTrace="true" |wc -l )
if [[ $allow_trace == 0 ]]
then
echo " 2.6 Turn off TRACE : PASSED "
else
echo " 2.6 Turn off TRACE : FAILED "
fi 
server_existance=$( cat $CATALINA_HOME/conf/server_back.xml | grep "server=" | wc -l )
server=$( cat $CATALINA_HOME/conf/server_back.xml | grep -e server="Apache"| server="Apache-Coyote/1.1" wc -l )
if [[ $server_existance == 0 ]]
then 
echo "  2.7 Ensure Sever Header is Modified To Prevent Information Disclosure : FAILED "
elif [[ $server == 0 ]]
then
echo " 2.7 Ensure Sever Header is Modified To Prevent Information Disclosure : PASSED "
else
echo "  2.7 Ensure Sever Header is Modified To Prevent Information Disclosure : FAILED "
fi 
shutdown_value=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'shutdown="SHUTDOWN"' | wc -l ) 
if [[ $shutdown_value == 0 ]]
then
echo " 3.1 Set a nondeterministic Shutdown command value : PASSED "
else
echo " 3.1 Set a nondeterministic Shutdown command value : FAILED "
fi 
Server_port=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'Server port="-1"' | wc -l )
if [[ $Server_port == 0 ]]
then
echo " 3.2 Disable the Shutdown port : FAILED "
else
echo " 3.2 Disable the Shutdown port : PASSED "
fi 
ownership=$( find  $CATALINA_HOME  -maxdepth 1 ! -user $tomcat_admin ! -group $tomcat_group | wc -l )
perm=$( find  $CATALINA_HOME -maxdepth 1   -perm /g+w,o+rwx | wc -l  )
if [[ $perm == 0 ]] && [[ $ownership == 0 ]]
then
echo " 4.1 Restrict access to CATALINA_HOME : PASSED " 
echo " 4.2 Restrict access to $CATALINA_BASE : PASSED "
else
echo " 4.1 Restrict access to CATALINA_HOME : FAILED "
echo " 4.2 Restrict access to $CATALINA_BASE : FAILED"
fi

ownership1=$(  find  $CATALINA_HOME/conf ! -user $tomcat_admin  ! -group $tomcat_group | wc -l )
perm1=$( find  $CATALINA_HOME/conf -perm /g+w,o+rwx | wc -l )
if [[ $perm1 == 0 ]] && [[ $ownership1 == 0 ]]
then
echo " 4.3 Restrict access to Tomcat configuration directory: PASSED "
else
echo " 4.3 Restrict access to Tomcat configuration directory: FAILED "
fi 
ownership2=$( find  $CATALINA_HOME/logs  ! -user $tomcat_admin ! -group $tomcat_group | wc -l )
perm2=$(  find  $CATALINA_HOME/logs  -perm /g+w,o+rwx | wc -l )
if [[ $perm2 == 0 ]] && [[ $ownership2 == 0 ]]
then
echo " 4.4 Restrict access to Tomcat logs directory : PASSED "
else
echo " 4.4 Restrict access to Tomcat logs directory : FAILED " 
fi
ownership3=$( find  $CATALINA_HOME/temp ! -user $tomcat_admin  ! -group $tomcat_group | wc -l )
perm3=$( find  $CATALINA_HOME/temp -perm /o+rwx | wc -l )
if [[ $perm3 == 0 ]] && [[ $ownership3 == 0 ]]
then
echo " 4.5 Restrict access to Tomcat temp directory : PASSED "
else
echo " 4.5 Restrict access to Tomcat temp directory : FAILED "
fi

ownership4=$( find  $CATALINA_HOME/bin  ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
perm4=$( find  $CATALINA_HOME/bin  -perm /g+w,o+rwx | wc -l )
if [[ $perm4 == 0 ]] && [[ $ownership4 == 0 ]]
then
echo " 4.6 Restrict access to Tomcat binaries directory : PASSED "
else
echo " 4.6 Restrict access to Tomcat binaries directory : FAILED "
fi 
ownership5=$( find  $CATALINA_HOME/webapps  ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
perm5=$( find  $CATALINA_HOME/webapps -perm /g+w,o+rwx | wc -l )
if [[ $perm5 == 0 ]] && [[ $ownership5 == 0 ]]
then
echo " 4.7 Restrict access to Tomcat web application directory : PASSED "
else
echo " 4.7 Restrict access to Tomcat web application directory : FAILED "
fi 

ownership6=$( find $CATALINA_HOME/conf/catalina.properties  ! -user $tomcat_admin  ! -group $tomcat_group | wc -l )
perm6=$( find $CATALINA_HOME/conf/catalina.properties -perm /g+w,o+rwx,u+x | wc -l )
if [[ $perm6 == 0 ]] && [[ $ownership6 == 0 ]]
then
echo " 4.8 Restrict access to Tomcat catalina.properties : PASSED "
else
echo " 4.8 Restrict access to Tomcat catalina.properties : FAILED "
fi 
ownership7=$( find  $CATALINA_HOME/conf/catalina.policy ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
perm7=$( find  $CATALINA_HOME/conf/catalina.policy  -perm /g+w,o+rwx,u+x | wc -l )
if [[ $perm7 == 0 ]] && [[ $ownership7 == 0 ]]
then
echo " 4.9 Restrict access to Tomcat catalina.policy : PASSED "
else
echo " 4.9 Restrict access to Tomcat catalina.policy : FAILED "
fi
ownership8=$( find  $CATALINA_HOME/conf/context.xml ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
perm8=$(  find  $CATALINA_HOME/conf/context.xml -perm /g+w,o+rwx,u+x | wc -l )
if [[ $perm8 == 0 ]] && [[ $ownership8 == 0 ]]
then
echo " 4.10 Restrict access to Tomcat context.xml : PASSED "
else
echo " 4.10 Restrict access to Tomcat context.xml : FAILED "
fi
ownership9=$(  find  $CATALINA_HOME/conf/logging.properties  ! -user $tomcat_admin  ! -group $tomcat_group | wc -l )
perm9=$( find  $CATALINA_HOME/conf/logging.properties  -perm /g+w,o+rwx,u+x | wc -l )
if [[ $perm9 == 0 ]] && [[ $ownership9 == 0 ]]
then
echo " 4.11 Restrict access to Tomcat logging.properties : PASSED "
else
echo " 4.11 Restrict access to Tomcat logging.properties : FAILED "
fi 
ownership10=$( find  $CATALINA_HOME/conf/server.xml ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
perm10=$( find  $CATALINA_HOME/conf/server.xml  -perm /g+w,o+rwx,u+x | wc -l )
if [[ $perm10 == 0 ]] && [[ $ownership10 == 0 ]]
then
echo " 4.12 Restrict access to Tomcat server.xml : PASSED "
else
echo " 4.12 Restrict access to Tomcat server.xml : FAILED "
fi 
ownership11=$( find  $CATALINA_HOME/conf/tomcat-users.xml ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
perm11=$( find  $CATALINA_HOME/conf/tomcat-users.xml -perm /g+w,o+rwx,u+x | wc -l )
if [[ $perm11 == 0 ]] && [[ $ownership11 == 0 ]]
then
echo " 4.13 Restrict access to Tomcat tomcat-users.xml : PASSED "
else
echo " 4.13 Restrict access to Tomcat tomcat-users.xml : FAILED "
fi
ownership12=$( find  $CATALINA_HOME/conf/web.xml  ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
perm12=$(  find  $CATALINA_HOME/conf/web.xml -perm /g+w,o+rwx,u+x | wc -l )
if [[ $perm12 == 0 ]] && [[ $ownership12 == 0 ]]
then
echo " 4.14 Restrict access to Tomcat web.xml : PASSED "
else
echo " 4.14 Restrict access to Tomcat web.xml : FAILED "
fi
ls -l $CATALINA_HOME/conf/aspic-providers.xml >/dev/null 2>&1
status_aspic=$?
ownership13=$( find  $CATALINA_HOME/conf/aspic-providers.xml 2>/dev/null ! -user $tomcat_admin ! -group $tomcat_group  | wc -l  )
perm13=$( find  $CATALINA_HOME/conf/aspic-providers.xml 2>/dev/null  -perm /g+w,o+rwx,u+x | wc -l )
if [[ $status_aspic == 2 ]]
then
echo " 4.15 Restrict access to jaspic-providers.xml : FAILED"
#ownership13=$( find  $CATALINA_HOME/conf/aspic-providers.xml  ! -user $tomcat_admin ! -group $tomcat_group  | wc -l )
#perm13=$( find  $CATALINA_HOME/conf/aspic-providers.xml  -perm /g+w,o+rwx,u+x | wc -l )
elif [[ $perm13 == 0 ]] && [[ $ownership13 == 0 ]]
then
echo " 4.15 Restrict access to jaspic-providers.xml : PASSED "
else
echo " 4.15 Restrict access to jaspic-providers.xml : FAILED "
fi 
echo " ############# SECTION 5 CONTROLS ############## "

REALM=$( cat  $CATALINA_HOME/conf/server_back.xml  | grep "Realm className" | grep -E  'UserDatabaseRealm| MemoryRealm | JDBCRealm | JAASRealm' | wc -l )
if [[ $REALM == 0 ]]
then
echo " 5.1 Use secure Realms : TRUE "
else
echo " 5.1 Use secure Realms : FALSE " 
fi 
LOCKOUT=$(  cat  $CATALINA_HOME/conf/server_back.xml | grep "LockOutRealm" | wc -l ) 
if [[ $LOCKOUT == 0 ]]
then
echo " 5.2 Use LockOut Realms : FALSE "
else
echo " 5.2 Use LockOut Realms : TRUE "
fi
echo " ####################### SECTION 6 CONTROLS ############ " 
CLIENT_AUTH=$(  cat  $CATALINA_HOME/conf/server_back.xml | grep 'clientAuth="true"' | wc -l )
CERT_VIR=$( cat  $CATALINA_HOME/conf/server_back.xml | grep 'certificateVerification="required"' | wc -l )
if [[ $CLIENT_AUTH == 0 ]] && [[ $CERT_VIR == 0 ]]
then
echo " 6.1 Setup Client-cert Authentication : FALSE "
else 
echo " 6.1 Setup Client-cert Authentication : PASSED  "
fi 
SSL_ENABLE=$(  cat  $CATALINA_HOME/conf/server_back.xml | grep 'SSLEnabled="true"' | wc -l )
if [[ $SSL_ENABLE == 0 ]]
then
echo " 6.2 Ensure SSLEnabled is set to True for Sensitive Connectors : FAILED "
else
echo " 6.2 Ensure SSLEnabled is set to True for Sensitive Connectors : PASSED " 
fi 
scheme=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'scheme="https"' | wc -l )
if [[ $scheme == 0 ]]
then
echo " 6.3 Ensure scheme is set accurately : FAILED "
else
echo " 6.3 Ensure scheme is set accurately : PASSED "
fi 
proto=$( cat $CATALINA_HOME/conf/server_back.xml | grep -e  'sslProtocol="TLSv1.2+TLSv1.3" | sslProtocol="TLSv1.2, TLSv1.3"' | wc -l )

sed -n '/Connector/{:start />/!{N;b start};/SSLEnabled="true"/p}' $CATALINA_HOME/conf/server_back.xml > $CATALINA_HOME/conf/ssl_connectors
SECURE_CONNECTORS=$( cat $CATALINA_HOME/conf/ssl_connectors | grep 'secure="false"' | wc -l )
if [[ $SECURE_CONNECTORS == 0 ]]
then
echo " 6.4 Ensure secure is set to true only for SSL-enabled Connectors : PASSED "
else
echo " 6.4 Ensure secure is set to true only for SSL-enabled Connectors : FAILED "
fi
proto=$( cat $CATALINA_HOME/conf/ssl_connectors | grep -e  'sslProtocol="TLSv1.2+TLSv1.3" | sslProtocol="TLSv1.2, TLSv1.3"' | wc -l )
if [[ $proto == 0 ]]
then
echo " 6.5 Ensure 'sslProtocol' is Configured Correctly for Secure Connectors : FAILED "
else
echo " 6.5 Ensure 'sslProtocol' is Configured Correctly for Secure Connectors : PASSED "
fi 






























#echo " ENTER THE WEBAPP NAMES "
#echo " FIRST APP :  "

#read first_app
#echo "$first_app" > apps.txt
#echo " SECOND APP : "
#read second_app 
#echo "$second_app" >> apps.txt

#echo " THIRD APP : "
#read third_app
#echo "$third_app" >> apps.txt
#readarray -t arr < ./apps.txt
#for item in "${arr[@]}"
#do
#ls -l $CATALINA_HOME/webapps/$item/WEB-INF/classes  >/dev/null 2>&1
#status${arr[@]}=$? 
##echo $item
#done  
#if [[ $status1 == 2 ]]
#then
#echo "test is good "
#else
#echo " test is not "
#fi 

ls -l $CATALINA_HOME/webapps/$app1/WEB-INF/classes/logging.properties  >/dev/null 2>&1
status1=$?
#ls -l $CATALINA_HOME/webapps/$app2/WEB-INF/classes/logging.properties  >/dev/null 2>&1 
#status2=$?
if [[ $status1 == 2 ]] || [[ $status2 == 2 ]]
then
echo " 7.1 Application specific logging : FAILED "
else
echo "  7.1 Application specific logging : PASSED "
fi

classname=$( cat $CATALINA_HOME/webapps/$app1/META-INF/context.xml 2>/dev/null | grep 'className="org.apache.catalina.valves.AccessLogValve"' | wc -l )
if [[ $classname == 0 ]] 
then
echo " 7.3 Ensure className is set correctly in context.xml for  APP $app1: FAILED "
else
echo " 7.3 Ensure className is set correctly in context.xml for APP: $app1 : PASSED "
fi
#classname2=$( cat $CATALINA_HOME/webapps/$app2/META-INF/context.xml | grep 'className="org.apache.catalina.valves.AccessLogValve"' | wc -l )
#if [[ $classname == 0 ]]
#then
#echo " 7.3 Ensure className is set correctly in context.xml for  APP $app2: FAILED "
#else
#echo " 7.3 Ensure className is set correctly in context.xml for APP: $app2 : PASSED "
#fi
pattern=$(  cat $CATALINA_HOME/webapps/$app1/META-INF/context.xml 2>/dev/null | grep 'pattern="%h %t %H cookie:%{SESSIONID}c request:%{SESSIONID}r %m %U %s %q %r"' | wc -l )
if [[ $pattern == 0 ]]
then
echo " 7.5 Ensure pattern in context.xml is correct for APP: $app1 : FAILED "
else
echo " 7.5 Ensure pattern in context.xml is correct for APP: $app1: PASSED "
fi 
#pattern=$(  cat $CATALINA_HOME/webapps/$app2/META-INF/context.xml | grep 'pattern="%h %t %H cookie:%{SESSIONID}c request:%{SESSIONID}r %m %U %s %q %r"' | wc -l )
#if [[ $pattern == 0 ]]
#then
#echo " 7.5 Ensure pattern in context.xml is correct for APP: $app2 : FAILED "
#else
#echo " 7.5 Ensure pattern in context.xml is correct for APP: $app2: PASSED "
#fi
package_access_sun=$( cat $CATALINA_HOME/conf/catalina.properties | grep package.access | grep sun. | wc -l )
package_access_apache==$( cat $CATALINA_HOME/conf/catalina.properties | grep package.access | grep "org.apache.catalina" | wc -l )
package_access_coyote=$( cat $CATALINA_HOME/conf/catalina.properties | grep package.access | grep "org.apache.coyote." | wc -l )
package_access_jasper=$( cat $CATALINA_HOME/conf/catalina.properties | grep package.access | grep "org.apache.jasper." | wc -l )
package_access_tomcat=$(  cat $CATALINA_HOME/conf/catalina.properties | grep package.access | grep "org.apache.tomcat." | wc -l )
if [[ $package_access_sun == 0 ]] || [[ $package_access_apache == 0 ]] || [[ $package_access_coyote == 0 ]] || [[ $package_access_jasper == 0 ]] || [[ $package_access_tomcat == 0 ]] 
then
echo " 8.1 Restrict runtime access to sensitive packages : FAILED "
else
echo " 8.1 Restrict runtime access to sensitive packages : PASSED "
fi
auto_deploy=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'autoDeploy="false"' | wc -l )
if [[ $auto_deploy == 0 ]]
then
echo " 9.2 Disabling auto deployment of applications : FAILED "
else
echo " 9.2 Disabling auto deployment of applications : PASSED "
fi
startup_deploy=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'deployOnStartup="false"' | wc -l )
if [[ $startup_deploy == 0 ]]
then
echo " 9.3 Disable deploy on startup of applications : FAILED "
else
echo " 9.3 Disable deploy on startup of applications : PASSED "
fi
Class_Name=$( cat $CATALINA_HOME/conf/server_back.xml | grep "org.apache.catalina.valves.RemoteAddrValve" | wc -l )
allow=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'allow="127\.0\.0\.1"' | wc -l )
if [[ $Class_Name == 0 ]]
then
echo " 10.2 Restrict access to the web administration application : FAILED "
elif [[ $allow == 0 ]]
then
echo " 10.2 Restrict access to the web administration application : FAILED "
else
echo " 10.2 Restrict access to the web administration application : PASSED "
fi 
SERVLET=$( cat $CATALINA_HOME/bin/catalina.sh | grep "Dorg.apache.catalina.STRICT_SERVLET_COMPLIANCE=true" | wc -l )
if [[ $SERVLET == 0 ]]
then
echo " 10.6 Enable strict servlet Compliance : FAILED "
else
echo " 10.6 Enable strict servlet Compliance : PASSED "
fi 
FACADES=$( cat $CATALINA_HOME/bin/catalina.sh | grep "Dorg.apache.catalina.connector.RECYCLE_FACADES=true" | wc -l )
if [[ $FACADES == 0 ]]
then
echo " 10.7 Turn off session facade recycling : FAILED "
else
echo " 10.7 Turn off session facade recycling : PASSED "
fi

BACK_SLASH=$( cat $CATALINA_HOME/bin/catalina.sh | grep "Dorg.apache.catalina.connector.CoyoteAdapter.ALLOW_BACKSLASH=false" | wc -l )
ENCODED_SLASH=$( cat $CATALINA_HOME/bin/catalina.sh | grep "Dorg.apache.tomcat.util.buf.UDecoder.ALLOW_ENCODED_SLASH=false" | wc -l )
if [[ $BACK_SLASH == 0 ]] || [[ $ENCODED_SLASH == 0 ]]
then
echo " 10.8 Do not allow additional path delimiters : FAILED "
else
echo " 10.8 Do not allow additional path delimiters : PASSED "
fi 
Tomcat_Connection_Timeout=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'connectionTimeout="60000"' | wc -l )
if [[ $Tomcat_Connection_Timeout == 0 ]]
then
echo " 10.9 Configure connectionTimeout : FAILED "
else
echo " 10.9 Configure connectionTimeout : PASSED "
fi 

MAX_HTTP_HEADER=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'maxHttpHeaderSize="8192"'  | wc -l )
if [[ $MAX_HTTP_HEADER == 0 ]]
then
echo " 10.10 Configure maxHttpHeaderSize : FAILED "
else
echo " 10.10 Configure maxHttpHeaderSize : PASSED "
fi
CONFIDENTIAL=$( cat $CATALINA_HOME/conf/web.xml | grep "<transport-guarantee>CONFIDENTIAL</transport-guarantee>" | wc -l )
if [[ $CONFIDENTIAL == 0 ]]
then
echo " 10.11 Force SSL for all applications : FAILED "
else
echo " 10.11 Force SSL for all applications : PASSED "
fi 
allowLinking=$( find  $CATALINA_HOME -name context.xml | xargs grep 'allowLinking=”true”' | wc -l )
if [[ $allowLinking == 0 ]]
then
echo " 10.12 Do not allow symbolic linking : PASSED "
else
echo " 10.12 Do not allow symbolic linking : FAILED "
fi 
privileged=$( find  $CATALINA_HOME -name context.xml | xargs grep 'privileged=”true”' | wc -l )
if [[ $privileged == 0 ]]
then
echo " 10.13 Do not run applications as privileged : PASSED "
else
echo " 10.13 Do not run applications as privileged : FAILED "
fi 
enableLookups=$( cat $CATALINA_HOME/conf/server_back.xml | grep 'enableLookups="true"' | wc -l )
if [[ $enableLookups == 0 ]]
then
echo " 10.15 Do not resolve hosts on logging valves : PASSED "
else
echo " 10.15 Do not resolve hosts on logging valves : FAILED "
fi 
LISTENER=$( cat $CATALINA_HOME/conf/server_back.xml | grep '"org.apache.catalina.core.JreMemoryLeakPreventionListener"' | wc -l )
if [[ $LISTENER == 0 ]]
then
echo " 10.16 Enable memory leak listener : FAILED "
else
echo " 10.16 Enable memory leak listener : PASSED "
fi 
metadata1=$( cat $CATALINA_HOME/webapps/$app1/WEB-INF/web.xml 2>/dev/null | grep 'metadata-complete="true"' | wc -l )
effective1=$(  cat $CATALINA_HOME/webapps/$app1/META-INF/context.xml 2>/dev/null | grep 'logEffectiveWebXml="true"' | wc -l )
if [[ $metadata1 == 0 ]] || [[ $effective1 == 0 ]]
then
echo  " 10.18 Use the logEffectiveWebXml and metadata-complete settings for deploying applications in production for APP $app1: FAILED "
else 
echo " 10.18 Use the logEffectiveWebXml and metadata-complete settings for deploying applications in production  for APP : $app1: PASSED "
fi 
#metadata2=$( cat $CATALINA_HOME/webapps/$app2/WEB-INF/web.xml | grep 'metadata-complete="true" | wc -l )
#effective2=$(  cat $CATALINA_HOME/webapps/$app2/META-INF/context.xml | grep 'logEffectiveWebXml="true"' | wc -l )
#if [[ $metadata2 == 0 ]] || [[ $effective2 == 0 ]]
#then
#echo " 10.18 Use the logEffectiveWebXml and metadata-complete settings for deploying applications in production for APP: $app2: FAILED "
#else
#echo " 10.18 Use the logEffectiveWebXml and metadata-complete settings for deploying applications in production for APP: $app2: PASSED "
#fi




