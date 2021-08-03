@ECHO OFF
CLS
ECHO REMEMBER TO RUN THIS AS ADMINISTRATOR!
ECHO This is a Batch Script written for the AASF project server hardening efforts
ECHO BY Nikolas Coleman 2021. 
ECHO Thank me later...preferably with more money
TIMEOUT /T 5
SET /P DRIVELETTER="PLEASE ENTER THE CURRENT USB DRIVE LETTER: "
CLS
GOTO IMPORTER
SET /P CONTINUE ="Would you like to continue the script or EXIT? [C/E]  :"
IF /I %CONTINUE%==C (GOTO RESUME)
IF /I %CONTUNUE%==E (GOTO CODE_EXIT)
ECHO COPYING FILES FROM USB TO DESKTOP!
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\GPSV\AuditPolicy\audit.inf" "C:\Users\ESSAdmin\Desktop"
ECHO COPIED AUDIT POLICY TO DESKTOP
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\GPSV\SecurityConfigurations\security.inf" "C:\Users\ESSAdmin\Desktop"
ECHO COPIED SECURITY CONFIGURATIONS TO DESKTOP
XCOPY /E /I /Y "%DRIVELETTER%:\AUTO_STIG_SERVER\GPSV\GroupPolicyObjects" "C:\Windows\System32\GroupPolicy"
ECHO COPIED GROUP POLICY OBJECTS TO GROUP POLICY FOLDER
ECHO APPLYING GROUP POLICY
GPUPDATE /FORCE
ECHO IMPORTING SECURITY CONFIGURATIONS!
secedit /configure /cfg C:\Users\ESSAdmin\Desktop\security.inf /db defltbase.sdb /verbose
ECHO IMPORTING AUDIT POLICY!
auditpol /restore /file:C:\Users\ESSAdmin\Desktop\audit.inf
REM RESUME ABOVE HERE IS PRETTY MUCH USELESS TO RESUME AFTER THIS LAST ADDITION. 
:RESUME
ECHO CONFIGURING DEP
BCDEDIT /set {current} nx OptOut
ECHO DISABLING SECONDARY LOGON SERVICE
sc config seclogon start= disabled
ECHO DELETING POWERSHELL V2
REM it is kindof impossible at this time to fully uninstall this program as of now there is no fix.
DISM /online /Disable-Feature /FeatureName:MicrosoftWindowsPowerShellV2
ECHO ADDING REGISTRY VALUES
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\ /v SchUseStrongCrypto /t REG_DWORD /d 1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\ /v SchUseStrongCrypto /t REG_DWORD /d 1
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeCaption /t REG_SZ /d "US Department of Defense Warning Statement"
reg add HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ /v LegalNoticeText /t REG_SZ /d "You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. At any time, the USG may inspect and seize data stored on this IS. Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details."
TIMEOUT /T 3
ECHO CLEANING UP FILES FROM DESKTOP!
DEL C:\Users\ESSAdmin\Desktop\audit.inf /f /q 
DEL C:\Users\ESSAdmin\Desktop\security.inf /f /q


:IMPORTER
CLS
ECHO **************************************************************************************************************
ECHO **************************************************************************************************************
ECHO *                                                                                                                                                                                                                                  
ECHO *              THIS PART OF THE SCRIPT IMPORTS PRIOR CONFIGURATION RULES BASED ON USER  INPUT 
ECHO *
ECHO **************************************************************************************************************
ECHO **************************************************************************************************************
ECHO *
ECHO *				PLEASE SELECT THE SYSTEM YOU WOULD LIKE TO IMPORT:
ECHO *
ECHO *
ECHO *					(1)   ACS GALAXY   
ECHO *			 		(2)   ACS GALLAGHER
ECHO *					(3)   ACS GENETEC
ECHO *					(4)   VMS BOSCH
ECHO *					(5)   VMS GENETEC
ECHO *					(6)   VMS MILESTONE
ECHO *					(7)   NONE OF THE ABOVE                 
ECHO *
ECHO *
SET /P USER_INPUT=" 				WHAT SYSTEM ARE YOU IMPORTING FIREWALL RULES FOR? [1-7]: "
IF /I %USER_INPUT%==1 (GOTO ACS_GALAXY)
IF /I %USER_INPUT%==2 (GOTO ACS_GALLAGHER)
IF /I %USER_INPUT%==3 (GOTO ACS_GENETEC)
IF /I %USER_INPUT%==4 (GOTO VMS_BOSCH)
IF /I %USER_INPUT%==5 (GOTO VMS_GENETEC)
IF /I %USER_INPUT%==6 (GOTO VMS_MILESTONE)
IF /I %USER_INPUT%==7 (GOTO CODE_EXIT)
GOTO CODE_EXIT

:ACS_GALAXY
ECHO NO CONFIG FOR GALAXY AT THIS TIME PLEASE CONTACT NIK COLEMAN
GOTO CODE_EXIT

:ACS_GALLAGHER
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GALLAGHER_ACS\audit.inf" "C:\Users\ESSAdmin\Desktop"
auditpol /restore /file:C:\Users\ESSAdmin\Desktop\audit.inf
DEL C:\Users\ESSAdmin\Desktop\audit.inf /f /q 
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GALLAGHER_ACS\security.inf" "C:\Users\ESSAdmin\Desktop"
secedit /configure /cfg C:\Users\ESSAdmin\Desktop\security.inf /db defltbase.sdb /verbose
DEL C:\Users\ESSAdmin\Desktop\security.inf /f /q
XCOPY /E /I /Y "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GALLAGHER_ACS\PolicyObjects" "C:\Windows\System32\GroupPolicy"
GPUPDATE /FORCE

:ACS_GENETEC
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GENETEC_ACS\audit.inf" "C:\Users\ESSAdmin\Desktop"
auditpol /restore /file:C:\Users\ESSAdmin\Desktop\audit.inf
DEL C:\Users\ESSAdmin\Desktop\audit.inf /f /q 
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GENETEC_ACS\security.inf" "C:\Users\ESSAdmin\Desktop"
secedit /configure /cfg C:\Users\ESSAdmin\Desktop\security.inf /db defltbase.sdb /verbose
DEL C:\Users\ESSAdmin\Desktop\security.inf /f /q
XCOPY /E /I /Y "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GENETEC_ACS\PolicyObjects" "C:\Windows\System32\GroupPolicy"
GPUPDATE /FORCE

:VMS_BOSCH
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\BOSCH_VMS\audit.inf" "C:\Users\ESSAdmin\Desktop"
auditpol /restore /file:C:\Users\ESSAdmin\Desktop\audit.inf
DEL C:\Users\ESSAdmin\Desktop\audit.inf /f /q 
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\BOSCH_VMS\security.inf" "C:\Users\ESSAdmin\Desktop"
secedit /configure /cfg C:\Users\ESSAdmin\Desktop\security.inf /db defltbase.sdb /verbose
DEL C:\Users\ESSAdmin\Desktop\security.inf /f /q
XCOPY /E /I /Y "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\BOSCH_VMS\PolicyObjects" "C:\Windows\System32\GroupPolicy"
GPUPDATE /FORCE

:VMS_GENETEC
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GENETEC_VMS\audit.inf" "C:\Users\ESSAdmin\Desktop"
auditpol /restore /file:C:\Users\ESSAdmin\Desktop\audit.inf
DEL C:\Users\ESSAdmin\Desktop\audit.inf /f /q 
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GENETEC_VMS\security.inf" "C:\Users\ESSAdmin\Desktop"
secedit /configure /cfg C:\Users\ESSAdmin\Desktop\security.inf /db defltbase.sdb /verbose
DEL C:\Users\ESSAdmin\Desktop\security.inf /f /q
XCOPY /E /I /Y "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\GENETEC_VMS\PolicyObjects" "C:\Windows\System32\GroupPolicy"
GPUPDATE /FORCE

:VMS_MILESTONE
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\MILESTONE_VMS\audit.inf" "C:\Users\ESSAdmin\Desktop"
auditpol /restore /file:C:\Users\ESSAdmin\Desktop\audit.inf
DEL C:\Users\ESSAdmin\Desktop\audit.inf /f /q 
COPY "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\MILESTONE_VMS\security.inf" "C:\Users\ESSAdmin\Desktop"
secedit /configure /cfg C:\Users\ESSAdmin\Desktop\security.inf /db defltbase.sdb /verbose
DEL C:\Users\ESSAdmin\Desktop\security.inf /f /q
XCOPY /E /I /Y "%DRIVELETTER%:\AUTO_STIG_SERVER\SRVCONFIGS\MILESTONE_VMS\PolicyObjects" "C:\Windows\System32\GroupPolicy"
GPUPDATE /FORCE

:CODE_EXIT
SET /P EXIT_PROMPT="WOULD YOU LIKE TO RESTART THE COMPUTER NOW? [Y/N]:  
IF  /I %EXIT_PROMPT% ==Y (SHUTDOWN /R /T 3)
IF /I %EXIT_PROMPT%==N (PAUSE)
