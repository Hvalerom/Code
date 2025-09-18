#Requires -RunAsAdministrator

# --- Funciones de Ayuda ---
function Write-RuleTitle {
    param([string]$Title)
    Write-Host "-----------------------------------------" -ForegroundColor Yellow
    Write-Host "  $Title" -ForegroundColor White
    Write-Host "-----------------------------------------" -ForegroundColor Yellow
}

function Pause-Script {
    Write-Host "`nPresiona Enter para continuar..." -ForegroundColor Cyan
    Read-Host | Out-Null
}

# --- Funciones para cada Regla (Aplicar y Revertir) ---

# Regla 1: Habilitar Firewall de Windows (Todos los perfiles)
function Apply-Rule1 {
    Write-RuleTitle "Aplicando Regla 1: Habilitar Firewall (Todos los perfiles)"
    try {
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled True -ErrorAction Stop
        Write-Host "[+] Firewall habilitado para perfiles Domain, Private, Public." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al habilitar el Firewall: $($_.Exception.Message)"
    }
}
function Revert-Rule1 {
    Write-RuleTitle "Revirtiendo Regla 1: Deshabilitar Firewall (Todos los perfiles) - ¡Precaución!"
    try {
        # Nota: Deshabilitar el firewall generalmente no es recomendado. La reversión podría ser simplemente no hacer nada o restaurar a un estado previo conocido si se guardó.
        # Por simplicidad, aquí lo desactivamos, pero se advierte al usuario.
        Write-Warning "[!] ADVERTENCIA: Deshabilitar el Firewall reduce significativamente la seguridad."
        Set-NetFirewallProfile -Profile Domain, Private, Public -Enabled False -ErrorAction Stop
        Write-Host "[+] Firewall deshabilitado para perfiles Domain, Private, Public." -ForegroundColor Yellow
    } catch {
        Write-Warning "[!] Error al deshabilitar el Firewall: $($_.Exception.Message)"
    }
}

# Regla 2: Configurar UAC (Control de Cuentas de Usuario) a 'Notificar Siempre'
function Apply-Rule2 {
    Write-RuleTitle "Aplicando Regla 2: Configurar UAC a 'Notificar Siempre'"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 2 -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -ErrorAction Stop
        Write-Host "[+] UAC configurado para notificar siempre (requiere reinicio para efecto completo)." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al configurar UAC: $($_.Exception.Message)"
    }
}
function Revert-Rule2 {
    Write-RuleTitle "Revirtiendo Regla 2: Configurar UAC a 'Predeterminado'"
    try {
        # Valor predeterminado típico (Notificar solo cuando las apps intentan hacer cambios)
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Value 5 -ErrorAction Stop
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Value 1 -ErrorAction Stop
        Write-Host "[+] UAC configurado a predeterminado (requiere reinicio para efecto completo)." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir configuración UAC: $($_.Exception.Message)"
    }
}

# Regla 3: Establecer Longitud Mínima de Contraseña (14 caracteres)
function Apply-Rule3 {
    Write-RuleTitle "Aplicando Regla 3: Longitud Mínima de Contraseña a 14"
    try {
        net accounts /minpwlen:14
        Write-Host "[+] Longitud mínima de contraseña establecida a 14." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al establecer longitud mínima de contraseña: $($_.Exception.Message)"
    }
}
function Revert-Rule3 {
    Write-RuleTitle "Revirtiendo Regla 3: Longitud Mínima de Contraseña a 8"
    try {
        # Revertir a un valor común o predeterminado (ej. 8 o 0 si no se requiere)
        net accounts /minpwlen:8
        Write-Host "[+] Longitud mínima de contraseña revertida a 8." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir longitud mínima de contraseña: $($_.Exception.Message)"
    }
}

# Regla 4: Habilitar Complejidad de Contraseña
function Apply-Rule4 {
    Write-RuleTitle "Aplicando Regla 4: Requerir Complejidad de Contraseña"
     try {
        # Usa 'secedit' para políticas de seguridad locales
        $inf = "complexpass.inf"
        $sdb = "complexpass.sdb"
        "[Unicode]","Unicode=yes","[System Access]","PasswordComplexity = 1","[Version]","signature=`"`$CHICAGO$`"","Revision=1" | Out-File $inf -Encoding Unicode -Force
        secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY /quiet
        Remove-Item $inf -Force -ErrorAction SilentlyContinue
        Remove-Item $sdb -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Complejidad de contraseña habilitada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al habilitar complejidad de contraseña: $($_.Exception.Message)"
    }
}
function Revert-Rule4 {
    Write-RuleTitle "Revirtiendo Regla 4: Deshabilitar Complejidad de Contraseña"
     try {
        # Usa 'secedit' para políticas de seguridad locales
        $inf = "complexpass.inf"
        $sdb = "complexpass.sdb"
        "[Unicode]","Unicode=yes","[System Access]","PasswordComplexity = 0","[Version]","signature=`"`$CHICAGO$`"","Revision=1" | Out-File $inf -Encoding Unicode -Force
        secedit /configure /db $sdb /cfg $inf /areas SECURITYPOLICY /quiet
        Remove-Item $inf -Force -ErrorAction SilentlyContinue
        Remove-Item $sdb -Force -ErrorAction SilentlyContinue
        Write-Host "[+] Complejidad de contraseña deshabilitada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar complejidad de contraseña: $($_.Exception.Message)"
    }
}

# Regla 5: Establecer Historial de Contraseñas (Recordar 12 últimas)
function Apply-Rule5 {
    Write-RuleTitle "Aplicando Regla 5: Historial de Contraseñas a 12"
    try {
        net accounts /uniquepw:12
        Write-Host "[+] Historial de contraseñas establecido para recordar 12." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al establecer historial de contraseñas: $($_.Exception.Message)"
    }
}
function Revert-Rule5 {
    Write-RuleTitle "Revirtiendo Regla 5: Historial de Contraseñas a 0 (No recordar)"
    try {
        net accounts /uniquepw:0
        Write-Host "[+] Historial de contraseñas revertido a 0." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir historial de contraseñas: $($_.Exception.Message)"
    }
}

# Regla 6: Establecer Umbral de Bloqueo de Cuenta (5 intentos fallidos)
function Apply-Rule6 {
    Write-RuleTitle "Aplicando Regla 6: Umbral de Bloqueo de Cuenta a 5 intentos"
    try {
        net accounts /lockoutthreshold:5
        Write-Host "[+] Umbral de bloqueo de cuenta establecido a 5 intentos." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al establecer umbral de bloqueo: $($_.Exception.Message)"
    }
}
function Revert-Rule6 {
    Write-RuleTitle "Revirtiendo Regla 6: Deshabilitar Bloqueo de Cuenta (Umbral a 0)"
    try {
        net accounts /lockoutthreshold:0
        Write-Host "[+] Bloqueo de cuenta deshabilitado (umbral establecido a 0)." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir umbral de bloqueo: $($_.Exception.Message)"
    }
}

# Regla 7: Establecer Duración de Bloqueo de Cuenta (30 minutos)
function Apply-Rule7 {
    Write-RuleTitle "Aplicando Regla 7: Duración de Bloqueo a 30 minutos"
    try {
        net accounts /lockoutduration:30
        Write-Host "[+] Duración de bloqueo establecida a 30 minutos." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al establecer duración de bloqueo: $($_.Exception.Message)"
    }
}
function Revert-Rule7 {
    Write-RuleTitle "Revirtiendo Regla 7: Duración de Bloqueo a 30 minutos (valor predeterminado si umbral > 0)"
    try {
        # Nota: El valor predeterminado suele ser 30 si el bloqueo está activo. Si el umbral es 0, este valor no aplica mucho.
        net accounts /lockoutduration:30
        Write-Host "[+] Duración de bloqueo revertida a 30 minutos." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir duración de bloqueo: $($_.Exception.Message)"
    }
}

# Regla 8: Deshabilitar cuenta de Invitado
function Apply-Rule8 {
    Write-RuleTitle "Aplicando Regla 8: Deshabilitar Cuenta de Invitado"
    try {
        net user Invitado /active:no # 'Invitado' es el nombre en español, puede ser 'Guest' en inglés
        Write-Host "[+] Cuenta de Invitado deshabilitada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar cuenta de Invitado (puede que no exista o tenga otro nombre): $($_.Exception.Message)"
    }
}
function Revert-Rule8 {
    Write-RuleTitle "Revirtiendo Regla 8: Habilitar Cuenta de Invitado - ¡Precaución!"
    try {
        Write-Warning "[!] ADVERTENCIA: Habilitar la cuenta de invitado es un riesgo de seguridad."
        net user Invitado /active:yes # 'Invitado' es el nombre en español, puede ser 'Guest' en inglés
        Write-Host "[+] Cuenta de Invitado habilitada." -ForegroundColor Yellow
    } catch {
        Write-Warning "[!] Error al habilitar cuenta de Invitado: $($_.Exception.Message)"
    }
}

# Regla 9: Deshabilitar SMBv1 (Protocolo obsoleto y riesgoso)
function Apply-Rule9 {
    Write-RuleTitle "Aplicando Regla 9: Deshabilitar SMBv1"
    try {
        Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
        Write-Host "[+] SMBv1 deshabilitado (puede requerir reinicio)." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar SMBv1: $($_.Exception.Message)"
    }
}
function Revert-Rule9 {
    Write-RuleTitle "Revirtiendo Regla 9: Habilitar SMBv1 - ¡Precaución!"
    try {
        Write-Warning "[!] ADVERTENCIA: Habilitar SMBv1 es un riesgo de seguridad. Solo si es estrictamente necesario por compatibilidad."
        Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction Stop
        Write-Host "[+] SMBv1 habilitado (puede requerir reinicio)." -ForegroundColor Yellow
    } catch {
        Write-Warning "[!] Error al habilitar SMBv1: $($_.Exception.Message)"
    }
}

# Regla 10: Establecer Política de Ejecución de PowerShell a RemoteSigned
function Apply-Rule10 {
    Write-RuleTitle "Aplicando Regla 10: Política de Ejecución de PowerShell a RemoteSigned"
    try {
        Set-ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -ErrorAction Stop
        Write-Host "[+] Política de Ejecución para LocalMachine establecida a RemoteSigned." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al establecer la política de ejecución: $($_.Exception.Message)"
    }
}
function Revert-Rule10 {
    Write-RuleTitle "Revirtiendo Regla 10: Política de Ejecución de PowerShell a Restricted"
    try {
        # Restricted es el más seguro, pero puede impedir scripts legítimos. AllSigned es otra opción.
        Set-ExecutionPolicy Restricted -Scope LocalMachine -Force -ErrorAction Stop
        Write-Host "[+] Política de Ejecución para LocalMachine revertida a Restricted." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir la política de ejecución: $($_.Exception.Message)"
    }
}

# Regla 11: Deshabilitar Escritorio Remoto (RDP)
function Apply-Rule11 {
    Write-RuleTitle "Aplicando Regla 11: Deshabilitar Escritorio Remoto (RDP)"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 1 -ErrorAction Stop
        # También deshabilita la regla de firewall asociada
        Disable-NetFirewallRule -DisplayGroup "Escritorio remoto"
        Write-Host "[+] Escritorio Remoto deshabilitado." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar RDP: $($_.Exception.Message)"
    }
}
function Revert-Rule11 {
    Write-RuleTitle "Revirtiendo Regla 11: Habilitar Escritorio Remoto (RDP)"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections" -value 0 -ErrorAction Stop
        # Habilita la regla de firewall asociada
        Enable-NetFirewallRule -DisplayGroup "Escritorio remoto"
        Write-Host "[+] Escritorio Remoto habilitado." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al habilitar RDP: $($_.Exception.Message)"
    }
}

# Regla 12: Deshabilitar Asistencia Remota
function Apply-Rule12 {
    Write-RuleTitle "Aplicando Regla 12: Deshabilitar Asistencia Remota"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -name "fAllowToGetHelp" -value 0 -ErrorAction Stop
        Write-Host "[+] Asistencia Remota deshabilitada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar Asistencia Remota: $($_.Exception.Message)"
    }
}
function Revert-Rule12 {
    Write-RuleTitle "Revirtiendo Regla 12: Habilitar Asistencia Remota"
    try {
        Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Remote Assistance' -name "fAllowToGetHelp" -value 1 -ErrorAction Stop
        Write-Host "[+] Asistencia Remota habilitada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al habilitar Asistencia Remota: $($_.Exception.Message)"
    }
}

# Regla 13: Mostrar extensiones de archivo conocidas
function Apply-Rule13 {
    Write-RuleTitle "Aplicando Regla 13: Mostrar extensiones de archivo"
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -ErrorAction Stop
        Write-Host "[+] Configurado para mostrar extensiones de archivo conocidas (aplicado a usuario actual)." -ForegroundColor Green
        # Para aplicar a todos los usuarios, se necesitaría modificar el perfil predeterminado o usar GPO.
    } catch {
        Write-Warning "[!] Error al configurar mostrar extensiones: $($_.Exception.Message)"
    }
}
function Revert-Rule13 {
    Write-RuleTitle "Revirtiendo Regla 13: Ocultar extensiones de archivo"
    try {
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 1 -ErrorAction Stop
        Write-Host "[+] Configurado para ocultar extensiones de archivo conocidas (aplicado a usuario actual)." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir configuración de extensiones: $($_.Exception.Message)"
    }
}

# Regla 14: Requerir Ctrl+Alt+Supr para iniciar sesión
function Apply-Rule14 {
    Write-RuleTitle "Aplicando Regla 14: Requerir Ctrl+Alt+Supr para iniciar sesión"
    try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 0 -ErrorAction Stop
        Write-Host "[+] Se requiere Ctrl+Alt+Supr para iniciar sesión." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al configurar Ctrl+Alt+Supr: $($_.Exception.Message)"
    }
}
function Revert-Rule14 {
    Write-RuleTitle "Revirtiendo Regla 14: No requerir Ctrl+Alt+Supr para iniciar sesión"
    try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DisableCAD" -Value 1 -ErrorAction Stop
        Write-Host "[+] Ya no se requiere Ctrl+Alt+Supr para iniciar sesión." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir configuración Ctrl+Alt+Supr: $($_.Exception.Message)"
    }
}

# Regla 15: No mostrar el último nombre de usuario en inicio de sesión
function Apply-Rule15 {
    Write-RuleTitle "Aplicando Regla 15: No mostrar último usuario en inicio de sesión"
    try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -Value 1 -ErrorAction Stop
        Write-Host "[+] No se mostrará el último nombre de usuario en la pantalla de inicio de sesión." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al configurar ocultar último usuario: $($_.Exception.Message)"
    }
}
function Revert-Rule15 {
    Write-RuleTitle "Revirtiendo Regla 15: Mostrar último usuario en inicio de sesión"
    try {
        Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "dontdisplaylastusername" -Value 0 -ErrorAction Stop
        Write-Host "[+] Se mostrará el último nombre de usuario en la pantalla de inicio de sesión." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir configuración ocultar último usuario: $($_.Exception.Message)"
    }
}

# Regla 16: Deshabilitar ejecución automática (Autorun) en todas las unidades
function Apply-Rule16 {
    Write-RuleTitle "Aplicando Regla 16: Deshabilitar Autorun en todas las unidades"
    try {
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction Stop # 255 (0xFF) deshabilita en todos los tipos
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 255 -ErrorAction Stop # Para usuario actual también
        Write-Host "[+] Autorun deshabilitado para todas las unidades." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar Autorun: $($_.Exception.Message)"
    }
}
function Revert-Rule16 {
    Write-RuleTitle "Revirtiendo Regla 16: Habilitar Autorun (Configuración predeterminada)"
    try {
        # El valor predeterminado suele ser 149 (0x95) o 145 (0x91) dependiendo de la versión de Windows. Usaremos 145.
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 145 -ErrorAction Stop
        Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Value 145 -ErrorAction Stop
        Write-Host "[+] Autorun revertido a configuración predeterminada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir Autorun: $($_.Exception.Message)"
    }
}

# Regla 17: Habilitar Auditoría de Inicio de Sesión (Éxito y Error)
function Apply-Rule17 {
    Write-RuleTitle "Aplicando Regla 17: Habilitar Auditoría de Inicio de Sesión (Éxito y Error)"
    try {
        auditpol /set /subcategory:"Logon" /success:enable /failure:enable
        Write-Host "[+] Auditoría de inicio de sesión habilitada para Éxito y Error." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al habilitar auditoría de inicio de sesión: $($_.Exception.Message)"
    }
}
function Revert-Rule17 {
    Write-RuleTitle "Revirtiendo Regla 17: Deshabilitar Auditoría de Inicio de Sesión"
    try {
        auditpol /set /subcategory:"Logon" /success:disable /failure:disable
        Write-Host "[+] Auditoría de inicio de sesión deshabilitada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar auditoría de inicio de sesión: $($_.Exception.Message)"
    }
}

# Regla 18: Habilitar Auditoría de Administración de Cuentas (Éxito y Error)
function Apply-Rule18 {
    Write-RuleTitle "Aplicando Regla 18: Habilitar Auditoría de Administración de Cuentas (Éxito y Error)"
    try {
        auditpol /set /subcategory:"User Account Management" /success:enable /failure:enable
        auditpol /set /subcategory:"Computer Account Management" /success:enable /failure:enable
        Write-Host "[+] Auditoría de administración de cuentas habilitada para Éxito y Error." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al habilitar auditoría de administración de cuentas: $($_.Exception.Message)"
    }
}
function Revert-Rule18 {
    Write-RuleTitle "Revirtiendo Regla 18: Deshabilitar Auditoría de Administración de Cuentas"
    try {
        auditpol /set /subcategory:"User Account Management" /success:disable /failure:disable
        auditpol /set /subcategory:"Computer Account Management" /success:disable /failure:disable
        Write-Host "[+] Auditoría de administración de cuentas deshabilitada." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar auditoría de administración de cuentas: $($_.Exception.Message)"
    }
}

# Regla 19: Deshabilitar el servicio 'Registro Remoto'
function Apply-Rule19 {
    Write-RuleTitle "Aplicando Regla 19: Deshabilitar Servicio de Registro Remoto"
    try {
        Set-Service -Name RemoteRegistry -StartupType Disabled -ErrorAction Stop
        Stop-Service -Name RemoteRegistry -Force -ErrorAction SilentlyContinue # Intenta detenerlo si está corriendo
        Write-Host "[+] Servicio de Registro Remoto deshabilitado y detenido (si estaba en ejecución)." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al deshabilitar el servicio Registro Remoto: $($_.Exception.Message)"
    }
}
function Revert-Rule19 {
    Write-RuleTitle "Revirtiendo Regla 19: Habilitar Servicio de Registro Remoto (Manual)"
    try {
        # Se revierte a Manual, que es un estado común, en lugar de Automático.
        Set-Service -Name RemoteRegistry -StartupType Manual -ErrorAction Stop
        Write-Host "[+] Servicio de Registro Remoto revertido a tipo de inicio Manual." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir el servicio Registro Remoto: $($_.Exception.Message)"
    }
}

# Regla 20: Limpiar archivo de paginación al apagar
function Apply-Rule20 {
    Write-RuleTitle "Aplicando Regla 20: Limpiar archivo de paginación al apagar"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 1 -ErrorAction Stop
        Write-Host "[+] Configurado para limpiar el archivo de paginación al apagar (puede ralentizar el apagado)." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al configurar la limpieza del archivo de paginación: $($_.Exception.Message)"
    }
}
function Revert-Rule20 {
    Write-RuleTitle "Revirtiendo Regla 20: No limpiar archivo de paginación al apagar"
    try {
        Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "ClearPageFileAtShutdown" -Value 0 -ErrorAction Stop
        Write-Host "[+] Revertido: No se limpiará el archivo de paginación al apagar." -ForegroundColor Green
    } catch {
        Write-Warning "[!] Error al revertir la limpieza del archivo de paginación: $($_.Exception.Message)"
    }
}


# --- Menú Principal ---
do {
    Clear-Host
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host "   MENÚ DE REGLAS DE SEGURIDAD WINDOWS    " -ForegroundColor Magenta
    Write-Host "==========================================" -ForegroundColor Magenta
    Write-Host " ID | Acción      | Regla"
    Write-Host "----|-------------|-------------------------------------------------"
    Write-Host " 1a | Aplicar     | Habilitar Firewall (Todos los perfiles)"
    Write-Host " 1r | Revertir    | Deshabilitar Firewall (Precaución)"
    Write-Host " 2a | Aplicar     | Configurar UAC a 'Notificar Siempre'"
    Write-Host " 2r | Revertir    | Configurar UAC a 'Predeterminado'"
    Write-Host " 3a | Aplicar     | Longitud Mínima Contraseña a 14"
    Write-Host " 3r | Revertir    | Longitud Mínima Contraseña a 8"
    Write-Host " 4a | Aplicar     | Requerir Complejidad de Contraseña"
    Write-Host " 4r | Revertir    | Deshabilitar Complejidad de Contraseña"
    Write-Host " 5a | Aplicar     | Historial de Contraseñas a 12"
    Write-Host " 5r | Revertir    | Historial de Contraseñas a 0"
    Write-Host " 6a | Aplicar     | Umbral de Bloqueo de Cuenta a 5 intentos"
    Write-Host " 6r | Revertir    | Deshabilitar Bloqueo de Cuenta (Umbral a 0)"
    Write-Host " 7a | Aplicar     | Duración de Bloqueo a 30 minutos"
    Write-Host " 7r | Revertir    | Duración de Bloqueo a 30 minutos (Predet.)"
    Write-Host " 8a | Aplicar     | Deshabilitar Cuenta de Invitado"
    Write-Host " 8r | Revertir    | Habilitar Cuenta de Invitado (Precaución)"
    Write-Host " 9a | Aplicar     | Deshabilitar SMBv1"
    Write-Host " 9r | Revertir    | Habilitar SMBv1 (Precaución)"
    Write-Host "10a | Aplicar     | Política Ejecución PowerShell a RemoteSigned"
    Write-Host "10r | Revertir    | Política Ejecución PowerShell a Restricted"
    Write-Host "11a | Aplicar     | Deshabilitar Escritorio Remoto (RDP)"
    Write-Host "11r | Revertir    | Habilitar Escritorio Remoto (RDP)"
    Write-Host "12a | Aplicar     | Deshabilitar Asistencia Remota"
    Write-Host "12r | Revertir    | Habilitar Asistencia Remota"
    Write-Host "13a | Aplicar     | Mostrar extensiones de archivo conocidas"
    Write-Host "13r | Revertir    | Ocultar extensiones de archivo conocidas"
    Write-Host "14a | Aplicar     | Requerir Ctrl+Alt+Supr para inicio de sesión"
    Write-Host "14r | Revertir    | No requerir Ctrl+Alt+Supr para inicio de sesión"
    Write-Host "15a | Aplicar     | No mostrar último usuario en inicio de sesión"
    Write-Host "15r | Revertir    | Mostrar último usuario en inicio de sesión"
    Write-Host "16a | Aplicar     | Deshabilitar Autorun en todas las unidades"
    Write-Host "16r | Revertir    | Habilitar Autorun (Predeterminado)"
    Write-Host "17a | Aplicar     | Habilitar Auditoría de Inicio de Sesión (Éxito/Error)"
    Write-Host "17r | Revertir    | Deshabilitar Auditoría de Inicio de Sesión"
    Write-Host "18a | Aplicar     | Habilitar Auditoría Adm. Cuentas (Éxito/Error)"
    Write-Host "18r | Revertir    | Deshabilitar Auditoría Adm. Cuentas"
    Write-Host "19a | Aplicar     | Deshabilitar Servicio Registro Remoto"
    Write-Host "19r | Revertir    | Habilitar Servicio Registro Remoto (Manual)"
    Write-Host "20a | Aplicar     | Limpiar archivo de paginación al apagar"
    Write-Host "20r | Revertir    | No limpiar archivo de paginación al apagar"
    Write-Host "------------------------------------------------------------------"
    Write-Host "  S | Salir"
    Write-Host "==========================================" -ForegroundColor Magenta

    $choice = Read-Host "Elige una opción (Ej: 1a, 1r, 2a, 2r, ..., S)"

    switch ($choice.ToLower()) {
        '1a' { Apply-Rule1 }
        '1r' { Revert-Rule1 }
        '2a' { Apply-Rule2 }
        '2r' { Revert-Rule2 }
        '3a' { Apply-Rule3 }
        '3r' { Revert-Rule3 }
        '4a' { Apply-Rule4 }
        '4r' { Revert-Rule4 }
        '5a' { Apply-Rule5 }
        '5r' { Revert-Rule5 }
        '6a' { Apply-Rule6 }
        '6r' { Revert-Rule6 }
        '7a' { Apply-Rule7 }
        '7r' { Revert-Rule7 }
        '8a' { Apply-Rule8 }
        '8r' { Revert-Rule8 }
        '9a' { Apply-Rule9 }
        '9r' { Revert-Rule9 }
        '10a' { Apply-Rule10 }
        '10r' { Revert-Rule10 }
        '11a' { Apply-Rule11 }
        '11r' { Revert-Rule11 }
        '12a' { Apply-Rule12 }
        '12r' { Revert-Rule12 }
        '13a' { Apply-Rule13 }
        '13r' { Revert-Rule13 }
        '14a' { Apply-Rule14 }
        '14r' { Revert-Rule14 }
        '15a' { Apply-Rule15 }
        '15r' { Revert-Rule15 }
        '16a' { Apply-Rule16 }
        '16r' { Revert-Rule16 }
        '17a' { Apply-Rule17 }
        '17r' { Revert-Rule17 }
        '18a' { Apply-Rule18 }
        '18r' { Revert-Rule18 }
        '19a' { Apply-Rule19 }
        '19r' { Revert-Rule19 }
        '20a' { Apply-Rule20 }
        '20r' { Revert-Rule20 }
        's'  { Write-Host "Saliendo del script." -ForegroundColor Green }
        default { Write-Warning "Opción no válida. Intenta de nuevo." }
    }

    if ($choice -ne 's') {
        Pause-Script
    }

} until ($choice -eq 's')

Write-Host "`nScript finalizado."
