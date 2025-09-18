# Windows Security Rules (PowerShell)

Este script de PowerShell (requiere ejecutarse como administrador) provee un **menú interactivo** para aplicar o revertir 20 reglas de endurecimiento de seguridad en Windows.  
Incluye ajustes de firewall, UAC, políticas de contraseñas, servicios, protocolos, auditorías y configuraciones de inicio de sesión.

## Características

- ✅ Habilitar/deshabilitar **Firewall** en todos los perfiles  
- ✅ Configurar **UAC** (Control de Cuentas de Usuario)  
- ✅ Políticas de contraseñas: longitud mínima, complejidad, historial, bloqueo de cuenta  
- ✅ Deshabilitar SMBv1, RDP, Asistencia Remota y cuenta Invitado  
- ✅ Mostrar/ocultar extensiones de archivo  
- ✅ Requerir/no requerir **Ctrl+Alt+Supr** al iniciar sesión  
- ✅ Configurar **Autorun**  
- ✅ Activar/desactivar auditorías de seguridad (inicio de sesión, administración de cuentas)  
- ✅ Deshabilitar/habilitar servicio **RemoteRegistry**  
- ✅ Limpiar/no limpiar **pagefile** al apagar  

## Uso

1. Ejecutar PowerShell como **Administrador**.  
2. Descargar el script:  
   ```powershell
   git clone https://github.com/tuusuario/windows-security-rules.git
   cd windows-security-rules
