# Monitor de Red - Especificaciones y Guía de Instalación

## 📹 Video de Demostración

Puedes ver el video de demostración del monitor de red en acción:
- **Video:** https://www.youtube.com/watch?v=MYRtj2fI4LY
- **Contenido:** Muestra el dashboard web en tiempo real, detección de conexiones sospechosas y el sistema de bloqueo automático/manual

> **¡ADVERTENCIA IMPORTANTE!**
> 
> **La versión automática BLOQUEARÁ TODAS LAS CONEXIONES SOSPECHOSAS SIN PREGUNTAR.**
> 
> **Solo para usuarios avanzados** con experiencia en:
> - Configuración de firewalls
> - Resolución de problemas de red
> - Gestión de listas blancas/negras
> 
> **Puede interrumpir servicios críticos si no se configura correctamente.**

## 🔄 PASO 1: Requisitos Previos
**¿Qué es?** Son las dependencias necesarias para compilar y ejecutar el monitor de red.

**Requisitos:**
- **Windows 7 o superior** (sistema operativo)
- **Privilegios de administrador** (para firewall y monitoreo de red)
- **Conexión a Internet** (para geolocalización de IPs)
- **Go 1.19 o superior** (para compilar el código fuente)

**Verificación de Go:**
```bash
go version
```
Si no tienes Go instalado, descárgalo desde: https://golang.org/dl/

## 🔄 PASO 2: Estructura del Proyecto
**¿Qué es?** Es la organización de archivos y carpetas del monitor de red.

**Estructura de Archivos:**
```
Network-Monitor/
├── network-monitor_Auto/        # Versión automática (bloqueo sin confirmación)
│   ├── network-monitor_Auto.go  # Código fuente principal
│   ├── go.mod                   # Módulos Go
│   └── go.sum                   # Hash de dependencias
│   ├── build.txt               # Comando de compilación
├── network-monitor_Manual/      # Versión manual (requiere aprobación)
│   ├── network-monitor_Manual.go # Código fuente principal
│   ├── web.go                   # Servidor web para dashboard
│   ├── dashboard.html           # Interfaz web moderna
│   ├── build.txt               # Comando de compilación
│   ├── go.mod                  # Módulos Go
│   ├── go.sum                  # Hash de dependencias
├── README.md                   # Guía de instalación
└── LICENSE.txt                 # Licencia del software
```

## 🔄 PASO 3: Compilación del Monitor
**¿Qué es?** Es el proceso de convertir el código fuente en un ejecutable.

**Pasos de Compilación:**

1. **Abrir terminal o PowerShell**

2. **Navegar a la carpeta deseada:**
```bash
cd "c:\a\ruta\\Network-Monitor con  IA\network-monitor_Manual"
```

3. **Compilar la versión manual:**
```bash
go build -ldflags="-s -w" -o network-monitor_Manual.exe network-monitor_Manual.go web.go
```

4. **Verificar ejecutable creado:**
```bash
dir network-monitor_Manual.exe
```

## 🔄 PASO 4: Configuración Inicial (NO Crear, solo para referencia)
**¿Qué es?** Es la preparación de listas de seguridad y configuración básica.

**Archivos de Configuración:**

### whitelist.txt (IPs permitidas)
```bash
# Ejemplo de lista blanca (IPs permitidas)
192.168.1.1
10.0.0.1
127.0.0.1
```

### blacklist.txt (las que coloques aqui firewall bloqueara)
```bash
# Formato: IP | Proceso | Organización | Motivo | Efectos
1.1.1.1 | malware.exe | Hacker Inc. | Malware | Ninguno
2.2.2.2 | * | Red sospechosa | Bloqueo preventivo | Posible pérdida de servicio
```



## 🔄 PASO 5: Ejecución y Uso
**¿Qué es?** Es el inicio del monitor y uso del dashboard web.

**Pasos de Ejecución:**

1. **Ejecutar como administrador:**
```bash
# En PowerShell como administrador
.\network-monitor_Manual.exe
```

2. **Dashboard Web Automático:**
   - Se abre automáticamente en http://localhost:8080
   - Interfaz moderna con actualización en tiempo real
   - Visualización de conexiones, listas y estadísticas

3. **Monitoreo en Terminal:**
   - Verás logs en tiempo real
   - Alertas de conexiones sospechosas
   - Opciones de bloqueo manual

## 🔄 PASO 6: Características Avanzadas
**¿Qué es?** Son las funcionalidades mejoradas de esta versión.

### Dashboard Web Moderno
- **Interfaz responsive** con diseño oscuro profesional
- **Actualización automática** cada 5 segundos
- **Filtros en tiempo real** por estado, IP, proceso
- **Visualización de geolocalización** con mapas integrados
- **Exportación de datos** en CSV y JSON

### Sistema de Logging Mejorado
- **Múltiples formatos:** TXT, CSV, JSON
- **Sesiones organizadas** por fecha y hora
- **Integración directa** con dashboard web
- **Búsqueda avanzada** y filtrado

### Control de Conexiones Inteligente
- **Detección automática** de anomalías
- **Validación de hashes** de ejecutables confiables
- **Geolocalización con caché** para optimizar rendimiento
- **Integración con Windows Firewall**

## 🔄 PASO 7: Mantenimiento y Seguridad
**¿Qué es?** Son las mejores prácticas para mantener el sistema seguro.

**Recomendaciones de Seguridad:**
- **Revisar logs regularmente** (diariamente si es posible)
- **Mantener listas actualizadas** con nuevas IPs conocidas
- **Validar hashes** de ejecutables del sistema
- **Monitorear rendimiento** del sistema



## Descripción General
Aplicación de seguridad que monitorea conexiones de red en tiempo real, desarrollada en Go para Windows con dashboard web moderno.

## Características Clave

- **Monitoreo en Tiempo Real**
  - Conexiones TCP activas
  - Procesos asociados
  - Detección de anomalías

- **Dashboard Web Moderno**
  - Interfaz responsive con actualización automática
  - Visualización en tiempo real de conexiones
  - Filtros y búsqueda avanzada
  - Exportación de datos en múltiples formatos

- **Control de Acceso**
  - Lista Blanca (IPs permitidas)
  - Lista Negra (IPs/procesos bloqueados)
  - Lista de Desconocidas
  - Validación de hashes de ejecutables

- **Geolocalización**
  - Ubicación de IPs remotas
  - Caché integrado para rendimiento
  - Límite de consultas API
  - Visualización en mapa

- **Firewall**
  - Bloqueo automático/manual
  - Integración con Windows Firewall
  - Registro detallado
  - Reversión de cambios

## Componentes Principales

### 1. Almacenamiento (Storage)
- Gestión de archivos de configuración
- Almacenamiento persistente de listas y registros
- Sincronización segura para acceso concurrente
- Soporte para múltiples formatos (TXT, CSV, JSON)

### 2. Geolocalizador (GeoLocator)
- Consulta de información geográfica de IPs
- Sistema de caché para mejorar el rendimiento
- Control de tasa de consultas
- Integración con dashboard web

### 3. Firewall
- Bloqueo de conexiones no autorizadas
- Integración con el sistema operativo
- Registro de eventos de bloqueo
- Interfaz web para gestión

### 4. Monitor de Conexiones
- Monitoreo continuo de conexiones de red
- Detección de anomalías
- Gestión de eventos críticos
- Validación de hashes de procesos

### 5. Servidor Web (web.go)
- Dashboard en tiempo real en localhost:8080
- API REST para consulta de datos
- Actualización automática cada 5 segundos
- Interfaz moderna y responsive

## Versiones Disponibles

### 1. Versión Automática
- **Bloqueo automático** sin confirmación
- **Ideal para**:
  - Usuarios expertos
  - Protección estricta
  - Respuesta inmediata
- **Riesgos**:
  - Bloqueo de servicios legítimos
  - Requiere configuración cuidadosa

### 2. Versión Manual (Recomendada)
- **Control total** del usuario
- **Dashboard web moderno** incluido
- **Ideal para**:
  - Entornos que requieren revisión
  - Usuarios que prefieren control total
  - Minimizar falsos positivos
  - Visualización en tiempo real

## Limitaciones
- Posibles falsos positivos/negativos
- Rendimiento en sistemas con muchas conexiones
- Dependencia de permisos UAC
- Requiere conexión a Internet para geolocalización

## Troubleshooting Común

### Problema: "Acceso denegado"
**Solución:** Ejecutar como administrador

### Problema: "Dashboard no se abre"
**Solución:** Verificar que el puerto 8080 esté disponible

### Problema: "Geolocalización no funciona"
**Solución:** Verificar conexión a Internet y límites de API

### Problema: "Alto uso de CPU"
**Solución:** Reducir frecuencia de monitoreo en configuración

## 🔧 Cómo Reducir el Uso de CPU:

Para reducir la frecuencia de monitoreo y disminuir el uso de CPU, puedes modificar el valor en esa línea:

**Ubicación:** `network-monitor_Manual.go` - **Función `StartMonitoring()`**

**Código actual:**
```go
ticker := time.NewTicker(100 * time.Millisecond) // 100ms de detección
```

### Opciones recomendadas:

1. **Bajo uso de CPU (recomendado):**
   ```go
   ticker := time.NewTicker(500 * time.Millisecond) // 500ms de detección
   ```

2. **Muy bajo uso de CPU:**
   ```go
   ticker := time.NewTicker(1000 * time.Millisecond) // 1 segundo de detección
   ```

3. **Uso mínimo de CPU:**
   ```go
   ticker := time.NewTicker(2000 * time.Millisecond) // 2 segundos de detección
   ```

### Pasos para Modificar:
1. **Abrir el archivo** `network-monitor_Manual.go`
2. **Buscar la función** `StartMonitoring()`
3. **Localizar la línea** con `time.NewTicker(100 * time.Millisecond)`
4. **Cambiar `100 * time.Millisecond`** por uno de los valores sugeridos
5. **Guardar el archivo**
6. **Recompilar** con el comando:
   ```bash
   go build -ldflags="-s -w" -o network-monitor_Manual.exe network-monitor_Manual.go web.go
   ```

⚠️ **Nota:** Mayor valor = menor uso de CPU pero detección más lenta de conexiones sospechosas.

## Reasons for not making it open source:

https://www.youtube.com/watch?v=hbbXzuLOyJ0

https://www.youtube.com/watch?v=alfIxtD9CKM
