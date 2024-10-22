# 3o Entregable - Proyecto Final de Ciberseguridad: Módulos de Python y GitHub 

## Descripción
Este proyecto consiste en la creación de cuatro scripts en Python que realizan diversas tareas de ciberseguridad: análisis de conexiones TCP, detección de servicios sospechosos, consumo de APIs (Shodan e IPAbuseDB), y la implementación de un honeypot SSH. Los scripts aceptan parámetros de entrada y cuentan con menús interactivos para diversas funcionalidades, así como el manejo de errores durante la ejecución.

## Objetivos
- Desarrollar habilidades en Python: Aplicar lo aprendido sobre Python para crear scripts que realicen tareas de ciberseguridad.

## Scripts

1. **analyze_connections.py**
   - Este script analiza las conexiones TCP activas en el sistema y genera un informe sobre las conexiones sospechosas basándose en puertos no estándar.

2. **suspicious_services.py**
   - Este script obtiene los servicios en ejecución en el sistema, identifica aquellos que son sospechosos (por ejemplo, los que están deshabilitados o no están en ejecución), y genera un informe en un archivo de texto. Además, ofrece la opción de exportar los resultados a un archivo de Excel.

3. **modules_api.py**
   - Este script interactúa con las APIs de Shodan e IPAbuseDB para buscar vulnerabilidades y detectar direcciones IP sospechosas.

4. **honeypot_ssh.py**
   - Este script permite crear un honeypot SSH en el sistema, simulando un servidor SSH de kali linux para atraer posibles atacantes.

## Requisitos
- Python 3.x
- Paquetes de Python: `paramiko`, `Requests`, `termcolor`, `shodan`, `openpyxl`
- Tener acceso a PowerShell en Windows para ejecutar ciertos comandos.

## Instrucciones de Uso
Clona el repositorio en tu máquina local:

```bash
git clone https://github.com/AlxCastle/PIA_3E.git
```

Ahora cuentas con la carpeta y los scripts.

### Ejecución del script principal:

El script principal permite seleccionar diferentes opciones a través de un menú interactivo:

```bash
python main.py
```

Las opciones disponibles son:

- **[1]** Iniciar un honeypot SSH
- **[2]** Consultar la API de Shodan
- **[3]** Consultar la API de IPAbuseDB
- **[4]** Analizar conexiones TCP
- **[5]** Detectar servicios sospechosos
- **[0]** Salir

### Ejemplo de Ejecución

Ejemplo 1: Ejecutar el análisis de conexiones y guardar el informe en un archivo específico:

```bash
python main.py
```

Seleccione la opción 4 y siga las instrucciones que da el programa.

## Demostración
Puedes ver un video corto de la explicación y ejecución de los scripts aquí: https://youtu.be/bmVoowfu71o

## Colaboradores
Este proyecto fue desarrollado en colaboración con:

- Emilio Rafael Puente Cardona
- Manuel Emilio Delgado Gómez
- Alondra Castillo Gonzalez
  
