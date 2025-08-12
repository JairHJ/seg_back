#!/bin/bash
# Script para detener todos los microservicios del proyecto
# Lee los PID de los archivos .pid y mata los procesos

# Definimos el directorio del proyecto
PROJECT_DIR="$(pwd)"
LOG_DIR="$PROJECT_DIR/logs"

# Verificamos si el directorio de logs existe
if [ ! -d "$LOG_DIR" ]; then
    echo "No se encontró el directorio de logs en $LOG_DIR"
    exit 1
fi

# Función para detener un servicio
stop_service() {
    local service_name=$1
    local pid_file="$LOG_DIR/$service_name.pid"

    if [ -f "$pid_file" ]; then
        local pid
        pid=$(cat "$pid_file")
        
        if kill -0 "$pid" > /dev/null 2>&1; then
            echo "Deteniendo $service_name (PID: $pid)..."
            kill "$pid"
            rm "$pid_file"
            echo "$service_name detenido."
        else
            echo "El proceso $service_name (PID: $pid) no está activo."
            rm "$pid_file"
        fi
    else
        echo "No se encontró archivo PID para $service_name."
    fi
}

# Detenemos cada microservicio
stop_service "api_gateway"
stop_service "auth_service"
stop_service "user_service"
stop_service "task_service"

echo "Todos los microservicios han sido detenidos."
