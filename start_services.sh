#!/bin/bash
PROJECT_DIR="$(pwd)"
LOG_DIR="$PROJECT_DIR/logs"

mkdir -p "$LOG_DIR"

# Usaremos el Python del sistema ya que las dependencias están instaladas

check_port() {
    local port=$1
    if lsof -i:$port > /dev/null; then
        echo "Error: El puerto $port ya está en uso."
        exit 1
    fi
}

check_port 5000
check_port 5001
check_port 5002
check_port 5003

start_service() {
    local service_dir=$1
    local service_name=$2
    local port=$3
    echo "Iniciando $service_name en el puerto $port..."
    cd "$PROJECT_DIR/$service_dir" || exit 1
    # No usar entorno virtual, usar sistema
    python3 app.py > "$LOG_DIR/$service_name.log" 2>&1 &
    echo "$!" > "$LOG_DIR/$service_name.pid"
    cd "$PROJECT_DIR"
}

start_service "api_gateway" "api_gateway" 5000
start_service "auth_service" "auth_service" 5001
start_service "user_service" "user_service" 5002
start_service "task_service" "task_service" 5003

echo "Todos los microservicios han sido iniciados."
echo "Logs disponibles en $LOG_DIR"
echo "Para detener los servicios, usa el comando 'stop_services.sh'."
