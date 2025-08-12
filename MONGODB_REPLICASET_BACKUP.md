# Documentación de Redundancia y Respaldo en MongoDB

## Redundancia (Replica Set)

Para asegurar alta disponibilidad y redundancia de datos en MongoDB, se recomienda usar un Replica Set. Un Replica Set es un grupo de instancias de MongoDB que mantienen el mismo conjunto de datos, proporcionando tolerancia a fallos y recuperación automática.

### Pasos básicos para configurar un Replica Set local:

1. Inicia varios procesos de mongod en diferentes puertos y carpetas de datos:
   
   ```bash
   mongod --replSet rs0 --port 27017 --dbpath /data/db1 --bind_ip localhost &
   mongod --replSet rs0 --port 27018 --dbpath /data/db2 --bind_ip localhost &
   mongod --replSet rs0 --port 27019 --dbpath /data/db3 --bind_ip localhost &
   ```

2. Conéctate a uno de los nodos y configura el Replica Set:
   
   ```bash
   mongo --port 27017
   > rs.initiate({
       _id: "rs0",
       members: [
         { _id: 0, host: "localhost:27017" },
         { _id: 1, host: "localhost:27018" },
         { _id: 2, host: "localhost:27019" }
       ]
     })
   ```

3. Verifica el estado:
   
   ```bash
   > rs.status()
   ```

## Respaldo (Backup y Restore)

- **Backup:**
  
  ```bash
  mongodump --uri="mongodb://localhost:27017/api_gateway_db" --out ./backup/
  ```

- **Restore:**
  
  ```bash
  mongorestore --uri="mongodb://localhost:27017/api_gateway_db" ./backup/api_gateway_db/
  ```

Para entornos productivos, se recomienda usar servicios gestionados (MongoDB Atlas) o scripts de backup automáticos y almacenamiento externo.

---

Para más detalles, consulta la documentación oficial de MongoDB: https://www.mongodb.com/docs/manual/replication/
