# Usa la imagen oficial de PostgreSQL como base
FROM postgres:latest

# Copia el archivo init.sql al contenedor
COPY init.sql /docker-entrypoint-initdb.d/

# Exponer el puerto de PostgreSQL (por defecto, 5432)
EXPOSE 5432