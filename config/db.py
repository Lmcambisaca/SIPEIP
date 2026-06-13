import mysql.connector

conexion = mysql.connector.connect(
    host="localhost",
    user="root",
    password="",
    database="sipeip"
)

print("Conexión exitosa")

