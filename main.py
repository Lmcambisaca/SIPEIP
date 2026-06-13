from flask import Flask, render_template, request, redirect, session
from datetime import timedelta
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import re


app = Flask(__name__)
app.permanent_session_lifetime = timedelta(minutes=15)
app.secret_key = "sipeip2026"

# ==========================================
# SESION EXPIRE 
# ==========================================

from datetime import timedelta

# ==========================================
# CONEXIÓN MYSQL
# ==========================================

def conectar():
    return mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="sipeip"
    )

# ==========================================
# LISTAR USUARIOS
# ==========================================

@app.route('/')
def listar_usuarios():

    if 'usuario' not in session:
        return redirect('/login')

    if session['id_rol'] != 1:
        return "Acceso denegado. Solo los administradores pueden ingresar."

    buscar = request.args.get('buscar', '')
    estado = request.args.get('estado', '')
    rol = request.args.get('rol', '')

    conexion = conectar()
    cursor = conexion.cursor()

    consulta = """
        SELECT u.id_usuario,
               u.nombre,
               u.apellido,
               u.correo,
               u.estado,
               r.nombre_rol
        FROM usuario u
        INNER JOIN rol r
        ON u.id_rol = r.id_rol
        WHERE 1=1
    """

    parametros = []

    if buscar:
        consulta += """
            AND (
                u.nombre LIKE %s
                OR u.apellido LIKE %s
                OR u.correo LIKE %s
            )
        """
        parametros.extend([
            f"%{buscar}%",
            f"%{buscar}%",
            f"%{buscar}%"
        ])

    if estado:
        consulta += " AND u.estado = %s"
        parametros.append(estado)

    if rol:
        consulta += " AND r.nombre_rol = %s"
        parametros.append(rol)

    cursor.execute(consulta, parametros)

    usuarios = cursor.fetchall()

    conexion.close()

    return render_template(
        'usuarios.html',
        usuarios=usuarios
    )

# ==========================================
# LOGIN
# ==========================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        correo = request.form['correo']
        password = request.form['password']

        conexion = conectar()
        cursor = conexion.cursor()

        cursor.execute("""
            SELECT *
            FROM usuario
            WHERE correo=%s
        """, (correo,))

        usuario = cursor.fetchone()

        conexion.close()

        if usuario and check_password_hash(usuario[4], password):

            session.permanent = True

            session['usuario'] = usuario[1]
            session['id_rol'] = usuario[7]

            return redirect('/')

        else:
            return "Correo o contraseña incorrectos"

    return render_template('login.html')

@app.route('/logout')
def logout():

    session.clear()

    return redirect('/login')

# ==========================================
# REGISTRAR USUARIO
# ==========================================

@app.route('/registrar_usuario', methods=['GET', 'POST'])
def registrar_usuario():

    if request.method == 'POST':

        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        password = request.form['password']
        id_rol = request.form['id_rol']

        # Validar campos obligatorios
        if not nombre or not apellido or not correo or not password or not id_rol:
            return "Todos los campos son obligatorios"

        # Validar formato de correo
        patron_correo = r'^[\w\.-]+@[\w\.-]+\.\w+$'

        if not re.match(patron_correo, correo):
            return "Ingrese un correo electrónico válido"

        password_hash = generate_password_hash(password)

        conexion = conectar()
        cursor = conexion.cursor()

        # Verificar si el correo ya existe
        cursor.execute(
            "SELECT * FROM usuario WHERE correo = %s",
            (correo,)
        )

        usuario_existente = cursor.fetchone()

        if usuario_existente:
            conexion.close()
            return "El correo ya se encuentra registrado"

        # Registrar usuario
        cursor.execute("""
            INSERT INTO usuario
            (nombre, apellido, correo, password, estado, id_rol)
            VALUES (%s,%s,%s,%s,%s,%s)
        """, (
            nombre,
            apellido,
            correo,
            password_hash,
            'Activo',
            id_rol
        ))

        conexion.commit()
        conexion.close()

        return "Usuario registrado correctamente"

    return render_template('registrar_usuario.html')

# ==========================================
# EDITAR USUARIO
# ==========================================

@app.route('/editar_usuario/<int:id>', methods=['GET', 'POST'])
def editar_usuario(id):

    conexion = conectar()
    cursor = conexion.cursor()

    if request.method == 'POST':

        nombre = request.form['nombre']
        apellido = request.form['apellido']
        correo = request.form['correo']
        id_rol = request.form['id_rol']

        # Verificar correo duplicado
        cursor.execute("""
            SELECT *
            FROM usuario
            WHERE correo = %s
            AND id_usuario <> %s
        """, (correo, id))

        usuario_existente = cursor.fetchone()

        if usuario_existente:
            conexion.close()
            return "El correo ya se encuentra registrado"

        # Actualizar usuario
        cursor.execute("""
            UPDATE usuario
            SET nombre=%s,
                apellido=%s,
                correo=%s,
                id_rol=%s
            WHERE id_usuario=%s
        """, (
            nombre,
            apellido,
            correo,
            id_rol,
            id
        ))

        conexion.commit()
        conexion.close()

        return "Usuario actualizado correctamente"

    # Mostrar datos del usuario
    cursor.execute("""
        SELECT id_usuario,
               nombre,
               apellido,
               correo,
               id_rol
        FROM usuario
        WHERE id_usuario=%s
    """, (id,))

    usuario = cursor.fetchone()

    conexion.close()

    return render_template(
        'editar_usuario.html',
        usuario=usuario
    )

# ==========================================
# ELIMINAR USUARIO
# ==========================================

@app.route('/eliminar_usuario/<int:id>')
def eliminar_usuario(id):

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(
        "DELETE FROM usuario WHERE id_usuario=%s",
        (id,)
    )

    conexion.commit()
    conexion.close()

    return "Usuario eliminado correctamente"

# ==========================================
# DESACTIVAR USUARIO
# ==========================================

@app.route('/desactivar_usuario/<int:id>')
def desactivar_usuario(id):

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(
        """
        UPDATE usuario
        SET estado='Inactivo'
        WHERE id_usuario=%s
        """,
        (id,)
    )

    conexion.commit()
    conexion.close()

    return "Usuario desactivado correctamente"

# ==========================================
# ACTIVAR USUARIO
# ==========================================

@app.route('/activar_usuario/<int:id>')
def activar_usuario(id):

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute(
        """
        UPDATE usuario
        SET estado='Activo'
        WHERE id_usuario=%s
        """,
        (id,)
    )

    conexion.commit()
    conexion.close()

    return "Usuario activado correctamente"

# ==========================================
# EJECUTAR FLASK
# ==========================================

if __name__ == '__main__':
    app.run(debug=True)