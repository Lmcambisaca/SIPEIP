from flask import Flask, render_template, request, redirect, session
from datetime import timedelta
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import re
def es_admin():
    return session.get('id_rol') == 1


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

    if 'intentos' not in session:
        session['intentos'] = 0

    if request.method == 'POST':

        if session['intentos'] >= 3:
            return "Cuenta bloqueada temporalmente. Demasiados intentos fallidos."

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

        if usuario and check_password_hash(usuario[4], password):

            # Validar estado de la cuenta

            if usuario[5] != 'Activo':
                conexion.close()
                return "La cuenta se encuentra inactiva"

            session['intentos'] = 0

            session.permanent = True

            print(usuario)

            session['usuario'] = usuario[1]
            session['id_rol'] = usuario[7]

            # Registrar inicio de sesión

            cursor.execute("""
                INSERT INTO auditoria_sesion(usuario, accion)
                VALUES(%s,%s)
            """, (
                usuario[1],
                'Inicio de sesión'
            ))

            conexion.commit()
            conexion.close()

            return redirect('/')

        else:

            conexion.close()

            session['intentos'] += 1

            return f"Correo o contraseña incorrectos. Intento {session['intentos']} de 3"

    return render_template('login.html')

# ==========================================
# cerrar sesion
# ==========================================

@app.route('/logout')
def logout():

    usuario = session.get('usuario')

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        INSERT INTO auditoria_sesion
        (usuario, accion)
        VALUES (%s, %s)
    """, (
        usuario,
        'Cierre de sesión'
    ))

    conexion.commit()
    conexion.close()

    session.clear()

    return redirect('/login')

# ==========================================
# RECUPERAR CONTRASEÑA
# ==========================================

@app.route('/recuperar_password', methods=['GET', 'POST'])
def recuperar_password():

    if request.method == 'POST':

        correo = request.form['correo']
        password_actual = request.form['password_actual']
        password = request.form['password']
        confirmar = request.form['confirmar']

        if password != confirmar:
            return "Las contraseñas no coinciden"

        conexion = conectar()
        cursor = conexion.cursor()

        cursor.execute("""
            SELECT *
            FROM usuario
            WHERE correo = %s
        """, (correo,))

        usuario = cursor.fetchone()

        if not usuario:
            conexion.close()
            return "El correo no existe"
        
        password_hash = generate_password_hash(password)

        cursor.execute("""
            UPDATE usuario
            SET password = %s
            WHERE correo = %s
        """, (password_hash, correo))
        
        cursor.execute("""
            INSERT INTO recuperacion_password (correo)
            VALUES (%s)
        """, (correo,))

        conexion.commit()
        conexion.close()

        return "Contraseña actualizada correctamente"

    return render_template('recuperar_password.html')

# ==========================================
# REGISTRAR USUARIO
# ==========================================
 
@app.route('/registrar_usuario', methods=['GET', 'POST'])
def registrar_usuario():

    if not es_admin():
        return "Acceso denegado"

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
    
    if not es_admin():
        return "Acceso denegado"

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
    
    if not es_admin():
        return "Acceso denegado"

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

    if not es_admin():
        return "Acceso denegado"

# Obtener nombre del usuario

    cursor.execute("""
        SELECT nombre
        FROM usuario
        WHERE id_usuario=%s
    """, (id,))

    usuario = cursor.fetchone()

    if not usuario:
        conexion.close()
        return "Usuario no encontrado"

    nombre_usuario = usuario[0]

    # Verificar última actividad

    cursor.execute("""
        SELECT accion
        FROM auditoria_sesion
        WHERE usuario=%s
        ORDER BY fecha DESC
        LIMIT 1
    """, (nombre_usuario,))

    ultima_accion = cursor.fetchone()

    if ultima_accion and ultima_accion[0] == 'Inicio de sesión':

        conexion.close()

        return "No se puede desactivar el usuario porque mantiene una sesión activa."

    # Desactivar usuario

    cursor.execute("""
        UPDATE usuario
        SET estado='Inactivo'
        WHERE id_usuario=%s
    """, (id,))

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
    
    if not es_admin():
        return "Acceso denegado"

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
# LISTAR ROLES
# ==========================================

@app.route('/roles')
def roles():

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM rol
    """)

    roles = cursor.fetchall()

    conexion.close()

    return render_template(
        'roles.html',
        roles=roles
    )
    
# ==========================================
# REGISTRAR ROL
# ==========================================

@app.route('/registrar_rol', methods=['GET', 'POST'])
def registrar_rol():

    conexion = conectar()
    cursor = conexion.cursor()

    if request.method == 'POST':

        nombre_rol = request.form['nombre_rol']
        descripcion = request.form['descripcion']

        cursor.execute("""
            SELECT *
            FROM rol
            WHERE nombre_rol=%s
        """, (nombre_rol,))

        rol_existente = cursor.fetchone()

        if rol_existente:

            conexion.close()

            return "El rol ya existe"

        cursor.execute("""
            INSERT INTO rol(nombre_rol, descripcion)
            VALUES(%s,%s)
        """, (
            nombre_rol,
            descripcion
        ))

        conexion.commit()
        conexion.close()

        return "Rol registrado correctamente"

    conexion.close()

    return render_template('registrar_rol.html')
    

# ==========================================
# EDITAR ROL
# ==========================================

@app.route('/editar_rol/<int:id>', methods=['GET', 'POST'])
def editar_rol(id):

    conexion = conectar()
    cursor = conexion.cursor()
    
    if not es_admin():
        return "Acceso denegado"

    if request.method == 'POST':

        nombre_rol = request.form['nombre_rol']
        descripcion = request.form['descripcion']

        if not nombre_rol or not descripcion:
            conexion.close()
            return "Todos los campos son obligatorios"
        
        cursor.execute("""
            SELECT *
            FROM rol
            WHERE id_rol=%s
        """, (id,))

        rol_existente = cursor.fetchone()

        if not rol_existente:
            conexion.close()
            return "El rol no existe"

        cursor.execute("""
            SELECT *
            FROM rol
            WHERE nombre_rol=%s
            AND id_rol<>%s
        """, (nombre_rol, id))

        rol_duplicado = cursor.fetchone()

        if rol_duplicado:
            conexion.close()
            return "Ya existe un rol con ese nombre"

        cursor.execute("""
            UPDATE rol
            SET nombre_rol=%s,
                descripcion=%s
            WHERE id_rol=%s
        """, (
            nombre_rol,
            descripcion,
            id
        ))

        conexion.commit()
        conexion.close()

        return "Rol actualizado correctamente"

    cursor.execute("""
        SELECT *
        FROM rol
        WHERE id_rol=%s
    """, (id,))

    rol = cursor.fetchone()

    if not rol:
        conexion.close()
        return "El rol no existe"

    conexion.close()

    return render_template(
        'editar_rol.html',
        rol=rol
    )
    
# ==========================================
# ELIMINAR ROL
# ==========================================
    
@app.route('/eliminar_rol/<int:id>')
def eliminar_rol(id):

    conexion = conectar()
    cursor = conexion.cursor()
    
    if not es_admin():
        return "Acceso denegado"

    cursor.execute("""
        SELECT *
        FROM rol
        WHERE id_rol=%s
    """, (id,))

    rol = cursor.fetchone()

    if not rol:

        conexion.close()

        return "El rol no existe"

    cursor.execute("""
        SELECT *
        FROM usuario
        WHERE id_rol=%s
    """, (id,))

    usuarios = cursor.fetchone()

    if usuarios:

        conexion.close()

        return "No se puede eliminar el rol porque tiene usuarios asignados"

    cursor.execute("""
        DELETE FROM rol
        WHERE id_rol=%s
    """, (id,))

    conexion.commit()
    conexion.close()

    return "Rol eliminado correctamente"

# ==========================================
# ASIGNAR PERMISO
# ==========================================

@app.route('/asignar_permiso', methods=['GET', 'POST'])
def asignar_permiso():

    conexion = conectar()
    cursor = conexion.cursor()
    
    if not es_admin():
        return "Acceso denegado"

    if request.method == 'POST':

        id_rol = request.form['id_rol']
        id_permiso = request.form['id_permiso']


        cursor.execute("""
            SELECT *
            FROM rol_permiso
            WHERE id_rol=%s
            AND id_permiso=%s
        """, (id_rol, id_permiso))

        permiso_existente = cursor.fetchone()

        if permiso_existente:
            conexion.close()
            return "Este permiso ya está asignado al rol"

        cursor.execute("""
            INSERT INTO rol_permiso(id_rol, id_permiso)
            VALUES(%s,%s)
        """, (id_rol, id_permiso))

        conexion.commit()
        conexion.close()

        return "Permiso asignado correctamente"


    cursor.execute("""
        SELECT *
        FROM rol
    """)

    roles = cursor.fetchall()

    cursor.execute("""
        SELECT *
        FROM permiso
    """)

    permisos = cursor.fetchall()

    conexion.close()

    return render_template(
        'asignar_permiso.html',
        roles=roles,
        permisos=permisos
    )
   
# ==========================================
# REGISTRAR ENTIDADES
# ==========================================
   
@app.route('/registrar_entidad', methods=['GET', 'POST'])
def registrar_entidad():

    conexion = conectar()
    cursor = conexion.cursor()

    if request.method == 'POST':

        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        responsable = request.form['responsable']

        if not nombre or not descripcion or not responsable:
            conexion.close()
            return "Todos los campos son obligatorios"

        cursor.execute("""
            SELECT *
            FROM entidad
            WHERE nombre=%s
        """, (nombre,))

        entidad_existente = cursor.fetchone()

        if entidad_existente:
            conexion.close()
            return "La entidad ya existe"

        cursor.execute("""
            INSERT INTO entidad
            (nombre, descripcion, responsable)
            VALUES (%s,%s,%s)
        """, (
            nombre,
            descripcion,
            responsable
        ))

        conexion.commit()
        conexion.close()

        return "Entidad registrada correctamente"

    conexion.close()

    return render_template(
        'registrar_entidad.html'
    )
   
# ==========================================
# CONSULTAR ENTIDAD
# ==========================================
   
@app.route('/consultar_entidad')
def consultar_entidad():

    conexion = conectar()
    cursor = conexion.cursor()

    nombre = request.args.get('nombre', '')
    estado = request.args.get('estado', '')

    query = "SELECT * FROM entidad WHERE 1=1"

    params = []

    if nombre:
        query += " AND nombre LIKE %s"
        params.append(f"%{nombre}%")

    if estado:
        query += " AND estado=%s"
        params.append(estado)

    cursor.execute(query, params)
    entidades = cursor.fetchall()

    conexion.close()

    # TAR-93
    if not entidades:
        return "No existen entidades registradas"

    return render_template(
        'consultar_entidad.html',
        entidades=entidades
    )
# ==========================================
# EDITAR ENTIDAD
# ==========================================   
    
@app.route('/editar_entidad/<int:id>', methods=['GET', 'POST'])
def editar_entidad(id):

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT *
        FROM entidad
        WHERE id_entidad=%s
    """, (id,))

    entidad = cursor.fetchone()

    # TAR-97
    if not entidad:
        conexion.close()
        return "Entidad no encontrada"

    if request.method == 'POST':

        nombre = request.form['nombre']
        descripcion = request.form['descripcion']
        responsable = request.form['responsable']

        cursor.execute("""
            UPDATE entidad
            SET nombre=%s,
                descripcion=%s,
                responsable=%s
            WHERE id_entidad=%s
        """, (
            nombre,
            descripcion,
            responsable,
            id
        ))

        conexion.commit()
        conexion.close()

        return "Entidad actualizada correctamente"

    conexion.close()

    return render_template(
        'editar_entidad.html',
        entidad=entidad
    )
# ==========================================
# DESACTIVAR ENTIDAD
# ==========================================   
    
@app.route('/desactivar_entidad/<int:id>')
def desactivar_entidad(id):

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE entidad
        SET estado='Inactivo'
        WHERE id_entidad=%s
    """, (id,))

    conexion.commit()
    conexion.close()

    return "Entidad desactivada"

# ==========================================
# ACTIVAR ENTIDAD
# ==========================================

@app.route('/activar_entidad/<int:id>')
def activar_entidad(id):

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE entidad
        SET estado='Activo'
        WHERE id_entidad=%s
    """, (id,))

    conexion.commit()
    conexion.close()

    return "Entidad activada correctamente"

    
# ==========================================
# REGISTRAR PARAMETROS
# ==========================================
   
@app.route('/registrar_parametro', methods=['GET', 'POST'])
def registrar_parametro():

    conexion = conectar()
    cursor = conexion.cursor()

    if request.method == 'POST':

        nombre = request.form['nombre']
        valor = request.form['valor']
        descripcion = request.form['descripcion']
        
        if len(nombre) < 3:
            conexion.close()
            return "El nombre debe tener al menos 3 caracteres"
        
        if len(valor) < 1:
            conexion.close()
            return "Debe ingresar un valor válido"

        if not nombre or not valor or not descripcion:

            conexion.close()

            return "Todos los campos son obligatorios"

        # Validar duplicados

        cursor.execute("""
            SELECT *
            FROM parametro_institucional
            WHERE nombre=%s
        """, (nombre,))

        parametro_existente = cursor.fetchone()

        if parametro_existente:

            conexion.close()

            return "El parámetro ya existe"

        # Registrar parámetro

        cursor.execute("""
            INSERT INTO parametro_institucional
            (nombre, valor, descripcion)
            VALUES (%s,%s,%s)
        """, (
            nombre,
            valor,
            descripcion
        ))

        conexion.commit()
        conexion.close()

        return "Parámetro registrado correctamente"

    conexion.close()

    return render_template(
        'registrar_parametro.html'
    )
   
# ==========================================
# ACTIVAR ENTIDAD
# ==========================================   
   
@app.route('/activar_entidad/<int:id>')
def activar_entidad(id):

    conexion = conectar()
    cursor = conexion.cursor()

    cursor.execute("""
        UPDATE entidad
        SET estado='Activo'
        WHERE id_entidad=%s
    """, (id,))

    conexion.commit()
    conexion.close()

    return "Entidad activada"
   
# ==========================================
# EJECUTAR FLASK
# ==========================================

if __name__ == '__main__':
    app.run(debug=True)