import os
import time
import logging
import mysql.connector
import jwt
import datetime
from flask import Flask, request, jsonify
from functools import wraps
from datetime import datetime, timedelta




# Configurar la aplicación Flask
app = Flask(__name__)
app.config['DEBUG'] = True if os.getenv('FLASK_ENV') == 'development' else False

# Configurar logging
logging.basicConfig(level=logging.DEBUG)

# Configuración de la base de datos
db_config = {
    'host': os.getenv('DB_HOST', '35.212.82.162'),
    'port': int(os.getenv('DB_PORT', 13541)),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD', 'YJZUxEKsXZSxiPFlJGverCkCFQuPpHWh'),
    'database': os.getenv('DB_NAME', 'railway'),
    'charset': 'utf8mb4',
    'collation': 'utf8mb4_unicode_ci',
    'auth_plugin': 'mysql_native_password',
    'ssl_disabled': True,
    'pool_name': 'mypool',
    'pool_size': 5,
    'pool_reset_session': True,
    'buffered': True,
    'consume_results': True
}

SECRET_KEY = os.getenv('SECRET_KEY', 'mi_clave_secreta_por_defecto')

def execute_query(query, params=None, fetch_one=False, fetch_all=False, commit=False):
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        cursor.execute(query, params or ())
        
        if commit:
            conn.commit()
            return cursor.lastrowid if "INSERT" in query.upper() else cursor.rowcount
        
        results = None
        if fetch_one:
            results = cursor.fetchone()
        elif fetch_all:
            results = cursor.fetchall()
        
        # Convertir objetos de fecha/hora a strings
        if results:
            if isinstance(results, dict):  # Para fetchone
                results = convert_datetime_fields(results)
            elif isinstance(results, list):  # Para fetchall
                results = [convert_datetime_fields(row) for row in results]
        
        return results
        
    except mysql.connector.Error as err:
        app.logger.error(f"Error de base de datos: {err}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn and conn.is_connected():
            conn.close()

def convert_datetime_fields(row):
    """Convierte campos datetime, date y timedelta a strings"""
    converted = {}
    for key, value in row.items():
        if value is None:
            converted[key] = None
        elif isinstance(value, (datetime.datetime, datetime.date)):
            converted[key] = value.isoformat()
        elif isinstance(value, datetime.timedelta):
            # Convierte timedelta a segundos o string
            converted[key] = str(value)
        else:
            converted[key] = value
    return converted

# Decorador para verificar el token JWT y el rol
def token_required(roles=None):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                app.logger.warning('Token ausente o inválido')
                return jsonify({'message': 'Token ausente o inválido'}), 401

            token = auth_header.split(' ')[1]
            try:
                decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                current_user_id = decoded['user_id']
                
                # Verificar rol si se especificó
                if roles:
                    conn = get_db_connection()
                    cursor = conn.cursor(dictionary=True)
                    cursor.execute("SELECT role FROM users WHERE id = %s", (current_user_id,))
                    user = cursor.fetchone()
                    cursor.close()
                    conn.close()
                    
                    if not user or user['role'] not in roles:
                        return jsonify({'message': 'Acceso no autorizado'}), 403
                
                return f(current_user_id, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({'message': 'Token expirado'}), 401
            except jwt.InvalidTokenError:
                return jsonify({'message': 'Token inválido'}), 401
            except Exception as e:
                app.logger.error(f'Error verificando token: {str(e)}')
                return jsonify({'message': 'Error verificando token'}), 500
        return decorated
    return decorator

# Función para obtener la conexión a la base de datos
def get_db_connection():
    max_retries = 3
    attempt = 0
    
    while attempt < max_retries:
        try:
            conn = mysql.connector.connect(**db_config)
            # Verificación activa con limpieza de resultados
            cursor = conn.cursor(buffered=True)
            cursor.execute("SELECT 1")
            cursor.fetchall()  # Asegúrate de leer todos los resultados
            cursor.close()
            conn.close()  # Cierra la conexión de verificación
            
            # Crea una nueva conexión limpia para usar
            clean_conn = mysql.connector.connect(**db_config)
            return clean_conn
        except mysql.connector.Error as err:
            attempt += 1
            app.logger.error(f"Intento {attempt} fallido: {err}")
            # Limpia cualquier conexión residual
            try:
                if 'conn' in locals():
                    conn.close()
            except:
                pass
            if attempt == max_retries:
                raise RuntimeError(f"No se pudo conectar a la base de datos después de {max_retries} intentos")
            time.sleep(2)

@app.route('/')
def health_check():
    try:
        conn = get_db_connection()
        conn.close()
        return jsonify({'status': 'healthy', 'database': 'connected'}), 200
    except Exception as e:
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

# Ruta para el login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            raise ValueError("No JSON data received")
        email = data['email']
        password = data['password']
    except KeyError as e:
        app.logger.error(f'Falta el parámetro: {str(e)}')
        return jsonify({'message': f'Falta el parámetro: {str(e)}'}), 400
    except ValueError as e:
        app.logger.error(f'Entrada inválida: {str(e)}')
        return jsonify({'message': f'Entrada inválida: {str(e)}'}), 400
    except Exception as e:
        app.logger.error(f'Error inesperado procesando datos: {str(e)}')
        return jsonify({'message': f'Error inesperado: {str(e)}'}), 500

    try:
        # Establecer la conexión a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True, buffered=True)
        cursor.execute("SELECT id, email, role, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        # Verificar si se encontró al usuario y si la contraseña es correcta (sin hash)
        if user and user['password'] == password:
            token = jwt.encode({
                'user_id': user['id'],
                'exp': datetime.utcnow() + timedelta(hours=1)
            }, SECRET_KEY, algorithm='HS256')
            app.logger.debug(f'Token generado: {token}')
            return jsonify({'token': token, 'role': user['role']})
        else:
            app.logger.warning(f"Credenciales inválidas para email: {email}")
            return jsonify({'message': 'Credenciales inválidas'}), 401
    except mysql.connector.Error as err:
        app.logger.error(f"Error de base de datos durante el login: {err}")
        return jsonify({'message': f'Error de base de datos: {err}'}), 500
    except jwt.PyJWTError as err:
        app.logger.error(f"Error al generar token JWT: {err}")
        return jsonify({'message': 'Error generando token JWT'}), 500
    except Exception as e:
        app.logger.error(f'Error inesperado: {str(e)}')
        return jsonify({'message': f'Error inesperado: {str(e)}'}), 500

# Ruta para obtener el perfil del usuario
@app.route('/user/profile', methods=['GET'])
@token_required()
def user_profile(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, role FROM users WHERE id = %s", (current_user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if user:
            return jsonify(user)
        else:
            return jsonify({'message': 'Usuario no encontrado'}), 404
    except mysql.connector.Error as err:
        app.logger.error(f"Error de base de datos al recuperar perfil: {err}")
        return jsonify({'message': f'Error de base de datos: {err}'}), 500
    except Exception as e:
        app.logger.error(f'Error inesperado recuperando perfil: {str(e)}')
        return jsonify({'message': f'Error inesperado: {str(e)}'}), 500

# ==============================================
# CRUD para Maestros
# ==============================================

@app.route('/maestros', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_maestros(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM maestros")
        maestros = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(maestros)
    except Exception as e:
        app.logger.error(f'Error obteniendo maestros: {str(e)}')
        return jsonify({'message': 'Error obteniendo maestros'}), 500

@app.route('/maestros/<int:id>', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_maestro(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM maestros WHERE id_maestro = %s", (id,))
        maestro = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if maestro:
            return jsonify(maestro)
        else:
            return jsonify({'message': 'Maestro no encontrado'}), 404
    except Exception as e:
        app.logger.error(f'Error obteniendo maestro: {str(e)}')
        return jsonify({'message': 'Error obteniendo maestro'}), 500

@app.route('/maestros', methods=['POST'])
@token_required(['administrador'])
def create_maestro(current_user_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO maestros (nombre, apellido) VALUES (%s, %s)",
            (data['nombre'], data['apellido'])
        )
        conn.commit()
        maestro_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Maestro creado', 'id': maestro_id}), 201
    except Exception as e:
        app.logger.error(f'Error creando maestro: {str(e)}')
        return jsonify({'message': 'Error creando maestro'}), 500

@app.route('/maestros/<int:id>', methods=['PUT'])
@token_required(['administrador'])
def update_maestro(current_user_id, id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE maestros SET nombre = %s, apellido = %s WHERE id_maestro = %s",
            (data['nombre'], data['apellido'], id)
        )
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Maestro no encontrado'}), 404
        return jsonify({'message': 'Maestro actualizado'})
    except Exception as e:
        app.logger.error(f'Error actualizando maestro: {str(e)}')
        return jsonify({'message': 'Error actualizando maestro'}), 500

@app.route('/maestros/<int:id>', methods=['DELETE'])
@token_required(['administrador'])
def delete_maestro(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM maestros WHERE id_maestro = %s", (id,))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Maestro no encontrado'}), 404
        return jsonify({'message': 'Maestro eliminado'})
    except Exception as e:
        app.logger.error(f'Error eliminando maestro: {str(e)}')
        return jsonify({'message': 'Error eliminando maestro'}), 500

# ==============================================
# CRUD para Asignaturas
# ==============================================

@app.route('/asignaturas', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_asignaturas(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM asignaturas")
        asignaturas = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(asignaturas)
    except Exception as e:
        app.logger.error(f'Error obteniendo asignaturas: {str(e)}')
        return jsonify({'message': 'Error obteniendo asignaturas'}), 500

@app.route('/asignaturas/<int:id>', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_asignatura(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM asignaturas WHERE id_asignatura = %s", (id,))
        asignatura = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if asignatura:
            return jsonify(asignatura)
        else:
            return jsonify({'message': 'Asignatura no encontrada'}), 404
    except Exception as e:
        app.logger.error(f'Error obteniendo asignatura: {str(e)}')
        return jsonify({'message': 'Error obteniendo asignatura'}), 500

@app.route('/asignaturas', methods=['POST'])
@token_required(['administrador'])
def create_asignatura(current_user_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO asignaturas 
            (nombre_asignatura, clave_asignatura, horas_teoricas) 
            VALUES (%s, %s, %s)""",
            (data['nombre_asignatura'], data['clave_asignatura'], data['horas_teoricas'])
        )
        conn.commit()
        asignatura_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Asignatura creada', 'id': asignatura_id}), 201
    except Exception as e:
        app.logger.error(f'Error creando asignatura: {str(e)}')
        return jsonify({'message': 'Error creando asignatura'}), 500

@app.route('/asignaturas/<int:id>', methods=['PUT'])
@token_required(['administrador'])
def update_asignatura(current_user_id, id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """UPDATE asignaturas SET 
            nombre_asignatura = %s, 
            clave_asignatura = %s, 
            horas_teoricas = %s 
            WHERE id_asignatura = %s""",
            (data['nombre_asignatura'], data['clave_asignatura'], data['horas_teoricas'], id)
        )
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Asignatura no encontrada'}), 404
        return jsonify({'message': 'Asignatura actualizada'})
    except Exception as e:
        app.logger.error(f'Error actualizando asignatura: {str(e)}')
        return jsonify({'message': 'Error actualizando asignatura'}), 500

@app.route('/asignaturas/<int:id>', methods=['DELETE'])
@token_required(['administrador'])
def delete_asignatura(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM asignaturas WHERE id_asignatura = %s", (id,))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Asignatura no encontrada'}), 404
        return jsonify({'message': 'Asignatura eliminada'})
    except Exception as e:
        app.logger.error(f'Error eliminando asignatura: {str(e)}')
        return jsonify({'message': 'Error eliminando asignatura'}), 500

# ==============================================
# CRUD para Aulas
# ==============================================

@app.route('/aulas', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_aulas(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM aulas")
        aulas = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(aulas)
    except Exception as e:
        app.logger.error(f'Error obteniendo aulas: {str(e)}')
        return jsonify({'message': 'Error obteniendo aulas'}), 500

@app.route('/aulas/<int:id>', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_aula(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM aulas WHERE id_aula = %s", (id,))
        aula = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if aula:
            return jsonify(aula)
        else:
            return jsonify({'message': 'Aula no encontrada'}), 404
    except Exception as e:
        app.logger.error(f'Error obteniendo aula: {str(e)}')
        return jsonify({'message': 'Error obteniendo aula'}), 500

@app.route('/aulas', methods=['POST'])
@token_required(['administrador'])
def create_aula(current_user_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO aulas (aula) VALUES (%s)",
            (data['aula'],)
        )
        conn.commit()
        aula_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Aula creada', 'id': aula_id}), 201
    except Exception as e:
        app.logger.error(f'Error creando aula: {str(e)}')
        return jsonify({'message': 'Error creando aula'}), 500

@app.route('/aulas/<int:id>', methods=['PUT'])
@token_required(['administrador'])
def update_aula(current_user_id, id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE aulas SET aula = %s WHERE id_aula = %s",
            (data['aula'], id)
        )
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Aula no encontrada'}), 404
        return jsonify({'message': 'Aula actualizada'})
    except Exception as e:
        app.logger.error(f'Error actualizando aula: {str(e)}')
        return jsonify({'message': 'Error actualizando aula'}), 500

@app.route('/aulas/<int:id>', methods=['DELETE'])
@token_required(['administrador'])
def delete_aula(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM aulas WHERE id_aula = %s", (id,))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Aula no encontrada'}), 404
        return jsonify({'message': 'Aula eliminada'})
    except Exception as e:
        app.logger.error(f'Error eliminando aula: {str(e)}')
        return jsonify({'message': 'Error eliminando aula'}), 500

# ==============================================
# CRUD para Carreras
# ==============================================

@app.route('/carreras', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_carreras(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM carreras")
        carreras = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(carreras)
    except Exception as e:
        app.logger.error(f'Error obteniendo carreras: {str(e)}')
        return jsonify({'message': 'Error obteniendo carreras'}), 500

@app.route('/carreras/<int:id>', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_carrera(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM carreras WHERE id_carrera = %s", (id,))
        carrera = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if carrera:
            return jsonify(carrera)
        else:
            return jsonify({'message': 'Carrera no encontrada'}), 404
    except Exception as e:
        app.logger.error(f'Error obteniendo carrera: {str(e)}')
        return jsonify({'message': 'Error obteniendo carrera'}), 500

@app.route('/carreras', methods=['POST'])
@token_required(['administrador'])
def create_carrera(current_user_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO carreras (carrera) VALUES (%s)",
            (data['carrera'],)
        )
        conn.commit()
        carrera_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Carrera creada', 'id': carrera_id}), 201
    except Exception as e:
        app.logger.error(f'Error creando carrera: {str(e)}')
        return jsonify({'message': 'Error creando carrera'}), 500

@app.route('/carreras/<int:id>', methods=['PUT'])
@token_required(['administrador'])
def update_carrera(current_user_id, id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE carreras SET carrera = %s WHERE id_carrera = %s",
            (data['carrera'], id)
        )
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Carrera no encontrada'}), 404
        return jsonify({'message': 'Carrera actualizada'})
    except Exception as e:
        app.logger.error(f'Error actualizando carrera: {str(e)}')
        return jsonify({'message': 'Error actualizando carrera'}), 500

@app.route('/carreras/<int:id>', methods=['DELETE'])
@token_required(['administrador'])
def delete_carrera(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM carreras WHERE id_carrera = %s", (id,))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Carrera no encontrada'}), 404
        return jsonify({'message': 'Carrera eliminada'})
    except Exception as e:
        app.logger.error(f'Error eliminando carrera: {str(e)}')
        return jsonify({'message': 'Error eliminando carrera'}), 500

# ==============================================
# CRUD para Grupos
# ==============================================

@app.route('/grupos', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_grupos(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM grupos")
        grupos = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(grupos)
    except Exception as e:
        app.logger.error(f'Error obteniendo grupos: {str(e)}')
        return jsonify({'message': 'Error obteniendo grupos'}), 500

@app.route('/grupos/<int:id>', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_grupo(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM grupos WHERE id_grupo = %s", (id,))
        grupo = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if grupo:
            return jsonify(grupo)
        else:
            return jsonify({'message': 'Grupo no encontrado'}), 404
    except Exception as e:
        app.logger.error(f'Error obteniendo grupo: {str(e)}')
        return jsonify({'message': 'Error obteniendo grupo'}), 500

@app.route('/grupos', methods=['POST'])
@token_required(['administrador'])
def create_grupo(current_user_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO grupos (grupo) VALUES (%s)",
            (data['grupo'],)
        )
        conn.commit()
        grupo_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Grupo creado', 'id': grupo_id}), 201
    except Exception as e:
        app.logger.error(f'Error creando grupo: {str(e)}')
        return jsonify({'message': 'Error creando grupo'}), 500

@app.route('/grupos/<int:id>', methods=['PUT'])
@token_required(['administrador'])
def update_grupo(current_user_id, id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE grupos SET grupo = %s WHERE id_grupo = %s",
            (data['grupo'], id)
        )
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Grupo no encontrado'}), 404
        return jsonify({'message': 'Grupo actualizado'})
    except Exception as e:
        app.logger.error(f'Error actualizando grupo: {str(e)}')
        return jsonify({'message': 'Error actualizando grupo'}), 500

@app.route('/grupos/<int:id>', methods=['DELETE'])
@token_required(['administrador'])
def delete_grupo(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM grupos WHERE id_grupo = %s", (id,))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Grupo no encontrado'}), 404
        return jsonify({'message': 'Grupo eliminado'})
    except Exception as e:
        app.logger.error(f'Error eliminando grupo: {str(e)}')
        return jsonify({'message': 'Error eliminando grupo'}), 500

# ==============================================
# CRUD para Horarios
# ==============================================

@app.route('/horarios', methods=['POST'])
@token_required(['administrador'])
def create_horario(current_user_id):
    """Endpoint único para crear horarios"""
    try:
        data = request.get_json()
        
        # Validación de campos requeridos
        required_fields = {
            'id_maestro': 'maestros',
            'id_asignatura': 'asignaturas',
            'id_carrera': 'carreras', 
            'id_grupo': 'grupos',
            'id_aula': 'aulas',
            'dia': None,
            'hora_inicio': None,
            'hora_fin': None
        }
        
        # Verificar campos faltantes
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({
                'message': 'Faltan campos requeridos',
                'missing': missing_fields
            }), 400
        
        # Validar referencias
        ref_errors = []
        for field, table in required_fields.items():
            if table and not referencia_existe(table, data[field]):
                ref_errors.append(f'Referencia no encontrada: {field}')
        
        if ref_errors:
            return jsonify({
                'message': 'Errores en referencias',
                'errors': ref_errors
            }), 400
        
        # Validar formato de horas
        try:
            hora_inicio = datetime.strptime(data['hora_inicio'], '%H:%M').time()
            hora_fin = datetime.strptime(data['hora_fin'], '%H:%M').time()
            if hora_inicio >= hora_fin:
                return jsonify({
                    'message': 'La hora de fin debe ser posterior a la hora de inicio'
                }), 400
        except ValueError:
            return jsonify({
                'message': 'Formato de hora inválido (use HH:MM)'
            }), 400
        # Insertar el horario
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO horarios 
            (id_maestro, id_asignatura, id_carrera, id_grupo, id_aula, dia, hora_inicio, hora_fin) 
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)""",
            (
                data['id_maestro'], data['id_asignatura'], data['id_carrera'],
                data['id_grupo'], data['id_aula'], data['dia'],
                data['hora_inicio'], data['hora_fin']
            )
        )
        conn.commit()
        horario_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Horario creado exitosamente',
            'id': horario_id
        }), 201
        
    except mysql.connector.Error as err:
        app.logger.error(f'Error de base de datos: {str(err)}')
        return jsonify({
            'message': 'Error de base de datos',
            'details': str(err)
        }), 500
    except Exception as e:
        app.logger.error(f'Error inesperado: {str(e)}')
        return jsonify({
            'message': 'Error interno del servidor',
            'details': str(e)
        }), 500

# ... [mantén las otras funciones GET, PUT, DELETE como están] ...
        
@app.route('/horarios/<int:id>', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_horario(current_user_id, id):
    try:
        query = """
        SELECT h.*, 
               m.nombre as maestro_nombre, m.apellido as maestro_apellido,
               a.nombre_asignatura, a.clave_asignatura,
               c.carrera,
               g.grupo,
               au.aula
        FROM horarios h
        JOIN maestros m ON h.id_maestro = m.id_maestro
        JOIN asignaturas a ON h.id_asignatura = a.id_asignatura
        JOIN carreras c ON h.id_carrera = c.id_carrera
        JOIN grupos g ON h.id_grupo = g.id_grupo
        JOIN aulas au ON h.id_aula = au.id_aula
        WHERE h.id_horario = %s
        """
        horario = execute_query(query, (id,), fetch_one=True)
        
        if not horario:
            return jsonify({'message': 'Horario no encontrado'}), 404
        return jsonify(horario)
    except mysql.connector.Error as err:
        app.logger.error(f'Error de base de datos obteniendo horario: {str(err)}', exc_info=True)
        return jsonify({'message': 'Error obteniendo horario'}), 500
    except Exception as e:
        app.logger.error(f'Error inesperado obteniendo horario: {str(e)}', exc_info=True)
        return jsonify({'message': 'Error interno del servidor'}), 500

@app.route('/horarios/<int:id>', methods=['PUT'])
@token_required(['administrador'])
def update_horario(current_user_id, id):
    try:
        data = request.get_json()
        
        # Validación de campos requeridos
        required_fields = [
            'id_maestro', 'id_asignatura', 'id_carrera', 
            'id_grupo', 'id_aula', 'dia', 
            'hora_inicio', 'hora_fin'
        ]
        
        if not all(field in data for field in required_fields):
            return jsonify({'message': 'Faltan campos requeridos'}), 400
        
        # Verificar que el horario existe
        if not execute_query("SELECT 1 FROM horarios WHERE id_horario = %s", (id,), fetch_one=True):
            return jsonify({'message': 'Horario no encontrado'}), 404
        
        # Validar que las referencias existan
        if not all(referencia_existe(field, data[field]) for field in [
            ('maestros', 'id_maestro'),
            ('asignaturas', 'id_asignatura'),
            ('carreras', 'id_carrera'),
            ('grupos', 'id_grupo'),
            ('aulas', 'id_aula')
        ]):
            return jsonify({'message': 'Una o más referencias no existen'}), 400
        
        # Actualizar el horario
        affected_rows = execute_query(
            """UPDATE horarios SET 
            id_maestro = %s, 
            id_asignatura = %s, 
            id_carrera = %s, 
            id_grupo = %s, 
            id_aula = %s, 
            dia = %s, 
            hora_inicio = %s, 
            hora_fin = %s 
            WHERE id_horario = %s""",
            (
                data['id_maestro'], data['id_asignatura'], data['id_carrera'],
                data['id_grupo'], data['id_aula'], data['dia'],
                data['hora_inicio'], data['hora_fin'], id
            ),
            commit=True
        )
        
        if affected_rows == 0:
            return jsonify({'message': 'No se realizaron cambios en el horario'}), 200
        
        return jsonify({'message': 'Horario actualizado exitosamente'})
        
    except mysql.connector.Error as err:
        app.logger.error(f'Error de base de datos actualizando horario: {str(err)}', exc_info=True)
        return jsonify({'message': 'Error actualizando horario'}), 500
    except Exception as e:
        app.logger.error(f'Error inesperado actualizando horario: {str(e)}', exc_info=True)
        return jsonify({'message': 'Error interno del servidor'}), 500

@app.route('/horarios/<int:id>', methods=['DELETE'])
@token_required(['administrador'])
def delete_horario(current_user_id, id):
    try:
        # Verificar que el horario existe
        if not execute_query("SELECT 1 FROM horarios WHERE id_horario = %s", (id,), fetch_one=True):
            return jsonify({'message': 'Horario no encontrado'}), 404
        
        # Eliminar el horario
        affected_rows = execute_query(
            "DELETE FROM horarios WHERE id_horario = %s",
            (id,),
            commit=True
        )
        
        if affected_rows == 0:
            return jsonify({'message': 'No se eliminó el horario'}), 200
        
        return jsonify({'message': 'Horario eliminado exitosamente'})
        
    except mysql.connector.Error as err:
        if err.errno == 1451:  # Error de clave foránea
            return jsonify({
                'message': 'No se puede eliminar el horario porque tiene registros relacionados'
            }), 400
        app.logger.error(f'Error de base de datos eliminando horario: {str(err)}', exc_info=True)
        return jsonify({'message': 'Error eliminando horario'}), 500
    except Exception as e:
        app.logger.error(f'Error inesperado eliminando horario: {str(e)}', exc_info=True)
        return jsonify({'message': 'Error interno del servidor'}), 500

# Función auxiliar para verificar referencias

def referencia_existe(tabla, id_referencia):
    try:
        app.logger.debug(f"Verificando referencia: {tabla}, ID: {id_referencia}")  # Debug
        resultado = execute_query(
            f"SELECT 1 FROM {tabla} WHERE id_{tabla[:-1]} = %s",
            (id_referencia,),
            fetch_one=True
        )
        if resultado:
            app.logger.debug(f"Referencia encontrada: {tabla}, ID: {id_referencia}")  # Debug
        return resultado is not None
    except Exception as e:
        app.logger.error(f"Error al verificar referencia {tabla}: {str(e)}")
        return False


# ==============================================
# CRUD para Registro de Asistencias
# ==============================================

@app.route('/asistencias', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_asistencias(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
        SELECT ra.*, 
               h.dia, h.hora_inicio, h.hora_fin,
               m.nombre as maestro_nombre, m.apellido as maestro_apellido,
               a.nombre_asignatura,
               c.carrera,
               g.grupo,
               au.aula,
               te.estado
        FROM registro_asistencias ra
        JOIN horarios h ON ra.id_horario = h.id_horario
        JOIN maestros m ON h.id_maestro = m.id_maestro
        JOIN asignaturas a ON h.id_asignatura = a.id_asignatura
        JOIN carreras c ON h.id_carrera = c.id_carrera
        JOIN grupos g ON h.id_grupo = g.id_grupo
        JOIN aulas au ON h.id_aula = au.id_aula
        JOIN tipo_estados te ON ra.id_estado = te.id_estado
        """
        cursor.execute(query)
        asistencias = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(asistencias)
    except Exception as e:
        app.logger.error(f'Error obteniendo asistencias: {str(e)}')
        return jsonify({'message': 'Error obteniendo asistencias'}), 500

@app.route('/asistencias/<int:id>', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_asistencia(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        
        query = """
        SELECT ra.*, 
               h.dia, h.hora_inicio, h.hora_fin,
               m.nombre as maestro_nombre, m.apellido as maestro_apellido,
               a.nombre_asignatura,
               c.carrera,
               g.grupo,
               au.aula,
               te.estado
        FROM registro_asistencias ra
        JOIN horarios h ON ra.id_horario = h.id_horario
        JOIN maestros m ON h.id_maestro = m.id_maestro
        JOIN asignaturas a ON h.id_asignatura = a.id_asignatura
        JOIN carreras c ON h.id_carrera = c.id_carrera
        JOIN grupos g ON h.id_grupo = g.id_grupo
        JOIN aulas au ON h.id_aula = au.id_aula
        JOIN tipo_estados te ON ra.id_estado = te.id_estado
        WHERE ra.id_asistencia = %s
        """
        cursor.execute(query, (id,))
        asistencia = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if asistencia:
            return jsonify(asistencia)
        else:
            return jsonify({'message': 'Asistencia no encontrada'}), 404
    except Exception as e:
        app.logger.error(f'Error obteniendo asistencia: {str(e)}')
        return jsonify({'message': 'Error obteniendo asistencia'}), 500

@app.route('/asistencias', methods=['POST'])
@token_required(['prefecto'])
def create_asistencia(current_user_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """INSERT INTO registro_asistencias 
            (id_horario, id_estado, fecha_asistencia, hora_asistencia) 
            VALUES (%s, %s, %s, %s)""",
            (data['id_horario'], data['id_estado'], 
             data['fecha_asistencia'], data['hora_asistencia'])
        )
        conn.commit()
        asistencia_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Asistencia registrada', 'id': asistencia_id}), 201
    except Exception as e:
        app.logger.error(f'Error registrando asistencia: {str(e)}')
        return jsonify({'message': 'Error registrando asistencia'}), 500

@app.route('/asistencias/<int:id>', methods=['PUT'])
@token_required(['prefecto'])
def update_asistencia(current_user_id, id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            """UPDATE registro_asistencias SET 
            id_horario = %s, 
            id_estado = %s, 
            fecha_asistencia = %s, 
            hora_asistencia = %s 
            WHERE id_asistencia = %s""",
            (data['id_horario'], data['id_estado'], 
             data['fecha_asistencia'], data['hora_asistencia'], id)
        )
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Asistencia no encontrada'}), 404
        return jsonify({'message': 'Asistencia actualizada'})
    except Exception as e:
        app.logger.error(f'Error actualizando asistencia: {str(e)}')
        return jsonify({'message': 'Error actualizando asistencia'}), 500

@app.route('/asistencias/<int:id>', methods=['DELETE'])
@token_required(['prefecto'])
def delete_asistencia(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM registro_asistencias WHERE id_asistencia = %s", (id,))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Asistencia no encontrada'}), 404
        return jsonify({'message': 'Asistencia eliminada'})
    except Exception as e:
        app.logger.error(f'Error eliminando asistencia: {str(e)}')
        return jsonify({'message': 'Error eliminando asistencia'}), 500

# ==============================================
# CRUD para Estados
# ==============================================

@app.route('/estados', methods=['GET'])
@token_required(['administrador', 'prefecto'])
def get_estados(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM tipo_estados")
        estados = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(estados)
    except Exception as e:
        app.logger.error(f'Error obteniendo estados: {str(e)}')
        return jsonify({'message': 'Error obteniendo estados'}), 500

# ==============================================
# CRUD para Usuarios (solo administrador)
# ==============================================

@app.route('/usuarios', methods=['GET'])
@token_required(['administrador'])
def get_usuarios(current_user_id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, role FROM users")
        usuarios = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify(usuarios)
    except Exception as e:
        app.logger.error(f'Error obteniendo usuarios: {str(e)}')
        return jsonify({'message': 'Error obteniendo usuarios'}), 500

@app.route('/usuarios/<int:id>', methods=['GET'])
@token_required(['administrador'])
def get_usuario(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, name, email, role FROM users WHERE id = %s", (id,))
        usuario = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if usuario:
            return jsonify(usuario)
        else:
            return jsonify({'message': 'Usuario no encontrado'}), 404
    except Exception as e:
        app.logger.error(f'Error obteniendo usuario: {str(e)}')
        return jsonify({'message': 'Error obteniendo usuario'}), 500

@app.route('/usuarios', methods=['POST'])
@token_required(['administrador'])
def create_usuario(current_user_id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)",
            (data['name'], data['email'], data['password'], data['role'])
        )
        conn.commit()
        usuario_id = cursor.lastrowid
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Usuario creado', 'id': usuario_id}), 201
    except Exception as e:
        app.logger.error(f'Error creando usuario: {str(e)}')
        return jsonify({'message': 'Error creando usuario'}), 500

@app.route('/usuarios/<int:id>', methods=['PUT'])
@token_required(['administrador'])
def update_usuario(current_user_id, id):
    try:
        data = request.get_json()
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute(
            "UPDATE users SET name = %s, email = %s, role = %s WHERE id = %s",
            (data['name'], data['email'], data['role'], id)
        )
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        return jsonify({'message': 'Usuario actualizado'})
    except Exception as e:
        app.logger.error(f'Error actualizando usuario: {str(e)}')
        return jsonify({'message': 'Error actualizando usuario'}), 500

@app.route('/usuarios/<int:id>', methods=['DELETE'])
@token_required(['administrador'])
def delete_usuario(current_user_id, id):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM users WHERE id = %s", (id,))
        conn.commit()
        affected_rows = cursor.rowcount
        cursor.close()
        conn.close()
        
        if affected_rows == 0:
            return jsonify({'message': 'Usuario no encontrado'}), 404
        return jsonify({'message': 'Usuario eliminado'})
    except Exception as e:
        app.logger.error(f'Error eliminando usuario: {str(e)}')
        return jsonify({'message': 'Error eliminando usuario'}), 500

# Iniciar la aplicación
if __name__ == '__main__':
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=int(os.getenv('PORT', 5000)))
