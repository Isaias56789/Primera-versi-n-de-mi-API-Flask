import os  # <-- Este es el que falta
import time  # <-- También necesario para los reintentos
import logging
import mysql.connector
import jwt
import datetime
from flask import Flask, request, jsonify
# Configurar la aplicación Flask
app = Flask(__name__)
app.config['DEBUG'] = True

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
    'buffered': True,  # <-- Añade esto
    'consume_results': True  # <-- Añade esto
}

SECRET_KEY = 'mi_clave_secreta'

# Función para obtener la conexión a la base de datos
def get_db_connection():
    max_retries = 3
    attempt = 0
    
    while attempt < max_retries:
        try:
            conn = mysql.connector.connect(**db_config)
            # Verificación activa con limpieza de resultados
            cursor = conn.cursor(buffered=True)  # <-- Añade buffered=True
            cursor.execute("SELECT 1")
            cursor.fetchall()  # <-- Asegúrate de leer todos los resultados
            cursor.close()
            conn.close()  # <-- Cierra la conexión de verificación
            
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
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, email, role, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        # Verificar si se encontró al usuario y si la contraseña es correcta (sin hash)
        if user and user['password'] == password:
            token = jwt.encode({
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, SECRET_KEY, algorithm='HS256')
            app.logger.debug(f'Token generado: {token}')
            return jsonify({'token': token})
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
def user_profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        app.logger.warning('Token ausente o inválido')
        return jsonify({'message': 'Token ausente o inválido'}), 401

    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = decoded['user_id']
    except jwt.ExpiredSignatureError:
        app.logger.warning('Token JWT expirado')
        return jsonify({'message': 'Token expirado'}), 401
    except jwt.InvalidTokenError as e:
        app.logger.error(f'Token JWT inválido: {str(e)}')
        return jsonify({'message': 'Token inválido'}), 401
    except Exception as e:
        app.logger.error(f'Error inesperado decodificando token: {str(e)}')
        return jsonify({'message': 'Error decodificando token'}), 500

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, email, role FROM users WHERE id = %s", (user_id,))
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

# Iniciar la aplicación
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
