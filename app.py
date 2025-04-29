import logging
import mysql.connector
import jwt
import datetime
from flask import Flask, request, jsonify
from werkzeug.security import check_password_hash

# Configurar la aplicación Flask
app = Flask(__name__)

# Configurar logging
logging.basicConfig(level=logging.DEBUG)

# Configuración de la base de datos
db_config = {
    'host': '35.212.82.162',
    'port': 13541,
    'user': 'root',
    'password': 'YJZUxEKsXZSxiPFlJGverCkCFQuPpHWh',
    'database': 'railway'
    charset="utf8mb4" 
}

SECRET_KEY = 'mi_clave_secreta'

# Función para obtener la conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**db_config)

# Ruta para el login
@app.route('/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        email = data['email']
        password = data['password']
    except KeyError as e:
        app.logger.error(f'Missing parameter: {str(e)}')
        return jsonify({'message': f'Missing parameter: {str(e)}'}), 400

    try:
        # Establecer la conexión a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, email, role, password FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()

        # Verificar si se encontró al usuario y si la contraseña es correcta
        if user and check_password_hash(user['password'], password):
            token = jwt.encode({
                'user_id': user['id'],
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            }, SECRET_KEY, algorithm='HS256')
            return jsonify({'token': token})
        else:
            return jsonify({'message': 'Credenciales inválidas'}), 401
    except mysql.connector.Error as err:
        app.logger.error(f"Database error: {err}")
        return jsonify({'message': f'Database error: {err}'}), 500
    except Exception as e:
        app.logger.error(f'Unexpected error: {str(e)}')
        return jsonify({'message': f'Unexpected error: {str(e)}'}), 500

# Ruta para obtener el perfil del usuario
@app.route('/user/profile', methods=['GET'])
def user_profile():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'message': 'Missing or invalid token'}), 401

    token = auth_header.split(' ')[1]
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        user_id = decoded['user_id']
    except jwt.ExpiredSignatureError:
        return jsonify({'message': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'message': 'Token inválido'}), 401

    # Obtener los datos del usuario
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

# Iniciar la aplicación
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
