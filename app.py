from flask import Flask, request, jsonify
import mysql.connector
import jwt
import datetime
import os

app = Flask(__name__)

# Función para obtener la conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('MYSQLHOST'),
        port=int(os.getenv('MYSQLPORT')),
        user=os.getenv('MYSQLUSER'),
        password=os.getenv('MYSQLPASSWORD'),
        database=os.getenv('MYSQLDATABASE')
    )

# Clave secreta para JWT
SECRET_KEY = 'mi_clave_secreta'

@app.route('/login', methods=['POST'])
def login():
    try:
        # Obtener los datos del cuerpo de la solicitud
        data = request.get_json()
        email = data['email']
        password = data['password']
    except KeyError as e:
        # Si falta algún parámetro en la solicitud
        return jsonify({'message': f'Missing parameter: {str(e)}'}), 400

    # Intentar la conexión con la base de datos
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, email, role FROM users WHERE email = %s AND password = %s", (email, password))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
    except mysql.connector.Error as e:
        # Error específico de la base de datos
        return jsonify({'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        # Capturar cualquier otro error inesperado
        return jsonify({'message': f'Unexpected error: {str(e)}'}), 500

    # Si el usuario es encontrado, generar el token
    if user:
        token = jwt.encode({
            'user_id': user['id'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token})
    else:
        # Si las credenciales son incorrectas
        return jsonify({'message': 'Credenciales inválidas'}), 401

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

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT id, email, role FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
    except mysql.connector.Error as e:
        return jsonify({'message': f'Database error: {str(e)}'}), 500
    except Exception as e:
        return jsonify({'message': f'Unexpected error: {str(e)}'}), 500

    if user:
        return jsonify(user)
    else:
        return jsonify({'message': 'Usuario no encontrado'}), 404

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
