from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_cors import CORS
from flask_jwt_extended import JWTExtended, jwt_required, create_access_token, get_jwt_identity
import os

app = Flask(__name__)
CORS(app)
basedir = os.path.abspath(os.path.dirname(__file__))

# Configuración de la base de datos
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://usuario:contraseña@localhost/Perfectura'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret-key'  # Cambia esto en producción

db = SQLAlchemy(app)
ma = Marshmallow(app)
jwt = JWTExtended(app)

# Modelos
class Maestro(db.Model):
    __tablename__ = 'maestros'
    id_maestro = db.Column(db.BigInteger, primary_key=True)
    nombre = db.Column(db.String(255), nullable=False)
    apellido = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)
    horarios = db.relationship('Horario', backref='maestro', lazy=True)

class Asignatura(db.Model):
    __tablename__ = 'asignaturas'
    id_asignatura = db.Column(db.BigInteger, primary_key=True)
    nombre_asignatura = db.Column(db.String(255), nullable=False)
    clave_asignatura = db.Column(db.String(255), nullable=False)
    horas_teoricas = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)
    horarios = db.relationship('Horario', backref='asignatura', lazy=True)

class Carrera(db.Model):
    __tablename__ = 'carreras'
    id_carrera = db.Column(db.BigInteger, primary_key=True)
    carrera = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)
    horarios = db.relationship('Horario', backref='carrera', lazy=True)

class Grupo(db.Model):
    __tablename__ = 'grupos'
    id_grupo = db.Column(db.BigInteger, primary_key=True)
    grupo = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)
    horarios = db.relationship('Horario', backref='grupo', lazy=True)

class Aula(db.Model):
    __tablename__ = 'aulas'
    id_aula = db.Column(db.BigInteger, primary_key=True)
    aula = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)
    horarios = db.relationship('Horario', backref='aula', lazy=True)

class Horario(db.Model):
    __tablename__ = 'horarios'
    id_horario = db.Column(db.BigInteger, primary_key=True)
    id_maestro = db.Column(db.BigInteger, db.ForeignKey('maestros.id_maestro'), nullable=False)
    id_asignatura = db.Column(db.BigInteger, db.ForeignKey('asignaturas.id_asignatura'), nullable=False)
    id_carrera = db.Column(db.BigInteger, db.ForeignKey('carreras.id_carrera'), nullable=False)
    id_grupo = db.Column(db.BigInteger, db.ForeignKey('grupos.id_grupo'), nullable=False)
    id_aula = db.Column(db.BigInteger, db.ForeignKey('aulas.id_aula'), nullable=False)
    dia = db.Column(db.String(255), nullable=False)
    hora_inicio = db.Column(db.Time, nullable=False)
    hora_fin = db.Column(db.Time, nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)
    asistencias = db.relationship('RegistroAsistencia', backref='horario', lazy=True)

class TipoEstado(db.Model):
    __tablename__ = 'tipo_estados'
    id_estado = db.Column(db.BigInteger, primary_key=True)
    estado = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)
    asistencias = db.relationship('RegistroAsistencia', backref='estado', lazy=True)

class RegistroAsistencia(db.Model):
    __tablename__ = 'registro_asistencias'
    id_asistencia = db.Column(db.BigInteger, primary_key=True)
    id_horario = db.Column(db.BigInteger, db.ForeignKey('horarios.id_horario'), nullable=False)
    id_estado = db.Column(db.BigInteger, db.ForeignKey('tipo_estados.id_estado'), nullable=False)
    fecha_asistencia = db.Column(db.Date, nullable=False)
    hora_asistencia = db.Column(db.Time, nullable=False)
    created_at = db.Column(db.TIMESTAMP)
    updated_at = db.Column(db.TIMESTAMP)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.BigInteger, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(255), nullable=False, default='student')

# Esquemas
class MaestroSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Maestro

class AsignaturaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Asignatura

class CarreraSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Carrera

class GrupoSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Grupo

class AulaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Aula

class HorarioSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = Horario
    maestro = ma.Nested(MaestroSchema)
    asignatura = ma.Nested(AsignaturaSchema)
    carrera = ma.Nested(CarreraSchema)
    grupo = ma.Nested(GrupoSchema)
    aula = ma.Nested(AulaSchema)

class TipoEstadoSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = TipoEstado

class RegistroAsistenciaSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = RegistroAsistencia
    horario = ma.Nested(HorarioSchema)
    estado = ma.Nested(TipoEstadoSchema)

class UserSchema(ma.SQLAlchemyAutoSchema):
    class Meta:
        model = User
        exclude = ('password',)

# Inicializar esquemas
maestro_schema = MaestroSchema()
maestros_schema = MaestroSchema(many=True)

asignatura_schema = AsignaturaSchema()
asignaturas_schema = AsignaturaSchema(many=True)

carrera_schema = Carr
