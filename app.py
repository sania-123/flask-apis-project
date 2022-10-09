from flask import Flask,request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt

app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)

    def to_data(self):
        return {

            "id": self.id,
            "username": self.username,

        }


@app.route('/users', methods=['GET'])
def index():
    print("all user get successfully")
    data = User.query.all()
    user = list()
    for result in data:
        user.append(result.to_data())
    print(type(user))
    print("user = ", user)
    return {"user": user}


@app.route('/users/<int:id>', methods=['GET'])
def get_user(id: int):
    data = User.query.get(id)
    if data is None:
        return jsonify({ 'error': 'users does not exist'}), 404
    return data.to_data()

@app.route('/login', methods=['POST'])
def login():
    data=request.json
    print(data)

    if data:
        user = User.query.filter_by(username=data['username']).first()
        if user:
            if bcrypt.check_password_hash(user.password, data['password']):
                login_user(user)
            else:
                return "password is not correct"
    return "user login successfully"
@app.route('/logout', methods=['GET'])
@login_required
def logout():
    logout_user()
    return "user logout successfully"


@ app.route('/register', methods=['POST'])
def register():
    data=request.json
    print(data)
    if data:
        hashed_password = bcrypt.generate_password_hash(data['password'])
        new_user = User(username=data["username"], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
    return jsonify(data)


@app.route('/update/<int:id>', methods = ['PUT'])
def update(id):
    all_data=request.json
    print(all_data)
    if all_data:
        data = User.query.get(id)
        if data:

            data.username = all_data['username']
            data.password = bcrypt.generate_password_hash(all_data['password'])

            db.session.commit()
        return "Employee updated successfully"

@app.route('/delete/<id>/', methods = ['Delete'])
def delete(id):
    my_data = User.query.get(id)
    if my_data:
        db.session.delete(my_data)
        db.session.commit()
        return "Employee deleted successfully"
    return "employee not found"
if __name__ == "__main__":
    app.run(debug=True, port=8000)
