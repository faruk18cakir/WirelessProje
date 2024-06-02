from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(50), nullable=False)
    company_name = db.Column(db.String(150), nullable=False)
    materials = db.relationship('Material', backref='user', lazy=True)


class Material(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_company = db.Column(db.String(150), nullable=False)
    name = db.Column(db.String(150), nullable=False)
    type = db.Column(db.String(150), nullable=False)
    quantity = db.Column(db.String(150), nullable=False)
    vehicle_number = db.Column(db.String(150), nullable=False)
    vehicle_plate = db.Column(db.String(150), nullable=False)
    contact_phone = db.Column(db.String(150), nullable=False)
    delivery_address = db.Column(db.String(150), nullable=False)
    rfid_code = db.Column(db.String(150), nullable=False)
    dispatch_address = db.Column(db.String(150))
    dispatch_time = db.Column(db.DateTime)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    trackings = db.relationship('Tracking', backref='material', lazy=True)


class Tracking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    material_id = db.Column(db.Integer, db.ForeignKey('material.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    location = db.Column(db.String(150), nullable=False)
    status = db.Column(db.String(150), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user.role == 'user':
                return redirect(url_for('user_dashboard'))
        else:
            flash('Ya kullanıcı adı ya da şifre hatalı', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        company_name = request.form['company_name']
        user = User.query.filter_by(username=username).first()
        if user:
            flash('Bu kullanıcı sistemde kayıtlıdır.', 'danger')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, password=hashed_password, role=role, company_name=company_name)
        db.session.add(new_user)
        db.session.commit()
        flash('Kullanıcı başarıyla kaydedildi.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        return 'Permission denied'
    return render_template('admin_dashboard.html')


@app.route('/add_material', methods=['GET', 'POST'])
@login_required
def add_material():
    if current_user.role != 'admin':
        return 'Permission denied'
    if request.method == 'POST':
        order_company = request.form['order_company']
        name = request.form['name']
        type = request.form['type']
        quantity = request.form['quantity']
        vehicle_number = request.form['vehicle_number']
        vehicle_plate = request.form['vehicle_plate']
        contact_phone = request.form['contact_phone']
        delivery_address = request.form['delivery_address']
        rfid_code = request.form['rfid_code']
        new_material = Material(order_company=order_company, name=name, type=type, quantity=quantity,
                                vehicle_number=vehicle_number, vehicle_plate=vehicle_plate, contact_phone=contact_phone,
                                delivery_address=delivery_address, rfid_code=rfid_code, user_id=current_user.id)
        db.session.add(new_material)
        db.session.commit()
        flash('Malzeme başarıyla eklendi.', 'success')
        return redirect(url_for('add_material'))
    return render_template('add_material.html')


@app.route('/edit_database', methods=['GET', 'POST'])
@login_required
def edit_database():
    if current_user.role != 'admin':
        return 'Permission denied'
    if request.method == 'POST':
        rfid_code = request.form['rfid_code']
        material = Material.query.filter_by(rfid_code=rfid_code).first()
        if material:
            material.dispatch_address = request.form['dispatch_address']
            material.dispatch_time = datetime.utcnow()
            db.session.commit()
            flash('Malzeme bilgileri başarıyla güncellendi.', 'success')
        else:
            flash('Bu RFID koduna sahip bir malzeme bulunamadı.', 'danger')
    return render_template('edit_database.html')


@app.route('/track_material', methods=['GET', 'POST'])
@login_required
def track_material():
    if current_user.role != 'admin':
        return 'Permission denied'
    tracking_info = None
    if request.method == 'POST':
        rfid_code = request.form['rfid_code']
        material = Material.query.filter_by(rfid_code=rfid_code).first()
        if material:
            tracking_info = Tracking.query.filter_by(material_id=material.id).order_by(Tracking.timestamp).all()
        else:
            flash('Bu RFID koduna sahip bir malzeme bulunamadı.', 'danger')
    return render_template('track_material.html', tracking_info=tracking_info)


@app.route('/add_tracking', methods=['GET', 'POST'])
@login_required
def add_tracking():
    if current_user.role != 'admin':
        return 'Permission denied'
    if request.method == 'POST':
        rfid_code = request.form['rfid_code']
        location = request.form['location']
        status = request.form['status']
        material = Material.query.filter_by(rfid_code=rfid_code).first()
        if material:
            new_tracking = Tracking(material_id=material.id, location=location, status=status)
            db.session.add(new_tracking)
            db.session.commit()
            flash('Takip bilgisi başarıyla eklendi.', 'success')
        else:
            flash('Bu RFID koduna sahip bir malzeme bulunamadı.', 'danger')
    return render_template('add_tracking.html')


@app.route('/view_admin_materials')
@login_required
def view_admin_materials():
    if current_user.role != 'admin':
        return 'Permission denied'
    materials = Material.query.filter_by(user_id=current_user.id).all()
    return render_template('view_admin_materials.html', materials=materials)


@app.route('/user_dashboard')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return 'Permission denied'
    return render_template('user_dashboard.html')


@app.route('/view_user_materials')
@login_required
def view_user_materials():
    if current_user.role != 'user':
        return 'Permission denied'
    materials = Material.query.filter_by(order_company=current_user.company_name).all()
    return render_template('view_user_materials.html', materials=materials)


@app.route('/track_user_material', methods=['GET', 'POST'])
@login_required
def track_user_material():
    if current_user.role != 'user':
        return 'Permission denied'
    tracking_info = None
    if request.method == 'POST':
        rfid_code = request.form['rfid_code']
        material = Material.query.filter_by(rfid_code=rfid_code, order_company=current_user.company_name).first()
        if material:
            tracking_info = Tracking.query.filter_by(material_id=material.id).order_by(Tracking.timestamp).all()
        else:
            flash('Bu RFID koduna sahip bir malzeme bulunamadı.', 'danger')
    return render_template('track_user_material.html', tracking_info=tracking_info)


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)