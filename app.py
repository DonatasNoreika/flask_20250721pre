from flask_login import LoginManager, UserMixin, current_user, logout_user, login_user, login_required
from flask import Flask, render_template, redirect, url_for, flash, request
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_mail import Message, Mail
import forms
import os

app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key_here'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'prisijungti'
login_manager.login_message_category = 'info'


app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'MAIL_USERNAME'
app.config['MAIL_PASSWORD'] = 'MAIL_PASSWORD'

mail = Mail(app)

class Vartotojas(db.Model, UserMixin):
    __tablename__ = "vartotojas"
    id = db.Column(db.Integer, primary_key=True)
    vardas = db.Column("Vardas", db.String(20), unique=True, nullable=False)
    el_pastas = db.Column("El. pašto adresas", db.String(120), unique=True, nullable=False)
    slaptazodis = db.Column("Slaptažodis", db.String(60), unique=True, nullable=False)

    def get_reset_token(self):
        s = Serializer(app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token)['user_id']
        except:
            return None
        return db.session.get(Vartotojas, user_id)

class Uzduotis(db.Model):
    __tablename__ = "uzduotis"
    id = db.Column(db.Integer, primary_key=True)
    pavadinimas = db.Column("Pavadinimas", db.String)
    vartotojas_id = db.Column(db.Integer, db.ForeignKey("vartotojas.id"))
    vartotojas = db.relationship("Vartotojas")
    atlikta = db.Column("Atlikta", db.Boolean)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/registruotis", methods=['GET', 'POST'])
def registruotis():
    db.create_all()
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.RegistracijosForma()
    if form.validate_on_submit():
        koduotas_slaptazodis = bcrypt.generate_password_hash(form.slaptazodis.data).decode('utf-8')
        vartotojas = Vartotojas(vardas=form.vardas.data, el_pastas=form.el_pastas.data,
                                slaptazodis=koduotas_slaptazodis)
        db.session.add(vartotojas)
        db.session.commit()
        flash('Sėkmingai prisiregistravote! Galite prisijungti', 'success')
        return redirect(url_for('index'))
    return render_template('registruotis.html', title='Register', form=form)


@app.route("/prisijungti", methods=['GET', 'POST'])
def prisijungti():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = forms.PrisijungimoForma()
    if form.validate_on_submit():
        user = Vartotojas.query.filter_by(el_pastas=form.el_pastas.data).first()
        if user and bcrypt.check_password_hash(user.slaptazodis, form.slaptazodis.data):
            login_user(user, remember=form.prisiminti.data)
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Prisijungti nepavyko. Patikrinkite el. paštą ir slaptažodį', 'danger')
    return render_template('prisijungti.html', title='Prisijungti', form=form)


@login_manager.user_loader
def load_user(vartotojo_id):
    return db.session.get(Vartotojas, int(vartotojo_id))


@app.route("/atsijungti")
def atsijungti():
    logout_user()
    return redirect(url_for('index'))


@app.route("/uzduotys")
@login_required
def uzduotys():
    uzduotys = Uzduotis.query.filter_by(vartotojas=current_user).all()
    return render_template('uzduotys.html', uzduotys=uzduotys)

@app.route('/uzduotys/nauja', methods=['GET', 'POST'])
@login_required
def sukurti_uzduoti():
    form = forms.UzduotisForma()
    if form.validate_on_submit():
        uzduotis = Uzduotis(
            pavadinimas=form.pavadinimas.data,
            atlikta=form.atlikta.data,
            vartotojas_id=current_user.id
        )
        db.session.add(uzduotis)
        db.session.commit()
        flash('Užduotis sukurta!', 'success')
        return redirect(url_for('uzduotys'))
    return render_template('sukurti_uzduoti.html', form=form)


@app.route('/uzduotys/redaguoti/<int:id>', methods=['GET', 'POST'])
@login_required
def redaguoti_uzduoti(id):
    uzduotis = Uzduotis.query.filter_by(id=id, vartotojas_id=current_user.id).first_or_404()
    form = forms.UzduotisForma(obj=uzduotis)
    if form.validate_on_submit():
        uzduotis.pavadinimas = form.pavadinimas.data
        uzduotis.atlikta = form.atlikta.data
        db.session.commit()
        flash('Užduotis atnaujinta!', 'success')
        return redirect(url_for('uzduotys'))
    return render_template('redaguoti_uzduoti.html', form=form)


@app.route('/uzduotys/trinti/<int:id>')
@login_required
def trinti_uzduoti(id):
    uzduotis = Uzduotis.query.filter_by(id=id, vartotojas_id=current_user.id).first_or_404()
    db.session.delete(uzduotis)
    db.session.commit()
    flash('Užduotis ištrinta!', 'success')
    return redirect(url_for('uzduotys'))


def send_reset_email(user):
    token = user.get_reset_token()
    msg = Message('Slaptažodžio atnaujinimo užklausa',
                  sender='el@pastas.lt',
                  recipients=[user.el_pastas])
    msg.body = f'''Norėdami atnaujinti slaptažodį, paspauskite nuorodą:
    {url_for('reset_token', token=token, _external=True)}
    Jei jūs nedarėte šios užklausos, nieko nedarykite ir slaptažodis nebus pakeistas.
    '''
    print(msg.body)
    # mail.send(msg)


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_token(token):
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    user = Vartotojas.verify_reset_token(token)
    if user is None:
        flash('Užklausa netinkama arba pasibaigusio galiojimo', 'warning')
        return redirect(url_for('reset_request'))
    form = forms.SlaptazodzioAtnaujinimoForma()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.slaptazodis.data).decode('utf-8')
        user.slaptazodis = hashed_password
        db.session.commit()
        flash('Tavo slaptažodis buvo atnaujintas! Gali prisijungti', 'success')
        return redirect(url_for('prisijungti'))
    return render_template('reset_token.html', title='Reset Password', form=form)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    form = forms.UzklausosAtnaujinimoForma()
    if form.validate_on_submit():
        user = Vartotojas.query.filter_by(el_pastas=form.el_pastas.data).first()
        send_reset_email(user)
        flash('Jums išsiųstas el. laiškas su slaptažodžio atnaujinimo instrukcijomis.', 'info')
        return redirect(url_for('prisijungti'))
    return render_template('reset_request.html', title='Reset Password', form=form)

@app.errorhandler(404)
def klaida_404(klaida):
    return render_template("404.html"), 404

@app.errorhandler(403)
def klaida_403(klaida):
    return render_template("403.html"), 403

@app.errorhandler(500)
def klaida_500(klaida):
    return render_template("500.html"), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
