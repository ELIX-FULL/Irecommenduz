import os
import random
import time
from datetime import datetime, timedelta
from functools import wraps

from authlib.integrations.flask_client import OAuth
from flask import Flask, render_template, request, redirect, url_for, g, session, flash, abort, jsonify
from flask_mail import Mail, Message
from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy.orm import joinedload, subqueryload
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from database import SessionLocal, User, UserReview, Category, ReviewImage, ReviewVote, Follow, ReviewView

app = Flask(__name__)
oauth = OAuth(app)
# .env
app.config['GOOGLE_CLIENT_ID'] = '.apps.googleusercontent.com'  # <-- ВСТАВЬТЕ СЮДА ВАШ ID
app.config['GOOGLE_CLIENT_SECRET'] = 'GgJytvfwPpi67BQsGhe-q4K_Nd2n'  # <-- ВСТАВЬТЕ СЮДА ВАШ SECRET
app.config['YANDEX_CLIENT_ID'] = '3b2c77cbf5'  # <-- ВСТАВЬТЕ СЮДА ВАШ ID ИЗ ЯНДЕКСА
app.config['YANDEX_CLIENT_SECRET'] = 'fwefwffcd3'  # <-- ВСТАВЬТЕ СЮДА ВАШ ПАРОЛЬ
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'gmail.com'  # <-- ВАШ EMAIL
app.config['MAIL_PASSWORD'] = 'ewcf feqw fwcs fwws'  # <-- ВАШ 16-ЗНАЧНЫЙ ПАРОЛЬ ПРИЛОЖЕНИЯ
app.config['MAIL_DEFAULT_SENDER'] = (' uz', '@gmail.com')

mail = Mail(app)  # Инициализируем Mail

google = oauth.register(
    name='google',
    client_id=app.config["GOOGLE_CLIENT_ID"],
    client_secret=app.config["GOOGLE_CLIENT_SECRET"],
    access_token_url='https://accounts.google.com/o/oauth2/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
)

# --- НОВАЯ РЕГИСТРАЦИЯ КЛИЕНТА YANDEX ---
yandex = oauth.register(
    name='yandex',
    client_id=app.config["YANDEX_CLIENT_ID"],
    client_secret=app.config["YANDEX_CLIENT_SECRET"],
    access_token_url='https://oauth.yandex.ru/token',
    access_token_params=None,
    authorize_url='https://oauth.yandex.ru/authorize',
    authorize_params=None,
    api_base_url='https://login.yandex.ru/',
    userinfo_endpoint='info',
    client_kwargs={},
)

app.config['SECRET_KEY'] = os.urandom(24)
PROFILE_PICS_FOLDER = 'static/profile_pics'
REVIEW_PICS_FOLDER = 'static/review_pics'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
app.config['PROFILE_PICS_FOLDER'] = PROFILE_PICS_FOLDER
app.config['REVIEW_PICS_FOLDER'] = REVIEW_PICS_FOLDER


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def before_request():
    g.db = SessionLocal()
    g.categories = g.db.query(Category).order_by(Category.category_name).all()
    g.user = None
    g.user_votes = {}
    if 'user_id' in session:
        g.user = g.db.query(User).filter(User.user_id == session['user_id']).first()
        if g.user:  # Доп. проверка, если пользователь был удален, а сессия осталась
            votes = g.db.query(ReviewVote).filter_by(user_id=g.user.user_id).all()
            g.user_votes = {vote.review_id: vote.vote_type for vote in votes}


@app.teardown_request
def teardown_request(exception=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash('Для доступа к этой странице необходимо войти в систему.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    return decorated_function


def guest_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user:
            flash('Вы уже вошли в свой аккаунт.', 'info')
            return redirect(url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


@app.route('/google/login')
def google_login():
    """Перенаправляет пользователя на страницу входа Google."""
    redirect_uri = url_for('google_auth', _external=True)
    return google.authorize_redirect(redirect_uri)


@app.route('/google/auth')
def google_auth():
    """Обрабатывает ответ от Google."""
    token = google.authorize_access_token()
    user_info = google.get('userinfo').json()

    user = g.db.query(User).filter_by(email=user_info['email']).first()

    if not user:
        random_password = os.urandom(16).hex()
        login = user_info['name'].replace(" ", "").lower()
        while g.db.query(User).filter_by(login=login).first():
            login += str(random.randint(0, 9))

        user = User(
            login=login,
            email=user_info['email'],
            fullname=user_info['name'],
            password=generate_password_hash(random_password)
        )
        g.db.add(user)
        g.db.commit()

    session['user_id'] = user.user_id
    session['user_login'] = user.login
    flash('Вы успешно вошли через Google!', 'success')
    return redirect(url_for('index'))


@app.route('/yandex/login')
def yandex_login():
    """Перенаправляет пользователя на страницу входа Яндекс."""
    redirect_uri = url_for('yandex_auth', _external=True)
    return yandex.authorize_redirect(redirect_uri)


@app.route('/yandex/auth')
def yandex_auth():
    """Обрабатывает ответ от Яндекс."""
    token = yandex.authorize_access_token()
    user_info = yandex.get('info').json()

    email = user_info.get('default_email')
    fullname = user_info.get('real_name') or user_info.get('display_name')
    login = user_info.get('login')

    if not email:
        flash('Не удалось получить email от Яндекса. Попробуйте другой способ входа.', 'error')
        return redirect(url_for('login'))

    user = g.db.query(User).filter_by(email=email).first()

    if not user:
        random_password = os.urandom(16).hex()
        while g.db.query(User).filter_by(login=login).first():
            login += str(random.randint(0, 9))

        user = User(
            login=login,
            email=email,
            fullname=fullname,
            password=generate_password_hash(random_password)
        )
        g.db.add(user)
        g.db.commit()

    session['user_id'] = user.user_id
    session['user_login'] = user.login
    flash('Вы успешно вошли через Яндекс!', 'success')
    return redirect(url_for('index'))


@app.route('/categories')
def all_categories():
    return render_template('all_categories.html', categories=g.categories)


@app.route('/')
def index():
    all_reviews = g.db.query(UserReview).options(
        subqueryload(UserReview.images),
        joinedload(UserReview.user)
    ).order_by(UserReview.created_at.desc()).all()

    user_votes = {}
    if g.user:
        votes = g.db.query(ReviewVote).filter_by(user_id=g.user.user_id).all()
        user_votes = {vote.review_id: vote.vote_type for vote in votes}

    time_24_hours_ago = datetime.now() - timedelta(hours=24)
    popular_reviews = g.db.query(UserReview).options(joinedload(UserReview.user)).filter(
        UserReview.created_at >= time_24_hours_ago
    ).order_by(UserReview.rating.desc(), UserReview.likes.desc()).limit(5).all()

    return render_template('index.html', reviews=all_reviews, popular_reviews=popular_reviews, categories=g.categories,
                           user_votes=g.user_votes)


@app.route('/review/<int:review_id>')
def review_detail(review_id):
    review = g.db.query(UserReview).options(
        subqueryload(UserReview.images),
        joinedload(UserReview.user),
        joinedload(UserReview.category)
    ).filter(UserReview.review_id == review_id).first()

    if review is None:
        abort(404)

    return render_template('review_detail.html', review=review, categories=g.categories, user_votes=g.user_votes)


@app.route('/review/<int:review_id>/view', methods=['POST'])
@login_required
def record_view(review_id):
    existing_view = g.db.query(ReviewView).filter_by(
        user_id=g.user.user_id,
        review_id=review_id
    ).first()

    if not existing_view:
        review = g.db.query(UserReview).filter_by(review_id=review_id).first()
        if review:
            review.view_count += 1
            new_view = ReviewView(user_id=g.user.user_id, review_id=review_id)
            g.db.add(new_view)
            g.db.commit()
            return jsonify({'success': True, 'new_view_count': review.view_count}), 200

    return jsonify({'success': False, 'message': 'View already recorded'}), 208


@app.route('/add_review', methods=['GET', 'POST'])
@login_required
def add_review():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        category_id = request.form.get('category')
        rating = request.form.get('rating')
        if len(description) < 255:
            flash('Текст отзыва слишком короткий. Минимальная длина - 255 символов.', 'error')
            return render_template('add_review.html', categories=g.categories, name=name, description=description,
                                   category_id=category_id, rating=rating)

        if len(description) > 9000:
            flash('Текст отзыва слишком длинный. Максимальная длина - 9000 символов.', 'error')
            return render_template('add_review.html', categories=g.categories, name=name, description=description,
                                   category_id=category_id, rating=rating)

        if not (name and description and category_id and rating):
            flash('Пожалуйста, заполните все обязательные поля, включая рейтинг.', 'error')
            return redirect(request.url)

        new_review = UserReview(
            name=name,
            description=description,
            rating=int(rating),
            category_id=int(category_id),
            user_id=session['user_id']
        )
        g.db.add(new_review)
        g.db.commit()
        g.db.refresh(new_review)

        files = request.files.getlist('review_photos')
        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{session['user_id']}_{int(time.time())}_{filename}"
                file.save(os.path.join(app.config['REVIEW_PICS_FOLDER'], unique_filename))

                new_image = ReviewImage(image_path=unique_filename, review_id=new_review.review_id)
                g.db.add(new_image)

        g.db.commit()

        flash('Ваш отзыв успешно добавлен!', 'success')
        return redirect(url_for('index'))

    return render_template('add_review.html', categories=g.categories)


@app.route('/category/<int:category_id>')
def reviews_by_category(category_id):
    category = g.db.query(Category).filter(Category.category_id == category_id).first()
    if not category:
        abort(404)

    # Загружаем отзывы для конкретной категории
    reviews = g.db.query(UserReview).options(
        subqueryload(UserReview.images),
        joinedload(UserReview.user)
    ).filter(UserReview.category_id == category_id).order_by(UserReview.created_at.desc()).all()

    # Мы будем использовать тот же шаблон index.html, но передадим ему дополнительную информацию
    return render_template('index.html', reviews=reviews, categories=g.categories, current_category=category,
                           user_votes=g.user_votes)


@app.route('/search')
def search():
    query = request.args.get('q')  # Получаем поисковый запрос из URL
    if not query:
        return redirect(url_for('index'))

    search_results = g.db.query(UserReview).options(
        subqueryload(UserReview.images),
        joinedload(UserReview.user)
    ).filter(
        or_(
            UserReview.name.ilike(f'%{query}%'),
            UserReview.description.ilike(f'%{query}%')
        )
    ).order_by(UserReview.created_at.desc()).all()

    return render_template('search_results.html', reviews=search_results, query=query, categories=g.categories,
                           user_votes=g.user_votes)


@app.route('/search/autocomplete')
def search_autocomplete():
    query = request.args.get('q')
    if not query:
        return jsonify([])

    suggestions = g.db.query(UserReview.name, UserReview.review_id).filter(
        UserReview.name.ilike(f'%{query}%')
    ).limit(5).all()

    # Преобразуем результат в список словарей для JSON
    results = [{'name': name, 'url': url_for('review_detail', review_id=review_id)} for name, review_id in suggestions]

    return jsonify(results)


@app.route('/register', methods=['GET', 'POST'])
@guest_only
def register():
    if request.method == 'POST':
        login = request.form.get('login')
        email = request.form.get('email')
        password = request.form.get('password')
        user_by_login = g.db.query(User).filter(User.login == login).first()
        user_by_email = g.db.query(User).filter(User.email == email).first()
        if user_by_login:
            flash('Пользователь с таким логином уже существует.', 'error')
            return redirect(url_for('register'))
        if user_by_email:
            flash('Пользователь с таким email уже существует.', 'error')
            return redirect(url_for('register'))
        hashed_password = generate_password_hash(password)
        new_user = User(login=login, email=email, password=hashed_password, fullname=login)
        g.db.add(new_user)
        g.db.commit()
        flash('Регистрация прошла успешно! Теперь вы можете войти.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', categories=g.categories)


@app.route('/login', methods=['GET', 'POST'])
@guest_only
def login():
    if request.method == 'POST':
        login_or_email = request.form.get('login')
        password = request.form.get('password')
        user = g.db.query(User).filter((User.login == login_or_email) | (User.email == login_or_email)).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.user_id
            session['user_login'] = user.login
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Неверный логин/email или пароль.', 'error')
            return redirect(url_for('login'))
    return render_template('login.html', categories=g.categories)


@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_login', None)
    flash('Вы вышли из своего аккаунта.', 'info')
    return redirect(url_for('index'))


@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    user = g.db.query(User).filter(User.user_id == session['user_id']).first()
    if request.method == 'POST':
        user.fullname = request.form.get('fullname')
        user.email = request.form.get('email')
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and file.filename != '' and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                unique_filename = f"{user.user_id}_{filename}"
                file.save(os.path.join(app.config['PROFILE_PICS_FOLDER'], unique_filename))
                user.image = unique_filename
        g.db.commit()
        flash('Профиль успешно обновлен!', 'success')
        return redirect(url_for('profile'))
    user_reviews = g.db.query(UserReview).options(subqueryload(UserReview.images)).filter(
        UserReview.user_id == user.user_id).order_by(UserReview.created_at.desc()).all()
    follower_count = g.db.query(Follow).filter(Follow.followed_id == user.user_id).count()
    following_count = g.db.query(Follow).filter(Follow.follower_id == user.user_id).count()
    followers = g.db.query(User).join(Follow, Follow.follower_id == User.user_id).filter(
        Follow.followed_id == user.user_id).all()
    following = g.db.query(User).join(Follow, Follow.followed_id == User.user_id).filter(
        Follow.follower_id == user.user_id).all()

    return render_template(
        'profile.html',
        user_to_view=user,  # Используем то же имя переменной для унификации
        reviews=user_reviews,
        follower_count=follower_count,
        following_count=following_count,
        followers=followers,
        following=following,
        show_nav=False
    )


@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    user = g.db.query(User).filter(User.user_id == session['user_id']).first()
    old_password = request.form.get('old_password')
    new_password = request.form.get('new_password')
    confirm_password = request.form.get('confirm_password')
    if not check_password_hash(user.password, old_password):
        flash('Старый пароль введен неверно.', 'error')
        return redirect(url_for('profile'))
    if not new_password or new_password != confirm_password:
        flash('Новые пароли не совпадают или поле пустое.', 'error')
        return redirect(url_for('profile'))
    user.password = generate_password_hash(new_password)
    g.db.commit()
    flash('Пароль успешно изменен!', 'success')
    return redirect(url_for('profile'))


@app.route('/review/<int:review_id>/vote', methods=['POST'])
def vote_on_review(review_id):
    # --- НОВАЯ ПРОВЕРКА: Если пользователь не вошел, возвращаем ошибку 401 ---
    if not g.user:
        return jsonify({'error': 'Authentication required'}), 401

    review = g.db.query(UserReview).filter_by(review_id=review_id).first()
    if not review:
        return jsonify({'error': 'Отзыв не найден'}), 404

    data = request.get_json()
    vote_type = data.get('vote_type')  # 1 for like, -1 for dislike

    existing_vote = g.db.query(ReviewVote).filter_by(user_id=g.user.user_id, review_id=review_id).first()

    if existing_vote:
        if existing_vote.vote_type == vote_type:
            if vote_type == 1:
                review.likes -= 1
            else:
                review.dislikes -= 1
            g.db.delete(existing_vote)
            user_vote_status = 0  # Голос снят
        # Если кликнули на другую кнопку (дизлайк на лайк), меняем голос
        else:
            if vote_type == 1:
                review.likes += 1
                review.dislikes -= 1
            else:
                review.likes -= 1
                review.dislikes += 1
            existing_vote.vote_type = vote_type
            user_vote_status = vote_type
    else:
        # Если голоса не было, создаем новый
        new_vote = ReviewVote(user_id=g.user.user_id, review_id=review_id, vote_type=vote_type)
        if vote_type == 1:
            review.likes += 1
        else:
            review.dislikes += 1
        g.db.add(new_vote)
        user_vote_status = vote_type

    g.db.commit()
    return jsonify({
        'likes': review.likes,
        'dislikes': review.dislikes,
        'user_vote': user_vote_status
    })


@app.route('/review/<int:review_id>/delete', methods=['POST'])
@login_required  # Только авторизованный пользователь может удалять
def delete_review(review_id):
    # Находим отзыв в базе данных
    review_to_delete = g.db.query(UserReview).filter(UserReview.review_id == review_id).first()

    # Если отзыв не найден, возвращаем ошибку
    if not review_to_delete:
        abort(404)

    if review_to_delete.user_id != g.user.user_id:
        abort(403)  # 403 Forbidden - доступ запрещен

    # Если все проверки пройдены, удаляем отзыв
    g.db.delete(review_to_delete)
    g.db.commit()

    flash('Ваш отзыв был успешно удален.', 'success')
    # Перенаправляем пользователя на главную страницу
    return redirect(url_for('index'))


@app.route('/user/<string:username>')
def user_profile(username):
    # Находим пользователя, чей профиль мы смотрим
    user_to_view = g.db.query(User).filter(func.lower(User.login) == username.lower()).first()
    if not user_to_view:
        abort(404)  # Если пользователь не найден, показываем страницу 404

    # Находим все его отзывы
    user_reviews = g.db.query(UserReview).options(
        subqueryload(UserReview.images)
    ).filter(UserReview.user_id == user_to_view.user_id).order_by(UserReview.created_at.desc()).all()

    follower_count = g.db.query(Follow).filter(Follow.followed_id == user_to_view.user_id).count()
    following_count = g.db.query(Follow).filter(Follow.follower_id == user_to_view.user_id).count()

    is_following = False
    if g.user:
        is_following = g.db.query(Follow).filter(
            Follow.follower_id == g.user.user_id,
            Follow.followed_id == user_to_view.user_id
        ).first() is not None

    followers = g.db.query(User).join(Follow, Follow.follower_id == User.user_id).filter(
        Follow.followed_id == user_to_view.user_id).all()
    following = g.db.query(User).join(Follow, Follow.followed_id == User.user_id).filter(
        Follow.follower_id == user_to_view.user_id).all()

    return render_template(
        'user_profile.html',
        user_to_view=user_to_view,
        reviews=user_reviews,
        follower_count=follower_count,
        following_count=following_count,
        is_following=is_following,
        followers=followers,
        following=following,
        show_nav=False
    )


@app.route('/follow/<int:user_id>', methods=['POST'])
@login_required
def follow(user_id):
    if user_id == g.user.user_id:  # Нельзя подписаться на себя
        return jsonify({'error': 'Cannot follow yourself'}), 400

    existing_follow = g.db.query(Follow).filter_by(follower_id=g.user.user_id, followed_id=user_id).first()
    if not existing_follow:
        new_follow = Follow(follower_id=g.user.user_id, followed_id=user_id)
        g.db.add(new_follow)
        g.db.commit()
    return jsonify({'success': True})


@app.route('/unfollow/<int:user_id>', methods=['POST'])
@login_required
def unfollow(user_id):
    follow_to_delete = g.db.query(Follow).filter_by(follower_id=g.user.user_id, followed_id=user_id).first()
    if follow_to_delete:
        g.db.delete(follow_to_delete)
        g.db.commit()
    return jsonify({'success': True})



@app.route('/forgot-password', methods=['GET', 'POST'])
@guest_only
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = g.db.query(User).filter_by(email=email).first()

        if not user:
            flash('Пользователь с таким email не найден.', 'error')
            return redirect(url_for('forgot_password'))

        reset_code = f'{random.randint(100000, 999999)}'
        session['reset_code'] = reset_code
        session['reset_email'] = user.email

        try:
            msg = Message('Восстановление пароля', recipients=[user.email])
            msg.body = f'Ваш код для восстановления пароля: {reset_code}'
            mail.send(msg)
            flash('Код восстановления был успешно отправлен на вашу почту.', 'success')
            return redirect(url_for('verify_code'))
        except Exception as e:
            flash('Не удалось отправить письмо. Пожалуйста, попробуйте позже.', 'error')
            return render_template('forgot_password.html')

    return render_template('forgot_password.html')


@app.route('/verify-code', methods=['GET', 'POST'])
@guest_only
def verify_code():
    # Если пользователь попал сюда без email в сессии, отправляем его в начало
    if 'reset_email' not in session:
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        submitted_code = request.form.get('code')
        if submitted_code == session.get('reset_code'):
            session['code_verified'] = True  # Флаг, что код верный
            flash('Код подтвержден. Теперь вы можете установить новый пароль.', 'success')
            return redirect(url_for('reset_password'))
        else:
            flash('Неверный код подтверждения.', 'error')

    return render_template('verify_code.html')


@app.route('/reset-password', methods=['GET', 'POST'])
@guest_only
def reset_password():
    # Проверяем, что пользователь прошел этап верификации кода
    if not session.get('code_verified'):
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password or not new_password:
            flash('Пароли не совпадают или поле пустое.', 'error')
            return redirect(url_for('reset_password'))

        user = g.db.query(User).filter_by(email=session['reset_email']).first()
        if user:
            user.password = generate_password_hash(new_password)
            g.db.commit()

            # Очищаем сессию от временных данных
            session.pop('reset_code', None)
            session.pop('reset_email', None)
            session.pop('code_verified', None)

            flash('Пароль успешно изменен! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))

    return render_template('reset_password.html')


if __name__ == '__main__':
    app.run(debug=True)
