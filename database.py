from datetime import datetime

from sqlalchemy import create_engine, String, Text, DateTime, ForeignKey, text, Integer, UniqueConstraint
from sqlalchemy.orm import sessionmaker, declarative_base, Mapped, mapped_column, relationship
# .env
DB_USER = ""
DB_PASSWORD = ""
DB_HOST = ""
DB_PORT = ""
DB_NAME = ""

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ---  ТАБЛИЦА ДЛЯ ПОДПИСОК ---
class Follow(Base):
    __tablename__ = 'follows'
    id: Mapped[int] = mapped_column(primary_key=True)
    # Тот, кто подписывается
    follower_id: Mapped[int] = mapped_column(ForeignKey('users.user_id'))
    # Тот, на кого подписываются
    followed_id: Mapped[int] = mapped_column(ForeignKey('users.user_id'))

    __table_args__ = (UniqueConstraint('follower_id', 'followed_id', name='_follower_followed_uc'),)


class User(Base):
    __tablename__ = 'users'
    user_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    login: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    fullname: Mapped[str] = mapped_column(String, nullable=True)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password: Mapped[str] = mapped_column(String, nullable=False)
    user_balance: Mapped[int] = mapped_column(default=0)
    review_count: Mapped[int] = mapped_column(default=0)
    image: Mapped[str] = mapped_column(String, nullable=True)  # Путь к файлу аватарки
    reg_date: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    is_admin: Mapped[bool] = mapped_column(default=False, server_default=text('false'))

    reviews: Mapped[list["UserReview"]] = relationship(back_populates="user")

    # На кого я подписан
    following: Mapped[list["Follow"]] = relationship(foreign_keys=[Follow.follower_id], cascade="all, delete-orphan")
    # Кто на меня подписан
    followers: Mapped[list["Follow"]] = relationship(foreign_keys=[Follow.followed_id], cascade="all, delete-orphan")

    def __repr__(self):
        return f"<User {self.login}>"


class Category(Base):
    __tablename__ = 'categories'
    category_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    category_name: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    reviews: Mapped[list["UserReview"]] = relationship(back_populates="category")

    def __repr__(self):
        return f"<Category {self.category_name}>"


# ---  таблица для хранения фото отзывов ---
class ReviewImage(Base):
    __tablename__ = 'review_images'
    image_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    image_path: Mapped[str] = mapped_column(String, nullable=False)
    review_id: Mapped[int] = mapped_column(ForeignKey('reviews.review_id'))

    review: Mapped["UserReview"] = relationship(back_populates="images")


# ---  ТАБЛИЦА ДЛЯ ГОЛОСОВ ---
class ReviewVote(Base):
    __tablename__ = 'review_votes'
    vote_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    review_id: Mapped[int] = mapped_column(ForeignKey('reviews.review_id'))
    user_id: Mapped[int] = mapped_column(ForeignKey('users.user_id'))

    # 1 = лайк, -1 = дизлайк
    vote_type: Mapped[int] = mapped_column(Integer, nullable=False)

    # Гарантирует, что один пользователь может проголосовать за один отзыв только один раз
    __table_args__ = (UniqueConstraint('user_id', 'review_id', name='_user_review_uc'),)


class UserReview(Base):
    __tablename__ = 'reviews'
    review_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    rating: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    view_count: Mapped[int] = mapped_column(Integer, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now)
    likes: Mapped[int] = mapped_column(default=0)
    dislikes: Mapped[int] = mapped_column(default=0)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.user_id'))
    category_id: Mapped[int] = mapped_column(ForeignKey('categories.category_id'))

    user: Mapped["User"] = relationship(back_populates="reviews")
    category: Mapped["Category"] = relationship(back_populates="reviews")
    images: Mapped[list["ReviewImage"]] = relationship(back_populates="review", cascade="all, delete-orphan")

    votes: Mapped[list["ReviewVote"]] = relationship(cascade="all, delete-orphan")
    views: Mapped[list["ReviewView"]] = relationship(cascade="all, delete-orphan")


class ReviewView(Base):
    __tablename__ = 'review_views'
    view_id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    review_id: Mapped[int] = mapped_column(ForeignKey('reviews.review_id'))
    user_id: Mapped[int] = mapped_column(ForeignKey('users.user_id'))

    __table_args__ = (UniqueConstraint('user_id', 'review_id', name='_user_review_view_uc'),)


def init_db():
    print("Dropping all tables...")
    Base.metadata.drop_all(bind=engine)
    print("Creating all tables...")
    Base.metadata.create_all(bind=engine)
    print("Tables created successfully.")


if __name__ == "__main__":
    init_db()
