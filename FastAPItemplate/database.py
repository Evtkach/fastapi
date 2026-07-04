from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

from models import User

DATABASE_URL = "postgresql://postgres:mysecretpassword@localhost:5432/postgres"

engine = create_engine(DATABASE_URL, echo=True)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

Base.metadata.create_all(bind=engine)

db = SessionLocal()

try:
    new_user = User(name="Иван", email="ivan@example.com")

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    print(f"Пользователь создан с ID: {new_user.id}")

finally:
    db.close()