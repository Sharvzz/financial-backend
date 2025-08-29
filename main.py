from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import (
    create_engine,
    Column,
    Integer,
    String,
    DateTime,
    Numeric,
    ForeignKey,
    Text,
    UniqueConstraint,
    Index,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, relationship
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, Field, field_validator
from decimal import Decimal
from datetime import datetime, timezone
import os
import uvicorn
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordBearer
# Database URL (from environment variable, fallback to Railway URL if not set)
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:CmpkJJZPavJSwCUYfPaNqGabzaHJPmFz@tramway.proxy.rlwy.net:54731/railway"
)

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

app = FastAPI()

# CORS (adjust FRONTEND_ORIGIN env for production)
FRONTEND_ORIGIN = os.getenv("FRONTEND_ORIGIN", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN] if FRONTEND_ORIGIN != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# JWT settings
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key")  # keep in env for production
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# User model
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    categories = relationship("Category", back_populates="user", cascade="all, delete-orphan")
    transactions = relationship("Transaction", back_populates="user", cascade="all, delete-orphan")


class Category(Base):
    __tablename__ = "categories"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    name = Column(String, nullable=False)
    type = Column(String, nullable=False)  # "income" | "expense"
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="categories")

    __table_args__ = (
        UniqueConstraint("user_id", "name", "type", name="uq_category_user_name_type"),
        Index("ix_categories_user_type_name", "user_id", "type", "name"),
    )


class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    type = Column(String, nullable=False)  # "income" | "expense"
    amount = Column(Numeric(14, 2), nullable=False)
    category_id = Column(Integer, ForeignKey("categories.id", ondelete="SET NULL"), nullable=True, index=True)
    description = Column(Text, nullable=True)
    occurred_at = Column(DateTime(timezone=True), nullable=False, index=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = relationship("User", back_populates="transactions")
    category = relationship("Category")

    __table_args__ = (
        Index("ix_transactions_user_occurred", "user_id", "occurred_at"),
        Index("ix_transactions_user_type", "user_id", "type"),
        Index("ix_transactions_user_category", "user_id", "category_id"),
    )

Base.metadata.create_all(bind=engine)

# Pydantic schemas
class UserCreate(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Auth dependency
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_error = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        subject = payload.get("sub")
        if subject is None:
            raise credentials_error
    except JWTError:
        raise credentials_error

    # Support subject being email for now
    user = db.query(User).filter(User.email == subject).first()
    if not user:
        raise credentials_error
    return user

# Validation models
class CategoryIn(BaseModel):
    name: str
    type: str

    @field_validator("name")
    @classmethod
    def name_non_empty(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("name is required")
        if len(v) > 100:
            raise ValueError("name too long")
        return v

    @field_validator("type")
    @classmethod
    def type_allowed(cls, v: str) -> str:
        if v not in {"income", "expense"}:
            raise ValueError("type must be 'income' or 'expense'")
        return v


class TransactionIn(BaseModel):
    type: str
    amount: Decimal = Field(gt=0)
    categoryId: int | None = None
    categoryName: str | None = None
    description: str | None = None
    occurredAt: str | None = None

    @field_validator("type")
    @classmethod
    def tx_type_allowed(cls, v: str) -> str:
        if v not in {"income", "expense"}:
            raise ValueError("type must be 'income' or 'expense'")
        return v

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if len(v) > 500:
            v = v[:500]
        return v

    @field_validator("occurredAt")
    @classmethod
    def validate_occurred_at(cls, v: str | None) -> str | None:
        if v is None:
            return v
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except Exception as _:
            raise ValueError("occurredAt must be ISO 8601 datetime")
        return v


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(name=user.name, email=user.email, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"id": new_user.id, "name": new_user.name, "email": new_user.email}

@app.post("/login", response_model=Token)
def login(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    access_token = create_access_token({"sub": db_user.email})
    return {"access_token": access_token, "token_type": "bearer"}


# Categories
@app.get("/categories")
def list_categories(type: str | None = None, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    query = db.query(Category).filter(Category.user_id == current_user.id)
    if type is not None:
        if type not in {"income", "expense"}:
            raise HTTPException(status_code=400, detail="type must be 'income' or 'expense'")
        query = query.filter(Category.type == type)
    categories = query.order_by(Category.name.asc()).all()
    return [
        {"id": c.id, "userId": c.user_id, "name": c.name, "type": c.type, "createdAt": c.created_at.isoformat()}
        for c in categories
    ]


@app.post("/categories")
def create_category(payload: CategoryIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    existing = db.query(Category).filter(
        Category.user_id == current_user.id,
        Category.name == payload.name,
        Category.type == payload.type,
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Category already exists")
    category = Category(user_id=current_user.id, name=payload.name, type=payload.type)
    db.add(category)
    db.commit()
    db.refresh(category)
    return {"id": category.id, "userId": category.user_id, "name": category.name, "type": category.type, "createdAt": category.created_at.isoformat()}


# Transactions
@app.post("/transactions")
def create_transaction(payload: TransactionIn, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    # Resolve occurred_at
    occurred_at = (
        datetime.now(timezone.utc)
        if payload.occurredAt is None
        else datetime.fromisoformat(payload.occurredAt.replace("Z", "+00:00"))
    )

    # Validate or upsert category
    category_id: int | None = None
    if payload.categoryId is not None:
        cat = db.query(Category).filter(
            Category.id == payload.categoryId,
            Category.user_id == current_user.id,
        ).first()
        if not cat:
            raise HTTPException(status_code=404, detail="Category not found")
        if cat.type != payload.type:
            raise HTTPException(status_code=400, detail="Category type mismatch")
        category_id = cat.id
    elif payload.categoryName:
        # upsert by (user_id, name, type)
        cat = db.query(Category).filter(
            Category.user_id == current_user.id,
            Category.name == payload.categoryName.strip(),
            Category.type == payload.type,
        ).first()
        if not cat:
            cat = Category(user_id=current_user.id, name=payload.categoryName.strip(), type=payload.type)
            db.add(cat)
            db.commit()
            db.refresh(cat)
        category_id = cat.id

    amount = Decimal(payload.amount).quantize(Decimal("0.01"))

    tx = Transaction(
        user_id=current_user.id,
        type=payload.type,
        amount=amount,
        category_id=category_id,
        description=payload.description,
        occurred_at=occurred_at,
        updated_at=datetime.now(timezone.utc),
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)
    return {
        "id": tx.id,
        "userId": tx.user_id,
        "type": tx.type,
        "amount": float(tx.amount),
        "categoryId": tx.category_id,
        "description": tx.description,
        "occurredAt": tx.occurred_at.isoformat(),
        "createdAt": tx.created_at.isoformat(),
        "updatedAt": tx.updated_at.isoformat(),
    }


@app.get("/transactions")
def list_transactions(limit: int = 20, offset: int = 0, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    limit = max(1, min(limit, 100))
    offset = max(0, offset)
    items = (
        db.query(Transaction)
        .filter(Transaction.user_id == current_user.id)
        .order_by(Transaction.occurred_at.desc())
        .limit(limit)
        .offset(offset)
        .all()
    )
    return [
        {
            "id": t.id,
            "userId": t.user_id,
            "type": t.type,
            "amount": float(t.amount),
            "categoryId": t.category_id,
            "description": t.description,
            "occurredAt": t.occurred_at.isoformat(),
            "createdAt": t.created_at.isoformat(),
            "updatedAt": t.updated_at.isoformat(),
        }
        for t in items
    ]


def _range_start_end(now_utc: datetime, range_key: str) -> tuple[datetime, datetime]:
    if range_key == "last_30_days":
        start = now_utc - timedelta(days=30)
        return start, now_utc
    if range_key == "last_90_days":
        start = now_utc - timedelta(days=90)
        return start, now_utc
    if range_key == "ytd":
        start = datetime(year=now_utc.year, month=1, day=1, tzinfo=timezone.utc)
        return start, now_utc
    raise HTTPException(status_code=400, detail="invalid range")


from datetime import timedelta  # placed here to avoid top clutter

@app.get("/summary")
def get_summary(range: str = "last_30_days", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    now_utc = datetime.now(timezone.utc)
    start, end = _range_start_end(now_utc, range)

    # Aggregations within range
    txs = (
        db.query(Transaction)
        .filter(
            Transaction.user_id == current_user.id,
            Transaction.occurred_at >= start,
            Transaction.occurred_at <= end,
        )
        .all()
    )
    income = sum(float(t.amount) for t in txs if t.type == "income")
    expenses = sum(float(t.amount) for t in txs if t.type == "expense")

    # Balance overall: sum(income) - sum(expense) across ALL time
    all_txs = db.query(Transaction).filter(Transaction.user_id == current_user.id).all()
    total_income = sum(float(t.amount) for t in all_txs if t.type == "income")
    total_expense = sum(float(t.amount) for t in all_txs if t.type == "expense")
    total_balance = total_income - total_expense

    savings_rate = 0.0
    if income > 0:
        savings_rate = max(0.0, 1.0 - (expenses / income))

    # Monthly trend for last 12 months
    months: list[dict] = []
    # construct list of last 12 months labels YYYY-MM
    cursor = datetime(year=now_utc.year, month=now_utc.month, day=1, tzinfo=timezone.utc)
    for _ in range(12):
        label = f"{cursor.year:04d}-{cursor.month:02d}"
        months.append({"month": label, "income": 0.0, "expense": 0.0})
        # move back one month
        if cursor.month == 1:
            cursor = datetime(year=cursor.year - 1, month=12, day=1, tzinfo=timezone.utc)
        else:
            cursor = datetime(year=cursor.year, month=cursor.month - 1, day=1, tzinfo=timezone.utc)
    months.reverse()

    # Preload last 12 months data
    trend_start = datetime(year=now_utc.year if now_utc.month > 1 else now_utc.year - 1,
                           month=now_utc.month - 11 if now_utc.month > 11 else 1,
                           day=1, tzinfo=timezone.utc)
    trend_txs = (
        db.query(Transaction)
        .filter(Transaction.user_id == current_user.id, Transaction.occurred_at >= trend_start)
        .all()
    )
    bucket = {m["month"]: m for m in months}
    for t in trend_txs:
        label = f"{t.occurred_at.year:04d}-{t.occurred_at.month:02d}"
        if label in bucket:
            if t.type == "income":
                bucket[label]["income"] += float(t.amount)
            else:
                bucket[label]["expense"] += float(t.amount)

    return {
        "totalBalance": round(total_balance, 2),
        "monthlyIncome": round(income, 2),
        "monthlyExpenses": round(expenses, 2),
        "savingsRate": round(savings_rate, 3),
        "trend": months,
    }

# Run the app with port 8080
@app.get("/")
def home():
    return FileResponse("static/vadivelu-1.jpg")
if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=True)
