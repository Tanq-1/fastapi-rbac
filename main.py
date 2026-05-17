from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Annotated

import jwt
from fastapi import Depends, FastAPI, HTTPException, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel
from sqlmodel import Field, Session, SQLModel, create_engine, select

SECRET_KEY = "SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

sqlite_file_name = "todo.db"
sqlite_url = f"sqlite:///{sqlite_file_name}"

engine = create_engine(
    sqlite_url,
    connect_args={"check_same_thread": False},
)


def create_db_and_tables():
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session


SessionDep = Annotated[Session, Depends(get_session)]


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_db_and_tables()
    yield


app = FastAPI(
    title="Todo RBAC API",
    lifespan=lifespan,
)

class Role(str, Enum):
    admin = "admin"
    user = "user"


class User(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    hashed_password: str
    role: Role = Field(default=Role.user)


class Task(SQLModel, table=True):
    id: int | None = Field(default=None, primary_key=True)
    title: str
    description: str | None = None
    completed: bool = False
    owner_id: int = Field(foreign_key="user.id", index=True)

class UserCreate(SQLModel):
    username: str
    password: str
    role: Role = Role.user


class UserRead(SQLModel):
    id: int
    username: str
    role: Role


class Token(BaseModel):
    access_token: str
    token_type: str


class TaskCreate(SQLModel):
    title: str
    description: str | None = None


class TaskRead(SQLModel):
    id: int
    title: str
    description: str | None
    completed: bool
    owner_id: int

password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummy-password")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")


def get_password_hash(password: str) -> str:
    return password_hash.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return password_hash.verify(plain_password, hashed_password)


def create_access_token(
    data: dict,
    expires_delta: timedelta | None = None,
) -> str:
    to_encode = data.copy()

    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=15)
    )

    to_encode.update({"exp": expire})

    encoded_jwt = jwt.encode(
        to_encode,
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

    return encoded_jwt


def unauthorized_exception(detail: str = "Could not validate credentials"):
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def authenticate_user(
    session: Session,
    username: str,
    password: str,
) -> User | None:
    statement = select(User).where(User.username == username)
    user = session.exec(statement).first()

    if user is None:
        verify_password(password, DUMMY_HASH)
        return None

    if not verify_password(password, user.hashed_password):
        return None

    return user


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    session: SessionDep,
) -> User:
    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
        )

        user_id_raw = payload.get("sub")

        if user_id_raw is None:
            raise unauthorized_exception()

        user_id = int(user_id_raw)

    except (InvalidTokenError, ValueError):
        raise unauthorized_exception()

    user = session.get(User, user_id)

    if user is None:
        raise unauthorized_exception()

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def require_admin(current_user: CurrentUser) -> User:
    if current_user.role != Role.admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    return current_user


AdminUser = Annotated[User, Depends(require_admin)]

@app.post(
    "/signup",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def signup(
    payload: UserCreate,
    session: SessionDep,
):
    existing_user = session.exec(
        select(User).where(User.username == payload.username)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered",
        )

    user = User(
        username=payload.username,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@app.post("/login", response_model=Token)
def login(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],
    session: SessionDep,
):
    user = authenticate_user(
        session=session,
        username=form_data.username,
        password=form_data.password,
    )

    if user is None:
        raise unauthorized_exception("Incorrect username or password")

    access_token = create_access_token(
        data={
            "sub": str(user.id),
            "username": user.username,
            "role": user.role.value,
        },
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@app.get("/me", response_model=UserRead)
def get_me(current_user: CurrentUser):
    return current_user


@app.get("/users", response_model=list[UserRead])
def get_users(
    session: SessionDep,
    admin: AdminUser,
):
    users = session.exec(select(User)).all()
    return users

@app.post(
    "/tasks",
    response_model=TaskRead,
    status_code=status.HTTP_201_CREATED,
)
def add_task(
    payload: TaskCreate,
    session: SessionDep,
    current_user: CurrentUser,
):
    task = Task(
        title=payload.title,
        description=payload.description,
        owner_id=current_user.id,
    )

    session.add(task)
    session.commit()
    session.refresh(task)

    return task


@app.get("/tasks", response_model=list[TaskRead])
def view_tasks(
    session: SessionDep,
    current_user: CurrentUser,
    owner_id: int | None = Query(default=None),
):
    if owner_id is None:
        statement = select(Task).where(Task.owner_id == current_user.id)
        return session.exec(statement).all()

    if current_user.role != Role.admin and owner_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Users can only view their own tasks",
        )

    statement = select(Task).where(Task.owner_id == owner_id)
    return session.exec(statement).all()